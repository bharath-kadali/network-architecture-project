#!/usr/bin/env python3
"""bserve: BFP/1 file server.   usage: ./bserve ROOT PORT [HOST]

Written from SPEC.md only; shares no code with bcurl.
"""
import mimetypes
import os
import socket
import struct
import sys
import threading

MAX_PAYLOAD = 16384
T_REQUEST, T_RESPONSE, T_DATA = 0x01, 0x02, 0x03
END_STREAM = 0x01
STATIC = {1: "content-type", 2: "content-length", 3: "host", 4: "user-agent",
          5: "accept", 6: "server", 7: "connection", 8: "last-modified",
          9: "etag", 10: "cache-control"}
INDEX = {v: k for k, v in STATIC.items()}


class Malformed(Exception):
    pass


def read_exact(sock, n):
    """Read exactly n bytes; return None on EOF (clean or mid-frame)."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return bytes(buf)


def discard(sock, n):
    while n > 0:
        chunk = sock.recv(min(n, 65536))
        if not chunk:
            return False
        n -= len(chunk)
    return True


def frame(ftype, flags, stream, payload):
    assert len(payload) <= MAX_PAYLOAD
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack(">I", stream)[1:] + payload


def encode_headers(pairs):
    out = bytearray()
    for name, value in pairs:
        v = value.encode()
        assert len(v) <= 255
        if name in INDEX:
            out.append(0x80 | INDEX[name])
        else:
            n = name.encode()
            out += bytes([0x00, len(n)]) + n
        out += bytes([len(v)]) + v
    return bytes(out)


def parse_headers(buf):
    """Validate a header block; return list of (name, value). Raise Malformed."""
    i, out = 0, []
    while i < len(buf):
        b = buf[i]
        i += 1
        if 0x81 <= b <= 0x8A:
            name = STATIC[b & 0x7F]
        elif b == 0x00:
            if i >= len(buf):
                raise Malformed("truncated literal")
            nl = buf[i]
            i += 1
            if nl < 1 or i + nl > len(buf):
                raise Malformed("bad name length")
            name = buf[i:i + nl].decode("ascii", "replace")
            i += nl
        else:
            raise Malformed("bad entry byte")
        if i >= len(buf):
            raise Malformed("missing value")
        vl = buf[i]
        i += 1
        if i + vl > len(buf):
            raise Malformed("value runs past block")
        out.append((name, buf[i:i + vl]))
        i += vl
    return out


def parse_request(payload, flags, stream):
    if not flags & END_STREAM:
        raise Malformed("no END_STREAM")
    if stream == 0:
        raise Malformed("stream 0")
    if len(payload) < 3:
        raise Malformed("short request")
    method, path_len = struct.unpack(">BH", payload[:3])
    if method != 0x01:
        raise Malformed("method")
    if 3 + path_len > len(payload):
        raise Malformed("path_len runs past payload")
    try:
        path = payload[3:3 + path_len].decode("utf-8")
    except UnicodeDecodeError:
        raise Malformed("path not utf-8")
    if "\x00" in path or not path.startswith("/"):
        raise Malformed("bad path")
    parse_headers(payload[3 + path_len:])
    return path


def locate(root, path):
    """Return a regular-file path inside root, or None."""
    if path.endswith("/"):
        path += "index.html"
    full = os.path.realpath(os.path.join(root, path.lstrip("/")))
    if os.path.commonpath([root, full]) != root:
        return None
    return full if os.path.isfile(full) else None


def send_error(conn, stream, status, text):
    body = text.encode()
    hdr = encode_headers([("content-type", "text/plain"),
                          ("content-length", str(len(body))),
                          ("server", "bserve/1")])
    conn.sendall(frame(T_RESPONSE, 0, stream, struct.pack(">H", status) + hdr)
                 + frame(T_DATA, END_STREAM, stream, body))


def send_file(conn, stream, full):
    st = os.stat(full)
    f = open(full, "rb")  # PermissionError handled by caller -> 500
    with f:
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        hdr = encode_headers([
            ("content-type", ctype),
            ("content-length", str(st.st_size)),
            ("server", "bserve/1"),
            ("last-modified", str(int(st.st_mtime))),
            ("etag", "%x-%x" % (st.st_size, int(st.st_mtime))),
            ("cache-control", "no-cache"),
        ])
        head = struct.pack(">H", 200) + hdr
        if st.st_size == 0:
            conn.sendall(frame(T_RESPONSE, END_STREAM, stream, head))
            return
        conn.sendall(frame(T_RESPONSE, 0, stream, head))
        sent = 0
        while sent < st.st_size:
            chunk = f.read(min(MAX_PAYLOAD, st.st_size - sent))
            if not chunk:
                raise ConnectionError("file shrank while sending")
            sent += len(chunk)
            conn.sendall(frame(T_DATA, END_STREAM if sent == st.st_size else 0, stream, chunk))


def serve(conn, addr, root):
    who = "%s:%d" % addr[:2]
    try:
        while True:
            hdr = read_exact(conn, 8)
            if hdr is None:
                return
            length = int.from_bytes(hdr[0:3], "big")
            ftype, flags = hdr[3], hdr[4]
            stream = int.from_bytes(hdr[5:8], "big")
            if length > MAX_PAYLOAD:
                if not discard(conn, length):
                    return
                if ftype == T_REQUEST:
                    send_error(conn, stream, 400, "bad request\n")
                    log(who, stream, "?", 400, "oversize frame")
                continue
            payload = read_exact(conn, length) if length else b""
            if payload is None:
                return
            if ftype != T_REQUEST:
                continue  # unknown or out-of-place frame: skip cleanly
            try:
                path = parse_request(payload, flags, stream)
            except Malformed as e:
                send_error(conn, stream, 400, "bad request\n")
                log(who, stream, "?", 400, str(e))
                continue
            full = locate(root, path)
            if full is None:
                send_error(conn, stream, 404, "not found\n")
                log(who, stream, path, 404, "")
                continue
            try:
                send_file(conn, stream, full)
                log(who, stream, path, 200, "%d bytes" % os.path.getsize(full))
            except PermissionError:
                send_error(conn, stream, 500, "internal error\n")
                log(who, stream, path, 500, "unreadable")
    except (ConnectionError, OSError):
        pass
    finally:
        conn.close()


def log(who, stream, path, status, note):
    print("%s stream=%d GET %s -> %d %s" % (who, stream, path, status, note),
          file=sys.stderr, flush=True)


def main():
    if len(sys.argv) not in (3, 4):
        sys.exit("usage: bserve ROOT PORT [HOST]")
    root = os.path.realpath(sys.argv[1])
    if not os.path.isdir(root):
        sys.exit("bserve: %s is not a directory" % sys.argv[1])
    host = sys.argv[3] if len(sys.argv) == 4 else ""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, int(sys.argv[2])))
    srv.listen(16)
    print("bserve: serving %s on port %s" % (root, sys.argv[2]), file=sys.stderr, flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=serve, args=(conn, addr, root), daemon=True).start()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
