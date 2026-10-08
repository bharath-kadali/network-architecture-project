#!/usr/bin/env python3
"""bcurl: client for BFP/1."""
import socket
import sys

MAXLEN = 16384
T_REQUEST, T_RESPONSE, T_DATA = 1, 2, 3
END_STREAM = 0x01
TYPE_NAMES = {1: "REQUEST", 2: "RESPONSE", 3: "DATA"}
TABLE = ["content-type", "content-length", "host", "user-agent", "accept",
         "server", "connection", "last-modified", "etag", "cache-control"]
INDEX = {n: i + 1 for i, n in enumerate(TABLE)}


class Fail(Exception):
    pass


def hexdump(data):
    lines = []
    for off in range(0, len(data), 16):
        row = data[off:off + 16]
        left = " ".join("%02x" % b for b in row[:8])
        right = " ".join("%02x" % b for b in row[8:])
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append("%08x  %-23s  %-23s  |%s|" % (off, left, right, asc))
    lines.append("%08x" % len(data))
    return "\n".join(lines)


def log_frame(verbose, prefix, label, length, ftype, flags, stream, raw):
    if not verbose:
        return
    name = TYPE_NAMES.get(ftype, "unknown 0x%02x" % ftype)
    sys.stderr.write("%s%s%s length=%d flags=0x%02x stream=%d\n" %
                     (prefix, name, label, length, flags, stream))
    for ln in hexdump(raw).split("\n"):
        sys.stderr.write("%s%s\n" % (prefix, ln))
    sys.stderr.flush()


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except OSError as e:
            raise Fail("read error: %s" % e)
        if not chunk:
            raise Fail("connection closed mid-frame" if buf or n else "closed")
        buf += chunk
    return bytes(buf)


def read_frame(sock):
    """Returns (length, type, flags, stream, payload, raw) or None on clean EOF
    at a frame boundary (reported as a failure by the caller)."""
    first = b""
    try:
        first = sock.recv(8)
    except OSError as e:
        raise Fail("read error: %s" % e)
    if not first:
        return None
    hdr = first + (recv_exact(sock, 8 - len(first)) if len(first) < 8 else b"")
    length = int.from_bytes(hdr[0:3], "big")
    ftype = hdr[3]
    flags = hdr[4]
    stream = int.from_bytes(hdr[5:8], "big")
    payload = recv_exact(sock, length) if length else b""
    return length, ftype, flags, stream, payload, hdr + payload


def build_frame(ftype, flags, stream, payload):
    if len(payload) > MAXLEN:
        raise Fail("request too large (%d bytes)" % len(payload))
    return (len(payload).to_bytes(3, "big") + bytes([ftype, flags]) +
            stream.to_bytes(3, "big") + payload)


def enc_header(name, value):
    nb = name.encode("ascii")
    vb = value.encode("utf-8")
    if len(vb) > 255 or len(nb) > 255 or not nb:
        raise ValueError("header too long or empty: %s" % name)
    if name in INDEX:
        return bytes([0x80 | INDEX[name], len(vb)]) + vb
    return b"\x00" + bytes([len(nb)]) + nb + bytes([len(vb)]) + vb


def parse_headers(block):
    out = []
    i, n = 0, len(block)
    while i < n:
        b = block[i]
        i += 1
        if b & 0x80:
            idx = b & 0x7F
            if not 1 <= idx <= 10:
                raise Fail("malformed header block (bad index %d)" % idx)
            name = TABLE[idx - 1]
        elif b == 0:
            if i >= n:
                raise Fail("malformed header block")
            nl = block[i]
            i += 1
            if nl < 1 or i + nl > n:
                raise Fail("malformed header block")
            name = block[i:i + nl].decode("latin-1").lower()
            i += nl
        else:
            raise Fail("malformed header block (bad byte 0x%02x)" % b)
        if i >= n:
            raise Fail("malformed header block")
        vl = block[i]
        i += 1
        if i + vl > n:
            raise Fail("malformed header block")
        out.append((name, block[i:i + vl].decode("utf-8", "replace")))
        i += vl
    return out


def parse_url(u):
    for p in ("http://", "bfp://"):
        if u.startswith(p):
            u = u[len(p):]
            break
    slash = u.find("/")
    if slash < 0:
        hp, path = u, "/"
    else:
        hp, path = u[:slash], u[slash:]
    if ":" not in hp:
        raise ValueError("URL needs host:port: %s" % u)
    host, _, port = hp.rpartition(":")
    if not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError("bad host:port in URL: %s" % u)
    return host, int(port), hp, path


def exchange(sock, verbose, stream, hostport, path, extra, out):
    pb = path.encode("utf-8")
    if len(pb) > 0xFFFF:
        raise Fail("path too long")
    hdrs = [("host", hostport), ("user-agent", "bcurl/1"), ("accept", "*/*"),
            ("connection", "keep-alive")] + extra
    block = b"".join(enc_header(n, v) for n, v in hdrs)
    payload = bytes([1]) + len(pb).to_bytes(2, "big") + pb + block
    frame = build_frame(T_REQUEST, END_STREAM, stream, payload)
    log_frame(verbose, "> ", "", len(payload), T_REQUEST, END_STREAM, stream, frame)
    try:
        sock.sendall(frame)
    except OSError as e:
        raise Fail("send error: %s" % e)

    status = None
    clen = None
    got = 0
    while True:
        fr = read_frame(sock)
        if fr is None:
            raise Fail("connection closed before response ended (truncated)")
        length, ftype, flags, fstream, data, raw = fr
        known = ftype in (T_RESPONSE, T_DATA)
        if not known or fstream != stream or length > MAXLEN:
            if known and fstream == stream and length > MAXLEN:
                log_frame(verbose, "< ", " (oversize)", length, ftype, flags, fstream, raw)
                raise Fail("oversize frame (%d bytes) on our stream" % length)
            reason = "unknown type" if not known else "other stream"
            log_frame(verbose, "< ", " [skipped: %s]" % reason, length, ftype, flags, fstream, raw)
            continue
        log_frame(verbose, "< ", "", length, ftype, flags, fstream, raw)
        if ftype == T_RESPONSE:
            if status is not None:
                raise Fail("second RESPONSE frame on stream")
            if len(data) < 2:
                raise Fail("RESPONSE too short")
            status = int.from_bytes(data[:2], "big")
            for name, val in parse_headers(data[2:]):
                if name == "content-length" and clen is None:
                    if not val.isdigit():
                        raise Fail("bad content-length %r" % val)
                    clen = int(val)
        else:
            if status is None:
                raise Fail("DATA before RESPONSE")
            out.write(data)
            got += len(data)
        if flags & END_STREAM:
            break
    if clen is not None and clen != got:
        raise Fail("content-length mismatch: header %d, received %d" % (clen, got))
    return status


def usage(msg=None):
    if msg:
        sys.stderr.write("bcurl: %s\n" % msg)
    sys.stderr.write("usage: bcurl [-v] [-H name:value]... URL [URL...]\n")
    return 2


def main(argv):
    verbose = False
    extra = []
    urls = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "-v":
            verbose = True
        elif a == "-H":
            i += 1
            if i >= len(argv):
                return usage("-H needs an argument")
            h = argv[i]
            if ":" not in h:
                return usage("bad header (want name:value): %s" % h)
            n, _, v = h.partition(":")
            n = n.strip().lower()
            v = v.strip()
            if not n or not n.isascii() or len(n) > 255 or len(v.encode()) > 255:
                return usage("bad header: %s" % h)
            extra.append((n, v))
        elif a.startswith("-H") and len(a) > 2:
            argv[i] = a[2:]
            argv.insert(i, "-H")
            continue
        elif a.startswith("-") and len(a) > 1:
            return usage("unknown option %s" % a)
        else:
            urls.append(a)
        i += 1
    if not urls:
        return usage()
    parsed = []
    for u in urls:
        try:
            parsed.append((u,) + parse_url(u))
        except ValueError as e:
            return usage(str(e))
    if len({(p[1], p[2]) for p in parsed}) > 1:
        sys.stderr.write("bcurl: all URLs must name the same host:port\n")
        return 2

    host, port = parsed[0][1], parsed[0][2]
    try:
        sock = socket.create_connection((host, port), timeout=30)
    except OSError as e:
        sys.stderr.write("bcurl: cannot connect to %s:%d: %s\n" % (host, port, e))
        return 1
    out = sys.stdout.buffer
    rc = 0
    try:
        stream = 1
        for url, h, p, hostport, path in parsed:
            status = exchange(sock, verbose, stream, hostport, path, extra, out)
            out.flush()
            if status >= 400:
                sys.stderr.write("bcurl: %d %s\n" % (status, url))
                rc = 22
            stream += 2
    except Fail as e:
        out.flush()
        sys.stderr.write("bcurl: %s\n" % e)
        return 1
    except ValueError as e:
        sys.stderr.write("bcurl: %s\n" % e)
        return 2
    finally:
        sock.close()
    return rc


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except BrokenPipeError:
        sys.exit(1)
