#!/usr/bin/env python3
"""End-to-end tests for bserve and bcurl. Builds raw frames itself (struct only),
so it is a third, independent reader/writer of the wire format in SPEC.md.

usage: python3 tests/test_bfp.py        (run from the project folder)
"""
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BSERVE = os.path.join(ROOT, "bserve")
BCURL = os.path.join(ROOT, "bcurl")

PASSED = []


def check(name, cond, detail=""):
    if not cond:
        print("FAIL  %s  %s" % (name, detail))
        raise SystemExit(1)
    PASSED.append(name)
    print("ok    %s" % name)


# ---- tiny independent wire helpers -------------------------------------------------
def frame(ftype, flags, stream, payload):
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack(">I", stream)[1:] + payload


def request(path, stream=1, flags=1, method=1, headers=b"", path_bytes=None, path_len=None):
    pb = path.encode() if path_bytes is None else path_bytes
    pl = len(pb) if path_len is None else path_len
    return frame(1, flags, stream, struct.pack(">BH", method, pl) + pb + headers)


def recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError("closed after %d of %d bytes" % (len(b), n))
        b += c
    return b


def read_frame(s):
    h = recv_exact(s, 8)
    n = int.from_bytes(h[:3], "big")
    return h[3], h[4], int.from_bytes(h[5:8], "big"), recv_exact(s, n) if n else b""


def read_response(s):
    """Return (stream, status, header_payload, body, [data frame sizes], resp_flags)."""
    t, f, st, p = read_frame(s)
    assert t == 2, "expected RESPONSE, got type %d" % t
    status = struct.unpack(">H", p[:2])[0]
    body, sizes, end = b"", [], f & 1
    while not end:
        t, f, st2, d = read_frame(s)
        assert t == 3 and st2 == st
        body += d
        sizes.append(len(d))
        end = f & 1
    return st, status, p[2:], body, sizes, f


def connect(port):
    return socket.create_connection(("127.0.0.1", port), timeout=10)


def run_bcurl(*args):
    r = subprocess.run([BCURL] + list(args), capture_output=True, timeout=30)
    return r.returncode, r.stdout, r.stderr


def main():
    tmp = tempfile.mkdtemp(prefix="bfp-test-")
    www = os.path.join(tmp, "www")
    shutil.copytree(os.path.join(ROOT, "www"), www)
    os.makedirs(os.path.join(www, "sub"))
    open(os.path.join(www, "sub", "index.html"), "w").write("sub index\n")
    open(os.path.join(www, "empty.txt"), "wb").close()
    big = os.urandom(100_000)
    open(os.path.join(www, "big.bin"), "wb").write(big)
    exact = os.urandom(16384 * 2)
    open(os.path.join(www, "exact.bin"), "wb").write(exact)
    open(os.path.join(tmp, "secret.txt"), "w").write("outside the root\n")
    os.symlink(os.path.join(tmp, "secret.txt"), os.path.join(www, "link.txt"))
    open(os.path.join(www, "héllo.txt"), "w").write("utf8 name\n")

    s0 = socket.socket()
    s0.bind(("127.0.0.1", 0))
    port = s0.getsockname()[1]
    s0.close()
    log = open(os.path.join(tmp, "server.log"), "w")
    srv = subprocess.Popen([BSERVE, www, str(port)], stderr=log)
    try:
        for _ in range(100):
            try:
                connect(port).close()
                break
            except OSError:
                time.sleep(0.05)
        url = lambda p: "127.0.0.1:%d%s" % (port, p)

        # --- bcurl against bserve ---
        rc, out, err = run_bcurl(url("/index.html"))
        check("200 body + exit 0", rc == 0 and out == b"hello, world\n", (rc, out, err))
        rc, out, err = run_bcurl(url("/"))
        check("'/' maps to index.html", rc == 0 and out == b"hello, world\n")
        rc, out, err = run_bcurl(url("/sub/"))
        check("'/sub/' maps to sub/index.html", rc == 0 and out == b"sub index\n")
        rc, out, err = run_bcurl(url("/nope.html"))
        check("404 -> exit 22", rc == 22 and out == b"not found\n", (rc, out, err))
        rc, out, err = run_bcurl(url("/sub"))
        check("directory without slash -> 404", rc == 22)
        rc, out, err = run_bcurl(url("/big.bin"))
        check("100000-byte file is byte-exact", rc == 0 and out == big)
        rc, out, err = run_bcurl(url("/exact.bin"))
        check("exact multiple of 16384 is byte-exact", rc == 0 and out == exact)
        rc, out, err = run_bcurl(url("/empty.txt"))
        check("empty file -> exit 0, no output", rc == 0 and out == b"")
        rc, out, err = run_bcurl(url("/héllo.txt"))
        check("UTF-8 path", rc == 0 and out == b"utf8 name\n", (rc, out, err))
        rc, out, err = run_bcurl("-H", "x-trace:42", "-H", "accept:text/html", url("/index.html"))
        check("-H literal and indexed headers accepted", rc == 0 and out == b"hello, world\n")
        rc, out, err = run_bcurl("127.0.0.1:1/x")
        check("connection refused -> exit 1", rc == 1, (rc, err))
        rc, out, err = run_bcurl(url("/a"), "127.0.0.1:%d/b" % (port + 1))
        check("two different hosts -> exit 2, no connection", rc == 2)

        # --- sandboxing ---
        for p in ("/../secret.txt", "/../../etc/passwd", "/sub/../../secret.txt", "/link.txt"):
            s = connect(port)
            s.sendall(request(p))
            _, status, _, body, _, _ = read_response(s)
            check("escape %s -> 404" % p, status == 404 and body == b"not found\n", status)
            s.close()
        s = connect(port)
        s.sendall(request("/sub/../index.html"))
        _, status, _, body, _, _ = read_response(s)
        check("'..' that stays inside root is served", status == 200 and body == b"hello, world\n")
        s.close()

        # --- keep-alive: many exchanges on one raw connection ---
        s = connect(port)
        for i, (p, want) in enumerate([("/index.html", 200), ("/missing", 404), ("/about.txt", 200),
                                       ("/index.html", 200)]):
            st = 2 * i + 1
            s.sendall(request(p, stream=st))
            rs, status, _, body, _, _ = read_response(s)
            assert rs == st and status == want, (p, rs, status)
        check("4 exchanges (incl. a 404) on one connection, ids echoed", True)
        s.close()
        # bcurl: two URLs, one connection (server log has both streams from same peer)
        log.flush()
        before = open(os.path.join(tmp, "server.log")).read()
        rc, out, err = run_bcurl(url("/index.html"), url("/about.txt"), url("/nope"))
        check("bcurl multi-URL output + exit 22 from the 404", out.startswith(b"hello, world\nsecond file\n") and rc == 22)
        time.sleep(0.2)
        log.flush()
        new = open(os.path.join(tmp, "server.log")).read()[len(before):]
        peers = set(re.findall(r"(127\.0\.0\.1:\d+) stream=", new))
        streams = re.findall(r"stream=(\d+)", new)
        check("bcurl multi-URL used ONE connection (1 peer port), streams 1,3,5",
              len(peers) == 1 and streams == ["1", "3", "5"], (peers, streams, new))

        # --- DATA framing sizes ---
        s = connect(port)
        s.sendall(request("/big.bin"))
        _, status, hdrs, body, sizes, flags = read_response(s)
        check("DATA frames all <= 16384 and sum to file", max(sizes) <= 16384 and sum(sizes) == len(big) and body == big, sizes)
        s.sendall(request("/empty.txt", stream=3))
        _, status, hdrs, body, sizes, flags = read_response(s)
        check("empty file: RESPONSE carries END_STREAM, no DATA", status == 200 and flags & 1 and sizes == [])
        s.close()

        # --- malformed requests -> 400, connection stays open ---
        ok_hdr = b"\x83\x09localhost\x84\x07bcurl/1"
        bad = {
            "no END_STREAM": request("/index.html", flags=0),
            "stream 0": request("/index.html", stream=0),
            "method 2": request("/index.html", method=2),
            "path_len past payload": request("/index.html", path_len=500),
            "path without leading /": request("index.html"),
            "invalid UTF-8 path": request("", path_bytes=b"/\xff\xfe"),
            "NUL in path": request("", path_bytes=b"/a\x00b"),
            "header byte 0x05": request("/index.html", headers=b"\x05\x01a"),
            "header index 11": request("/index.html", headers=b"\x8b\x01a"),
            "header index 0x80": request("/index.html", headers=b"\x80\x01a"),
            "truncated literal": request("/index.html", headers=b"\x00\x05ab"),
            "literal name_len 0": request("/index.html", headers=b"\x00\x00\x01a"),
            "value runs past block": request("/index.html", headers=b"\x83\x09abc"),
            "missing value": request("/index.html", headers=b"\x83"),
            "payload < 3 bytes": frame(1, 1, 1, b"\x01\x00"),
            "empty payload": frame(1, 1, 1, b""),
            "oversize REQUEST (16385)": frame(1, 1, 1, b"\x01\x00\x01/" + b"\x00" * (16385 - 4)),
        }
        s = connect(port)
        for i, (name, raw) in enumerate(bad.items()):
            st = 2 * i + 1
            raw = raw[:5] + raw[5:8].replace(raw[5:8], struct.pack(">I", st)[1:]) + raw[8:] if "stream 0" not in name else raw
            s.sendall(raw)
            rs, status, _, body, _, _ = read_response(s)
            check("400 for %s" % name, status == 400 and body == b"bad request\n", (status, body))
            # the very same connection must still work
            s.sendall(request("/index.html", stream=st + 1000))
            rs, status, _, body, _, _ = read_response(s)
            assert status == 200 and body == b"hello, world\n" and rs == st + 1000
        check("connection survived all %d malformed requests" % len(bad), True)
        s.close()

        # --- valid request with literal + indexed headers ---
        s = connect(port)
        s.sendall(request("/index.html", headers=ok_hdr + b"\x00\x07x-trace\x0242"))
        _, status, hdrs, body, _, _ = read_response(s)
        check("request with indexed + literal headers -> 200", status == 200)
        s.close()

        # --- unknown frame types skipped, no reply, no close ---
        s = connect(port)
        s.sendall(frame(0x7F, 0xFF, 1, b"future extension payload")
                  + frame(0x04, 0, 0, b"")
                  + frame(0x03, 1, 1, b"stray DATA at a server")
                  + frame(0x02, 1, 1, b"\x00\xc8")
                  + request("/index.html", stream=1))
        rs, status, _, body, _, _ = read_response(s)
        check("unknown/stray frames skipped silently; next request answered once",
              rs == 1 and status == 200 and body == b"hello, world\n")
        s.settimeout(0.5)
        try:
            extra = s.recv(1)
            check("no extra bytes after the response", extra == b"" and False, extra)
        except socket.timeout:
            check("no extra bytes after the response (connection still open)", True)
        s.settimeout(10)
        # big unknown frame (1 MiB, above 16384) is also skipped cleanly
        s.sendall(frame(0x55, 0, 9, b"\xaa" * 1_000_000) + request("/about.txt", stream=3))
        rs, status, _, body, _, _ = read_response(s)
        check("1 MB unknown frame skipped, connection in sync", rs == 3 and body == b"second file\n")
        s.close()

        # --- byte-at-a-time delivery (partial reads) ---
        s = connect(port)
        raw = request("/about.txt", headers=ok_hdr)
        for b in raw:
            s.send(bytes([b]))
            time.sleep(0.002)
        rs, status, _, body, _, _ = read_response(s)
        check("request delivered one byte at a time", status == 200 and body == b"second file\n")
        # two requests pipelined in one send
        s.sendall(request("/index.html", stream=3) + request("/about.txt", stream=5))
        a = read_response(s)
        b = read_response(s)
        check("two pipelined requests answered in order", a[0] == 3 and b[0] == 5 and b[3] == b"second file\n")
        # peer closes mid-frame: server must survive
        s.close()
        s = connect(port)
        s.sendall(request("/about.txt")[:11])
        s.close()
        time.sleep(0.2)
        rc, out, err = run_bcurl(url("/index.html"))
        check("server alive after a client hangs up mid-frame", rc == 0)

        # --- response headers, decoded independently ---
        s = connect(port)
        s.sendall(request("/index.html"))
        _, status, hdrs, body, _, _ = read_response(s)
        seen, i = {}, 0
        while i < len(hdrs):
            b = hdrs[i]
            i += 1
            if b & 0x80:
                name = ["content-type", "content-length", "host", "user-agent", "accept", "server",
                        "connection", "last-modified", "etag", "cache-control"][(b & 0x7F) - 1]
            else:
                assert b == 0
                nl = hdrs[i]
                name = hdrs[i + 1:i + 1 + nl].decode()
                i += 1 + nl
            vl = hdrs[i]
            seen[name] = hdrs[i + 1:i + 1 + vl].decode()
            i += 1 + vl
        st = os.stat(os.path.join(www, "index.html"))
        check("200 headers: type/length/server/mtime/etag/cache-control",
              seen == {"content-type": "text/html", "content-length": "13", "server": "bserve/1",
                       "last-modified": str(int(st.st_mtime)),
                       "etag": "%x-%x" % (13, int(st.st_mtime)), "cache-control": "no-cache"}, seen)
        s.close()

        # --- concurrency ---
        results = []

        def worker(k):
            try:
                rc, out, err = run_bcurl(url("/big.bin"), url("/index.html"))
                results.append(rc == 0 and out == big + b"hello, world\n")
            except Exception:
                results.append(False)
        ts = [threading.Thread(target=worker, args=(k,)) for k in range(10)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        check("10 concurrent bcurl runs all byte-exact", all(results) and len(results) == 10)

        # --- bcurl -v is honest: compare its hexdump to bytes seen on the wire ---
        wire = {"c2s": b"", "s2c": b""}
        ls = socket.socket()
        ls.bind(("127.0.0.1", 0))
        ls.listen(1)
        pport = ls.getsockname()[1]

        def proxy():
            c, _ = ls.accept()
            u = connect(port)

            def pump(src, dst, key):
                try:
                    while True:
                        d = src.recv(4096)
                        if not d:
                            break
                        wire[key] += d
                        dst.sendall(d)
                except OSError:
                    pass
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
            a = threading.Thread(target=pump, args=(c, u, "c2s"))
            b = threading.Thread(target=pump, args=(u, c, "s2c"))
            a.start(); b.start(); a.join(); b.join()
            c.close(); u.close()
        pt = threading.Thread(target=proxy)
        pt.start()
        rc, out, err = run_bcurl("-v", "-H", "x-trace:42", "127.0.0.1:%d/index.html" % pport)
        pt.join(timeout=10)
        dumped = {">": b"", "<": b""}
        for line in err.decode().splitlines():
            m = re.match(r"^([<>]) ([0-9a-f]{8})  ([0-9a-f ]+?)\s*\|", line)
            if m:
                dumped[m.group(1)] += bytes.fromhex(m.group(3).replace(" ", ""))
        check("-v hexdump of sent frames == bytes on the wire", dumped[">"] == wire["c2s"] and len(wire["c2s"]) > 0,
              (dumped[">"].hex(), wire["c2s"].hex()))
        check("-v hexdump of received frames == bytes on the wire", dumped["<"] == wire["s2c"] and len(wire["s2c"]) > 0)
        check("-v keeps stdout clean (body only)", out == b"hello, world\n")
        open(os.path.join(tmp, "last_request.hex"), "w").write(wire["c2s"].hex())
        open(os.path.join(tmp, "last_response.hex"), "w").write(wire["s2c"].hex())
        print("  captured request %d bytes, response %d bytes" % (len(wire["c2s"]), len(wire["s2c"])))
    finally:
        srv.terminate()
        srv.wait(timeout=5)
        log.close()
        print("\nserver log tail:")
        print("".join(open(os.path.join(tmp, "server.log")).readlines()[-6:]))
        shutil.rmtree(tmp, ignore_errors=True)
    print("\n%d checks passed" % len(PASSED))


if __name__ == "__main__":
    main()
