"""
代理功能自动验证脚本（不依赖外网 DNS）
用法：先启动 proxy.py 并点击"启动代理"，然后运行本脚本

测试内容：
  1. 1081 无鉴权代理 → 连接本机 HTTP 测试服务（127.0.0.1:8888）
  2. 1080 正确账号鉴权代理 → 连接同一个测试服务
  3. 1080 错误账号鉴权 → 应该被拒绝
"""

import socket
import struct
import threading
import http.server
import time

# ──────────────────────────────────────
# 1. 启动一个本地假 HTTP 服务监听 8888
# ──────────────────────────────────────
class EchoHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"Proxy works! Path=" + self.path.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass

def start_echo_server():
    srv = http.server.HTTPServer(("127.0.0.1", 8888), EchoHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    print("[测试服务] 已启动 http://127.0.0.1:8888")
    return srv


# ──────────────────────────────────────
# 2. SOCKS5 手动握手工具
# ──────────────────────────────────────
def socks5_connect_noauth(proxy_port: int, dst_ip: str, dst_port: int) -> socket.socket:
    """通过 SOCKS5 (无鉴权) 连接到目标，返回 socket"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(("127.0.0.1", proxy_port))

    # 握手
    s.sendall(b"\x05\x01\x00")
    r = s.recv(2)
    assert r == b"\x05\x00", f"握手失败: {r}"

    # CONNECT 命令（IPv4）
    packed_ip = socket.inet_aton(dst_ip)
    packed_port = struct.pack("!H", dst_port)
    s.sendall(b"\x05\x01\x00\x01" + packed_ip + packed_port)
    rep = s.recv(10)
    assert rep[1] == 0, f"连接失败，代理回应: {rep}"
    return s


def socks5_connect_auth(proxy_port: int, dst_ip: str, dst_port: int,
                        username: str, password: str) -> socket.socket:
    """通过 SOCKS5 (用户名密码鉴权) 连接目标"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(("127.0.0.1", proxy_port))

    # 握手
    s.sendall(b"\x05\x01\x02")
    r = s.recv(2)
    assert r == b"\x05\x02", f"握手失败，不支持鉴权: {r}"

    # 发送账号密码
    u = username.encode()
    p = password.encode()
    auth_pkt = bytes([0x01, len(u)]) + u + bytes([len(p)]) + p
    s.sendall(auth_pkt)
    ar = s.recv(2)
    if ar[1] != 0:
        s.close()
        raise PermissionError(f"鉴权失败！服务器返回: {ar}")

    # CONNECT 命令（IPv4）
    packed_ip = socket.inet_aton(dst_ip)
    packed_port = struct.pack("!H", dst_port)
    s.sendall(b"\x05\x01\x00\x01" + packed_ip + packed_port)
    rep = s.recv(10)
    assert rep[1] == 0, f"连接失败，代理回应: {rep}"
    return s


def http_get(s: socket.socket, host: str) -> str:
    req = f"GET /hello HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    s.sendall(req.encode())
    resp = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        resp += chunk
    return resp.decode("utf-8", errors="replace")


# ──────────────────────────────────────
# 3. 执行测试
# ──────────────────────────────────────
def run_tests():
    srv = start_echo_server()
    time.sleep(0.3)

    results = []

    # ── 测试 1: 1081 无鉴权 ──
    try:
        s = socks5_connect_noauth(1081, "127.0.0.1", 8888)
        resp = http_get(s, "127.0.0.1")
        s.close()
        ok = "Proxy works!" in resp
        results.append(("1081 无鉴权代理 → 本地 HTTP", ok, resp.split("\r\n\r\n")[-1]))
    except Exception as e:
        results.append(("1081 无鉴权代理 → 本地 HTTP", False, str(e)))

    # ── 测试 2: 1080 正确账号 ──
    try:
        s = socks5_connect_auth(1080, "127.0.0.1", 8888, "test", "123456")
        resp = http_get(s, "127.0.0.1")
        s.close()
        ok = "Proxy works!" in resp
        results.append(("1080 正确账号鉴权 → 本地 HTTP", ok, resp.split("\r\n\r\n")[-1]))
    except Exception as e:
        results.append(("1080 正确账号鉴权 → 本地 HTTP", False, str(e)))

    # ── 测试 3: 1080 错误账号 ──
    try:
        s = socks5_connect_auth(1080, "127.0.0.1", 8888, "test", "wrongpass")
        s.close()
        results.append(("1080 错误账号被拒绝", False, "应该抛出 PermissionError 但没有！"))
    except PermissionError as e:
        results.append(("1080 错误账号被拒绝", True, str(e)))
    except Exception as e:
        results.append(("1080 错误账号被拒绝", False, str(e)))

    # ── 打印结果 ──
    print("\n" + "="*55)
    print("  代理功能测试结果")
    print("="*55)
    all_ok = True
    for name, ok, detail in results:
        status = "✅ PASS" if ok else "❌ FAIL"
        print(f" {status}  {name}")
        if detail:
            print(f"         └─ {detail[:80]}")
        if not ok:
            all_ok = False
    print("="*55)
    print(f"  总体结果: {'✅ 全部通过！' if all_ok else '❌ 有测试失败'}")
    print("="*55)

    srv.shutdown()


if __name__ == "__main__":
    run_tests()
