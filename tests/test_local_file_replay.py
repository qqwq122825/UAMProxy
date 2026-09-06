from __future__ import annotations

import asyncio
import os
import tempfile
import unittest


try:
    from core.edition import LEGACY_LOCAL_MAP_RUNTIME_ENABLED
    from core.managers import local_map_manager
    from core.server import Socks5Server
except ImportError:  # Windows 构建环境会安装完整运行时依赖。
    LEGACY_LOCAL_MAP_RUNTIME_ENABLED = False
    local_map_manager = None
    Socks5Server = None


@unittest.skipIf(Socks5Server is None, "PySide6 is not installed")
class LocalFileReplayTests(unittest.IsolatedAsyncioTestCase):
    async def test_http_domain_mapping_returns_local_file_without_upstream(self):
        self.assertTrue(LEGACY_LOCAL_MAP_RUNTIME_ENABLED)
        original_map = dict(local_map_manager._map)
        server = Socks5Server(0, mode="pass", label="测试")

        with tempfile.TemporaryDirectory() as tmp:
            local_file = os.path.join(tmp, "record.html")
            expected = b"<html>local-replay-ok</html>"
            with open(local_file, "wb") as file_obj:
                file_obj.write(expected)
            local_map_manager._map = {"azenv.net": local_file}

            async def upstream_must_not_run(*_args, **_kwargs):
                self.fail("本地文件重放命中后仍尝试连接上游")

            server._connect_remote = upstream_must_not_run
            listener = await asyncio.start_server(
                server.handle_client, "127.0.0.1", 0
            )
            port = listener.sockets[0].getsockname()[1]
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(b"\x05\x01\x00")
                await writer.drain()
                self.assertEqual(await reader.readexactly(2), b"\x05\x00")

                host = b"azenv.net"
                writer.write(
                    b"\x05\x01\x00\x03" + bytes([len(host)]) + host + b"\x00\x50"
                )
                await writer.drain()
                self.assertEqual(
                    await reader.readexactly(10),
                    b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00",
                )

                writer.write(b"GET / HTTP/1.1\r\nHost: azenv.net\r\n\r\n")
                await writer.drain()
                response = await asyncio.wait_for(reader.read(), timeout=2)
                self.assertIn(b"HTTP/1.1 200 OK", response)
                self.assertTrue(response.endswith(expected))
                writer.close()
                await writer.wait_closed()
            finally:
                listener.close()
                await listener.wait_closed()
                local_map_manager._map = original_map


if __name__ == "__main__":
    unittest.main()
