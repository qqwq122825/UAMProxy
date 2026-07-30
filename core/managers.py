import os
import json
from datetime import date
from core.config import DATA_DIR, USERS_FILE

# ─────────────────────────────────────────
# 本地重放管理（域名 → 本地文件映射）
# ─────────────────────────────────────────
class LocalMapManager:
    """
    持久化域名→本地文件映射到 C:\\PyProxyApp\\local_map.json。
    当 SOCKS5 代理收到对应域名的 HTTP:80 请求时，直接用本地文件
    内容作响应，不访问真实服务器（类似 Fiddler 的 Map Local 功能）。
    """
    def __init__(self, path: str = os.path.join(DATA_DIR, "local_map.json")):
        self.path = path
        self._map: dict = {}
        self.load()

    def load(self):
        try:
            if os.path.exists(self.path):
                with open(self.path, "r", encoding="utf-8") as f:
                    self._map = json.load(f)
        except Exception:
            self._map = {}

    def save(self):
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self._map, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    @staticmethod
    def _normalize(domain: str) -> str:
        domain = domain.strip().lower()
        for prefix in ("https://", "http://"):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        return domain.split("/")[0].split(":")[0]

    def add(self, domain: str, filepath: str):
        key = self._normalize(domain)
        if key:
            self._map[key] = filepath
            self.save()

    def remove(self, domain: str):
        self._map.pop(self._normalize(domain), None)
        self.save()

    def get_file(self, host: str) -> str | None:
        """按域名查找本地文件路径，自动互转 www. 前缀。"""
        host = host.lower().split(":")[0]
        if host in self._map:
            return self._map[host]
        alt = host[4:] if host.startswith("www.") else "www." + host
        return self._map.get(alt)

    def items(self) -> list:
        return list(self._map.items())

    def clear(self):
        self._map.clear()
        self.save()


local_map_manager = LocalMapManager()

# ─────────────────────────────────────────
# 用户管理（持久化）
# ─────────────────────────────────────────
class UserManager:
    """
    users.json 格式：
    [
      {"username": "alice", "password": "123456", "expire": "2099-12-31", "note": "管理员"},
      ...
    ]
    expire = "never" 表示永不过期
    """
    def __init__(self, path: str = USERS_FILE):
        self.path = path
        self._users: list[dict] = []
        self.load()

    def load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    self._users = json.load(f)
            except Exception:
                self._users = []
        else:
            # 默认添加一个 test 账号方便初次测试
            self._users = [
                {
                    "username": "test",
                    "password": "test",
                    "expire": "never",
                    "note": "默认测试账号 test/test",
                    "perm": "both",
                }
            ]
            self.save()

    def save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._users, f, ensure_ascii=False, indent=2)

    def all(self) -> list[dict]:
        return list(self._users)

    @staticmethod
    def _norm_perm(value) -> str:
        """
        统一权限字段：
          - "record" / "replay" / "both"
        兼容历史：缺失/未知 -> "both"
        """
        v = (value or "").strip().lower()
        if v in ("record", "replay", "both"):
            return v
        return "both"

    def add(self, username: str, password: str, expire: str = "never",
            note: str = "", allow_multi: bool = False, perm: str = "both") -> bool:
        """返回 False 表示用户名已存在"""
        if any(u["username"] == username for u in self._users):
            return False
        self._users.append({"username": username, "password": password,
                             "expire": expire, "note": note,
                             "allow_multi": allow_multi,
                             "perm": self._norm_perm(perm)})
        self.save()
        return True

    def remove(self, username: str):
        self._users = [u for u in self._users if u["username"] != username]
        self.save()

    def remove_many(self, usernames) -> int:
        """批量删除用户并只写盘一次，返回实际删除数量。"""
        wanted = {
            str(username).strip()
            for username in usernames
            if username is not None and str(username).strip()
        }
        if not wanted:
            return 0
        before = len(self._users)
        self._users = [
            user for user in self._users
            if str(user.get("username") or "") not in wanted
        ]
        removed = before - len(self._users)
        if removed:
            self.save()
        return removed

    def update_password(self, username: str, new_pass: str):
        for u in self._users:
            if u["username"] == username:
                u["password"] = new_pass
                break
        self.save()

    def to_dict(self, perm: str | None = None) -> dict[str, str]:
        """返回 {username: password} 用于代理鉴权（过期账号会被过滤）"""
        today = date.today().isoformat()
        want = self._norm_perm(perm) if perm else None
        result = {}
        for u in self._users:
            exp = u.get("expire", "never")
            if exp == "never" or exp >= today:
                u_perm = self._norm_perm(u.get("perm"))
                if want is None:
                    ok = True
                elif want == "both":
                    ok = True
                else:
                    ok = (u_perm == "both" or u_perm == want)
                if ok:
                    result[u["username"]] = u["password"]
        return result

    def is_expired(self, username: str) -> bool:
        today = date.today().isoformat()
        for u in self._users:
            if u["username"] == username:
                exp = u.get("expire", "never")
                return exp != "never" and exp < today
        return True

    def get_allow_multi(self, username: str) -> bool:
        """是否允许同账户多 IP 同时在线（默认 False）"""
        for u in self._users:
            if u["username"] == username:
                return bool(u.get("allow_multi", False))
        return False

    def get_perm(self, username: str) -> str:
        """返回该用户权限：record / replay / both（未知/缺失则 both）"""
        for u in self._users:
            if u["username"] == username:
                return self._norm_perm(u.get("perm"))
        return "both"

    def get_expire(self, username: str) -> str:
        """返回该用户到期日期字符串；永不过期返回 'never'；未找到返回 '-'"""
        for u in self._users:
            if u["username"] == username:
                return u.get("expire", "never")
        return "-"

    def set_allow_multi(self, username: str, value: bool):
        for u in self._users:
            if u["username"] == username:
                u["allow_multi"] = value
                break
        self.save()


user_manager = UserManager()
