import base64
import json
import secrets
import string
import threading
from datetime import date, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from core.config import app_config
from core.events import _event, _admin_log
from core.managers import user_manager


def _parse_cookie(handler: BaseHTTPRequestHandler, name: str) -> str:
    """从 Cookie 头解析指定名称的值"""
    raw = handler.headers.get("Cookie", "") or ""
    for part in raw.split(";"):
        part = part.strip()
        if part.startswith(name + "="):
            val = part[len(name) + 1 :].strip()
            try:
                return base64.b64decode(val.encode()).decode("utf-8", errors="ignore")
            except Exception:
                return val
    return ""


def _set_auth_cookie(handler: BaseHTTPRequestHandler, token: str, max_age: int = 86400):
    """设置鉴权 Cookie（HttpOnly，1 天有效）"""
    encoded = base64.b64encode(token.encode("utf-8")).decode("ascii")
    handler.send_header(
        "Set-Cookie",
        f"admin_auth={encoded}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}",
    )


def _clear_auth_cookie(handler: BaseHTTPRequestHandler):
    """清除鉴权 Cookie"""
    handler.send_header("Set-Cookie", "admin_auth=; Path=/; HttpOnly; Max-Age=0")


def _json(handler: BaseHTTPRequestHandler, code: int, payload: dict):
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(data)


def _html(handler: BaseHTTPRequestHandler, code: int, html: str):
    data = html.encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(data)


def _rand_str(n: int, alphabet: str) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _pick_unique_username(prefix: str, length: int = 5) -> str:
    # 以 users.json 当前内容为准，避免冲突
    existing = {u.get("username", "") for u in user_manager.all()}
    alphabet = string.digits
    for _ in range(200):
        uname = f"{prefix}{_rand_str(length, alphabet)}"
        if uname not in existing:
            return uname
    # 极端情况下退化为更长随机
    return f"{prefix}{_rand_str(length + 3, alphabet)}"


def _make_password(length: int = 6) -> str:
    alphabet = string.digits
    return _rand_str(max(6, min(int(length), 64)), alphabet)


_LOGIN_PAGE = """
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" />
<title>UAMProxy 远程管理 - 登录</title>
<style>
  :root { --bg: #09090b; --card: #18181b; --border: #27272a; --text: #fafafa; --muted: #a1a1aa; --primary: #3b82f6; --primary-hover: #2563eb; --danger: #ef4444; }
  * { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  body { margin: 0; padding: 20px; min-height: 100vh; background: var(--bg); color: var(--text); display: flex; align-items: center; justify-content: center; }
  .login-box { width: 100%; max-width: 420px; background: var(--card); border: 1px solid var(--border); border-radius: 16px; padding: 40px 32px; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5); }
  .logo { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
  .logo-icon { width: 32px; height: 32px; background: linear-gradient(135deg, var(--primary), #8b5cf6); border-radius: 8px; }
  h1 { margin: 0; font-size: 1.5rem; font-weight: 600; letter-spacing: -0.025em; }
  .sub { color: var(--muted); font-size: 0.9rem; margin-bottom: 32px; line-height: 1.6; }
  .field { display: flex; flex-direction: column; gap: 8px; margin-bottom: 24px; }
  label { color: #d4d4d8; font-size: 0.9rem; font-weight: 500; }
  input { width: 100%; padding: 12px 16px; border-radius: 8px; border: 1px solid var(--border); background: var(--bg); color: var(--text); font-size: 1rem; transition: all 0.2s; }
  input:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.25); }
  .btn { width: 100%; padding: 12px; border: none; border-radius: 8px; background: var(--primary); color: #fff; font-weight: 500; font-size: 1rem; cursor: pointer; transition: all 0.2s; }
  .btn:hover:not(:disabled) { background: var(--primary-hover); transform: translateY(-1px); }
  .btn:active:not(:disabled) { transform: translateY(0); }
  .btn:disabled { opacity: 0.6; cursor: not-allowed; }
  .err { color: var(--danger); font-size: 0.875rem; margin-top: 12px; min-height: 20px; text-align: center; }
</style>
</head>
<body>
  <div class="login-box">
    <div class="logo">
      <div class="logo-icon"></div>
      <h1>UAMProxy</h1>
    </div>
    <div class="sub">请输入管理密码。密码在桌面端「远程管理」Tab 中设置并保存。</div>
    <form id="f" onsubmit="return doLogin(event)">
      <div class="field">
        <label>管理密码</label>
        <input type="password" id="pwd" placeholder="••••••••" autocomplete="current-password" required autofocus />
      </div>
      <button type="submit" class="btn" id="btn">登录控制台</button>
      <div class="err" id="err"></div>
    </form>
  </div>
  <script>
    async function doLogin(e) {
      e.preventDefault();
      var btn = document.getElementById('btn');
      var err = document.getElementById('err');
      err.textContent = '';
      btn.disabled = true;
      btn.textContent = '登录中...';
      try {
        var r = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: document.getElementById('pwd').value })
        });
        var d = await r.json();
        if (d.ok) location.href = '/';
        else err.textContent = d.error === 'wrong_password' ? '密码错误，请重试' : (d.error || '登录失败');
      } catch (x) {
        err.textContent = '网络错误，无法连接到代理端';
      }
      btn.disabled = false;
      btn.textContent = '登录控制台';
    }
  </script>
</body>
</html>
"""


def _admin_page(token: str) -> str:
    return """
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover" />
<title>UAMProxy 远程管理</title>
<style>
  :root { --bg: #09090b; --card: #18181b; --border: #27272a; --text: #fafafa; --muted: #a1a1aa; --primary: #3b82f6; --primary-hover: #2563eb; --success: #10b981; --danger: #ef4444; --nav-bg: #18181b; }
  * { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; -webkit-tap-highlight-color: transparent; }
  body { margin: 0; padding: 0; background: var(--bg); color: var(--text); min-height: 100vh; padding-bottom: 70px; /* 为底部导航留出空间 */ }
  
  /* Header */
  .header { display: flex; justify-content: space-between; align-items: center; padding: 16px 20px; background: var(--bg); position: sticky; top: 0; z-index: 10; border-bottom: 1px solid var(--border); }
  .logo { display: flex; align-items: center; gap: 10px; }
  .logo-icon { width: 24px; height: 24px; background: linear-gradient(135deg, var(--primary), #8b5cf6); border-radius: 6px; }
  .header h1 { margin: 0; font-size: 1.1rem; font-weight: 600; }
  .btn-logout { padding: 6px 12px; font-size: 0.85rem; border-radius: 6px; background: transparent; color: var(--muted); border: 1px solid var(--border); cursor: pointer; }
  
  /* Tab Content */
  .tab-content { display: none; padding: 20px; max-width: 800px; margin: 0 auto; }
  .tab-content.active { display: block; animation: fadeIn 0.2s ease; }
  @keyframes fadeIn { from { opacity: 0; transform: translateY(5px); } to { opacity: 1; transform: translateY(0); } }
  
  h2 { margin: 0 0 20px 0; font-size: 1.25rem; font-weight: 600; }
  .desc { color: var(--muted); font-size: 0.9rem; margin-bottom: 24px; line-height: 1.5; }
  
  /* Forms */
  .field { display: flex; flex-direction: column; gap: 8px; margin-bottom: 20px; }
  label { color: #d4d4d8; font-size: 0.9rem; font-weight: 500; }
  input { padding: 14px; border-radius: 10px; border: 1px solid var(--border); background: var(--card); color: var(--text); font-size: 1rem; }
  input:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.25); }
  
  .days-row { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
  .pill { padding: 8px 16px; font-size: 0.9rem; background: var(--card); border: 1px solid var(--border); border-radius: 999px; color: var(--text); cursor: pointer; }
  .pill:active { background: var(--border); }
  
  .checkbox-wrap { display: flex; align-items: center; gap: 10px; margin: 24px 0; padding: 12px; background: var(--card); border-radius: 10px; border: 1px solid var(--border); }
  .checkbox-wrap input { width: 20px; height: 20px; accent-color: var(--primary); margin: 0; }
  .checkbox-wrap span { font-size: 0.95rem; color: var(--text); }
  
  /* Buttons */
  .btn-primary { width: 100%; padding: 16px; background: var(--primary); color: white; border: none; border-radius: 12px; font-size: 1.05rem; font-weight: 600; cursor: pointer; transition: background 0.2s; }
  .btn-primary:active { transform: scale(0.98); }
  .btn-primary:disabled { opacity: 0.7; pointer-events: none; }
  .btn-danger { background: rgba(239, 68, 68, 0.1); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.2); padding: 8px 16px; font-size: 0.85rem; border-radius: 8px; cursor: pointer;}
  .btn-refresh { width: 100%; padding: 12px; background: var(--card); color: var(--text); border: 1px solid var(--border); border-radius: 10px; font-size: 0.95rem; margin-bottom: 16px; cursor: pointer; }
  
  /* Result */
  .result-box { margin-top: 24px; padding: 20px; background: rgba(59, 130, 246, 0.05); border: 1px solid rgba(59, 130, 246, 0.2); border-radius: 12px; display: none; }
  .result-box.show { display: block; }
  .result-box.error { background: rgba(239, 68, 68, 0.05); border-color: rgba(239, 68, 68, 0.2); }
  .result-box pre { margin: 0; font-size: 0.95rem; font-family: monospace; line-height: 1.6; white-space: pre-wrap; color: var(--success); }
  .result-box.error pre { color: var(--danger); }
  .btn-copy { margin-top: 16px; width: 100%; padding: 12px; background: var(--card); color: var(--text); border: 1px solid var(--border); border-radius: 8px; display: none; cursor: pointer; }
  
  /* List */
  .user-list { display: flex; flex-direction: column; gap: 12px; }
  .user-card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 16px; display: flex; justify-content: space-between; align-items: center; }
  .user-info { display: flex; flex-direction: column; gap: 6px; }
  .user-name { font-weight: 600; font-size: 1.05rem; display: flex; align-items: center; gap: 8px; }
  .user-meta { font-size: 0.85rem; color: var(--muted); }
  .badge { padding: 3px 8px; background: #27272a; border-radius: 6px; font-size: 0.75rem; color: #d4d4d8; }
  .empty-state { padding: 40px 20px; text-align: center; color: var(--muted); background: var(--card); border-radius: 12px; border: 1px solid var(--border); }
  
  /* Bottom Nav */
  .bottom-nav { position: fixed; bottom: 0; left: 0; right: 0; height: 65px; background: var(--nav-bg); border-top: 1px solid var(--border); display: flex; padding-bottom: env(safe-area-inset-bottom); z-index: 100; }
  .nav-item { flex: 1; display: flex; flex-direction: column; justify-content: center; align-items: center; gap: 4px; color: var(--muted); text-decoration: none; cursor: pointer; transition: color 0.2s; }
  .nav-item.active { color: var(--primary); }
  .nav-icon { font-size: 1.25rem; }
  .nav-text { font-size: 0.75rem; font-weight: 500; }
</style>
</head>
<body>

  <!-- Header -->
  <div class="header">
    <div class="logo">
      <div class="logo-icon"></div>
      <h1>代理管理台</h1>
    </div>
    <button class="btn-logout" onclick="logout()">退出</button>
  </div>

  <!-- Tab 1: 创建账号 -->
  <div id="tab-create" class="tab-content active">
    <h2>➕ 创建账号</h2>
    <div class="desc">默认创建重放账号 (perm=replay)，立即生效。</div>
    
    <div style="display:flex; gap:16px;">
      <div class="field" style="flex:1;">
        <label>用户名前缀</label>
        <input id="prefix" value="tt_" placeholder="例如: tt_" />
      </div>
      <div class="field" style="flex:1;">
        <label>密码长度</label>
        <input id="pwdlen" type="number" min="6" max="64" value="6" />
      </div>
    </div>
    
    <div class="field">
      <label>到期时间 (天) - 0 表示永久</label>
      <input id="days" type="number" min="0" max="3650" value="0" />
      <div class="days-row">
        <button type="button" class="pill" onclick="setDays(1)">1天</button>
        <button type="button" class="pill" onclick="setDays(3)">3天</button>
        <button type="button" class="pill" onclick="setDays(7)">7天</button>
        <button type="button" class="pill" onclick="setDays(15)">15天</button>
        <button type="button" class="pill" onclick="setDays(30)">30天</button>
        <button type="button" class="pill" onclick="setDays(0)">永久</button>
      </div>
    </div>
    
    <div class="field">
      <label>备注 (可选)</label>
      <input id="note" placeholder="例如: 客户A的临时号" />
    </div>

    <label class="checkbox-wrap">
      <input type="checkbox" id="allow_multi" />
      <span>允许多开 (多设备同时在线)</span>
    </label>

    <button class="btn-primary" id="btnCreate" onclick="createUser()">一键创建</button>
    
    <div id="resultBox" class="result-box">
      <pre id="out"></pre>
      <button type="button" class="btn-copy" id="btnCopy" onclick="copyResult()">📋 复制账号</button>
    </div>
  </div>

  <!-- Tab 2: 账号管理 -->
  <div id="tab-users" class="tab-content">
    <h2>👥 账号管理 <span id="userCount" style="color:var(--muted);font-weight:400;font-size:1rem;margin-left:8px;"></span></h2>
    <button class="btn-refresh" onclick="loadUsers()">🔄 刷新列表</button>
    <div id="userList" class="user-list">
      <div class="empty-state">加载中...</div>
    </div>
  </div>

  <!-- Bottom Navigation -->
  <div class="bottom-nav">
    <div class="nav-item active" onclick="switchTab('create')" id="nav-create">
      <div class="nav-icon">➕</div>
      <div class="nav-text">发卡</div>
    </div>
    <div class="nav-item" onclick="switchTab('users')" id="nav-users">
      <div class="nav-icon">👥</div>
      <div class="nav-text">管理</div>
    </div>
  </div>

  <script>
    var lastResult = null;
    
    function switchTab(tab) {
      document.getElementById('tab-create').classList.remove('active');
      document.getElementById('tab-users').classList.remove('active');
      document.getElementById('nav-create').classList.remove('active');
      document.getElementById('nav-users').classList.remove('active');
      
      document.getElementById('tab-' + tab).classList.add('active');
      document.getElementById('nav-' + tab).classList.add('active');
      
      if (tab === 'users') {
        loadUsers();
      }
    }

    function setDays(n) { document.getElementById('days').value = n; }
    function escapeHtml(s) { var d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; }
    
    async function loadUsers() {
      var el = document.getElementById('userList');
      var cnt = document.getElementById('userCount');
      try {
        var r = await fetch('/api/users', { headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin' });
        var d = await r.json();
        if (d.ok) {
          cnt.textContent = '(' + d.count + ')';
          if (d.users.length === 0) {
            el.innerHTML = '<div class="empty-state">暂无账号</div>';
          } else {
            el.innerHTML = d.users.map(function(u) {
              var isPermanent = u.expire === 'never';
              var expireText = isPermanent ? '<span class="badge" style="background:rgba(16,185,129,0.1);color:#10b981;">永久</span>' : '到期: ' + escapeHtml(u.expire);
              var noteText = u.note ? '<span class="badge">' + escapeHtml(u.note) + '</span>' : '';
              return '<div class="user-card"><div class="user-info"><div class="user-name">' + escapeHtml(u.username) + noteText + '</div><div class="user-meta">' + expireText + '</div></div><button type="button" class="btn-danger" data-username="' + escapeHtml(u.username) + '" onclick="delUser(this.dataset.username)">删除</button></div>';
            }).join('');
          }
        } else {
          cnt.textContent = '(失败)';
          el.innerHTML = '<div class="empty-state">加载失败</div>';
        }
      } catch (e) {
        cnt.textContent = '(失败)';
        el.innerHTML = '<div class="empty-state">' + escapeHtml(e.message) + '</div>';
      }
    }
    
    async function delUser(username) {
      if (!confirm('确认删除账号 [' + username + ']？此操作不可恢复。')) return;
      try {
        var r = await fetch('/api/delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin', body: JSON.stringify({ username: username }) });
        var d = await r.json();
        if (d.ok) { loadUsers(); } else { alert('删除失败: ' + (d.error || '未知错误')); }
      } catch (e) { alert('请求失败: ' + e.message); }
    }
    
    function copyResult() {
      if (!lastResult) return;
      var txt = '用户名 ' + lastResult.username + ' 密码 ' + lastResult.password;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(txt).then(function() {
          var btn = document.getElementById('btnCopy');
          var old = btn.innerHTML;
          btn.innerHTML = '✅ 已复制';
          setTimeout(function() { btn.innerHTML = old; }, 1500);
        }).catch(function() { 
          prompt('自动复制失败，请长按下方文字手动复制：', txt);
        });
      } else {
        prompt('当前浏览器环境不支持自动复制，请长按下方文字手动复制：', txt);
      }
    }
    
    async function createUser() {
      var btn = document.getElementById('btnCreate');
      var box = document.getElementById('resultBox');
      var out = document.getElementById('out');
      var btnCopy = document.getElementById('btnCopy');
      
      btn.disabled = true;
      btn.textContent = '创建中...';
      box.classList.remove('show', 'error');
      lastResult = null;
      btnCopy.style.display = 'none';
      
      try {
        var r = await fetch('/api/create', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({
            prefix: (document.getElementById('prefix').value || 'tt_').trim(),
            password_length: parseInt(document.getElementById('pwdlen').value || '6', 10) || 6,
            expire_days: parseInt(document.getElementById('days').value || '0', 10) || 0,
            note: (document.getElementById('note').value || '').trim(),
            allow_multi: document.getElementById('allow_multi').checked
          })
        });
        var d;
        try { d = await r.json(); } catch (_) { d = { ok: false, error: '响应解析失败' }; }
        
        box.classList.add('show');
        if (d.ok) {
          lastResult = { username: d.username, password: d.password };
          out.textContent = '创建成功！\\n\\n用户名：' + d.username + '\\n密  码：' + d.password + '\\n到  期：' + d.expire;
          btnCopy.style.display = 'block';
          
          var txt = '用户名 ' + d.username + ' 密码 ' + d.password;
          prompt('账号创建成功，请长按下方文字进行复制：', txt);
        } else {
          box.classList.add('error');
          out.textContent = '创建失败：' + (d.error || '未知错误') + (r.status === 401 ? ' (请重新登录)' : '');
        }
      } catch (e) {
        box.classList.add('show', 'error');
        out.textContent = '请求失败：' + (e.message || e);
      }
      
      btn.disabled = false;
      btn.textContent = '一键创建';
    }
    
    async function logout() {
      await fetch('/api/logout', { method: 'POST' });
      location.href = '/';
    }
  </script>
</body>
</html>
"""


class AdminApiServer:
    """
    远程用户管理（浏览器）：
      - GET  /                管理页面（需 token）
      - POST /api/create      创建账号（默认 perm=replay）
      - GET  /api/ping        心跳
    鉴权：token 放在 query `?token=` 或 Header `X-Admin-Token`
    """

    def __init__(self, bind: str, port: int, token: str, on_users_changed=None):
        self.bind = bind
        self.port = int(port)
        self.token = token or ""
        self.on_users_changed = on_users_changed
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def ensure_token(self) -> str:
        if not self.token:
            self.token = secrets.token_urlsafe(24)
            app_config.set("admin_token", self.token)
            app_config.save()
        return self.token

    def start(self):
        token = self.ensure_token()
        server_ref = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                # 避免刷屏；必要日志由 _event 输出
                pass

            def _authed(self) -> bool:
                q = parse_qs(urlparse(self.path).query)
                q_token = (q.get("token") or [""])[0]
                h_token = self.headers.get("X-Admin-Token", "")
                c_token = _parse_cookie(self, "admin_auth")
                return bool(token) and (
                    q_token == token or h_token == token or c_token == token
                )

            def _need_auth(self):
                _json(self, 401, {"ok": False, "error": "unauthorized"})

            def do_GET(self):
                p = urlparse(self.path).path
                if p == "/api/ping":
                    if not self._authed():
                        return self._need_auth()
                    return _json(self, 200, {"ok": True, "time": date.today().isoformat()})

                if p == "/api/users":
                    if not self._authed():
                        return self._need_auth()
                    user_manager.load()
                    today = date.today().isoformat()
                    users = []
                    for u in user_manager.all():
                        perm = (u.get("perm") or "both").strip().lower()
                        if perm not in ("record", "replay", "both"):
                            perm = "both"
                        if perm in ("replay", "both"):
                            exp = u.get("expire", "never")
                            if exp == "never" or exp >= today:
                                users.append({
                                    "username": u.get("username", ""),
                                    "expire": exp,
                                    "note": u.get("note", ""),
                                })
                    return _json(self, 200, {"ok": True, "users": users, "count": len(users)})

                if p == "/":
                    if not self._authed():
                        return _html(self, 200, _LOGIN_PAGE)
                    page = _admin_page(token)
                    return _html(self, 200, page)

                return _json(self, 404, {"ok": False, "error": "not_found"})

            def do_POST(self):
                p = urlparse(self.path).path

                # 登录：验证密码，设置 Cookie，返回成功
                if p == "/api/login":
                    try:
                        ln = int(self.headers.get("Content-Length", "0"))
                    except Exception:
                        ln = 0
                    raw = self.rfile.read(max(0, min(ln, 4096))) if ln else b""
                    try:
                        body = json.loads(raw.decode("utf-8") or "{}") if raw else {}
                    except Exception:
                        body = {}
                    pwd = str(body.get("password") or "").strip()
                    if not token:
                        return _json(self, 500, {"ok": False, "error": "no_token_configured"})
                    if pwd != token:
                        client_ip = self.client_address[0] if self.client_address else "?"
                        _admin_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [密码错误] {client_ip}")
                        return _json(self, 401, {"ok": False, "error": "wrong_password"})
                    client_ip = self.client_address[0] if self.client_address else "?"
                    _admin_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [登录] {client_ip}")
                    data = json.dumps({"ok": True}, ensure_ascii=False).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("Cache-Control", "no-store")
                    _set_auth_cookie(self, token)
                    self.end_headers()
                    self.wfile.write(data)
                    return

                if p == "/api/logout":
                    out = json.dumps({"ok": True}, ensure_ascii=False).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(out)))
                    _clear_auth_cookie(self)
                    self.end_headers()
                    self.wfile.write(out)
                    return

                if not self._authed():
                    return self._need_auth()

                if p == "/api/delete":
                    try:
                        ln = int(self.headers.get("Content-Length", "0"))
                    except Exception:
                        ln = 0
                    raw = self.rfile.read(max(0, min(ln, 4096))) if ln else b""
                    try:
                        body = json.loads(raw.decode("utf-8") or "{}") if raw else {}
                    except Exception:
                        body = {}
                    username = str(body.get("username") or "").strip()
                    if not username:
                        return _json(self, 400, {"ok": False, "error": "missing_username"})
                    user_manager.load()
                    if not any(u.get("username") == username for u in user_manager.all()):
                        return _json(self, 404, {"ok": False, "error": "user_not_found"})
                    user_manager.remove(username)
                    if callable(server_ref.on_users_changed):
                        try:
                            server_ref.on_users_changed()
                        except Exception:
                            pass
                    client_ip = self.client_address[0] if self.client_address else "?"
                    _admin_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [删除账号] {client_ip} -> {username}")
                    _event("INFO", "AdminAPI", f"远程删除账号 [{username}]")
                    return _json(self, 200, {"ok": True})

                # /api/create
                try:
                    ln = int(self.headers.get("Content-Length", "0"))
                except Exception:
                    ln = 0
                raw = self.rfile.read(max(0, min(ln, 64 * 1024))) if ln else b""
                try:
                    body = json.loads(raw.decode("utf-8") or "{}") if raw else {}
                except Exception:
                    body = {}

                prefix = str(body.get("prefix") or "tt_").strip()
                if not prefix:
                    prefix = "tt_"
                note = str(body.get("note") or "").strip()
                try:
                    pwdlen = int(body.get("password_length") or 6)
                except Exception:
                    pwdlen = 6
                try:
                    days = int(body.get("expire_days") or 0)
                except Exception:
                    days = 0
                allow_multi = bool(body.get("allow_multi", False))

                user_manager.load()
                username = _pick_unique_username(prefix=prefix, length=5)
                password = _make_password(pwdlen)
                expire = "never" if days <= 0 else (date.today() + timedelta(days=days)).isoformat()

                ok = user_manager.add(
                    username=username,
                    password=password,
                    expire=expire,
                    note=note,
                    allow_multi=allow_multi,
                    perm="replay"
                )
                if not ok:
                    return _json(self, 409, {"ok": False, "error": "username_exists"})

                client_ip = self.client_address[0] if self.client_address else "?"
                _admin_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [创建账号] {client_ip} -> {username} (perm=replay)")

                if callable(server_ref.on_users_changed):
                    try:
                        server_ref.on_users_changed()
                    except Exception:
                        pass

                _event("INFO", "AdminAPI", f"远程创建账号 [{username}] perm=replay expire={expire}")
                return _json(self, 200, {
                    "ok": True,
                    "username": username,
                    "password": password,
                    "perm": "replay",
                    "expire": expire,
                })

        self._httpd = ThreadingHTTPServer((self.bind, self.port), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        _event("INFO", "AdminAPI", f"已启动 http://{self.bind}:{self.port}/  (token 已配置)")

    def stop(self):
        if self._httpd:
            try:
                self._httpd.shutdown()
            except Exception:
                pass
            self._httpd = None
        self._thread = None
