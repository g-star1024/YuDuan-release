// 御端控制台共享鉴权逻辑：注入 Bearer 令牌、401 跳转登录、4033 强制改密、登出。
// 注意：服务端错误统一以 HTTP 200 + {code:...} 返回，故按 code 判定而非 status。
(function () {
  window.YD_TOKEN = localStorage.getItem('yd_token');
  window.YD_ROLE = localStorage.getItem('yd_role');
  window.YD_USER = localStorage.getItem('yd_user');

  const isLoginPage = location.pathname.endsWith('login.html');
  const isChangePage = location.pathname.endsWith('change-password.html');

  if (!window.YD_TOKEN && !isLoginPage) {
    location.href = 'login.html';
  }

  const _fetch = window.fetch;
  window.api = async function (p, opts) {
    opts = opts || {};
    const headers = Object.assign({ 'Authorization': 'Bearer ' + (window.YD_TOKEN || '') }, opts.headers || {});
    opts.headers = headers;
    const r = await _fetch(p, opts);
    const j = await r.json().catch(() => ({}));
    if (j.code === 401) {
      localStorage.removeItem('yd_token');
      localStorage.removeItem('yd_role');
      localStorage.removeItem('yd_user');
      location.href = 'login.html';
      throw new Error('unauthorized');
    }
    if (j.code === 4033 && !isChangePage) {
      // 强制改密：唯一放行页面
      location.href = 'change-password.html?forced=1';
      throw new Error('password change required');
    }
    return j;
  };

  document.addEventListener('DOMContentLoaded', function () {
    const out = document.getElementById('logout');
    if (out) out.onclick = function () {
      localStorage.removeItem('yd_token');
      localStorage.removeItem('yd_role');
      localStorage.removeItem('yd_user');
      location.href = 'login.html';
    };
    const roleEl = document.getElementById('role');
    if (roleEl) roleEl.textContent = '角色：' + (window.YD_ROLE || '-');
    const userEl = document.getElementById('user');
    if (userEl) userEl.textContent = '账号：' + (window.YD_USER || '-');
  });
})();
