// Dashboard behaviour. External (no inline script) so the CSP can forbid
// 'unsafe-inline'. Fetches the session-authenticated profile from /api/me.
(function () {
  function show(id) { document.getElementById(id).classList.remove('hidden'); }
  function hide(id) { document.getElementById(id).classList.add('hidden'); }

  function formatDate(unixSeconds) {
    return new Date(unixSeconds * 1000).toLocaleDateString(undefined, {
      year: 'numeric', month: 'long', day: 'numeric',
    });
  }

  async function loadProfile() {
    try {
      const res = await fetch('/api/me', { credentials: 'include' });

      if (res.status === 401) {
        window.location.href = '/login';
        return;
      }
      if (!res.ok) throw new Error('HTTP ' + res.status);

      const data = await res.json();

      document.getElementById('username').textContent = data.username;
      document.getElementById('email').textContent = data.email;
      document.getElementById('member-since').textContent = formatDate(data.created_at);
      document.getElementById('avatar').textContent = data.username.charAt(0).toUpperCase();

      const rolesEl = document.getElementById('roles');
      rolesEl.innerHTML = '';
      (data.roles || []).forEach(function (role) {
        const badge = document.createElement('span');
        badge.className =
          'inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ' +
          (role === 'admin' ? 'bg-amber-100 text-amber-800' : 'bg-indigo-100 text-indigo-800');
        badge.textContent = role;
        rolesEl.appendChild(badge);
      });
      if (!data.roles || data.roles.length === 0) {
        rolesEl.innerHTML = '<span class="text-slate-400 text-sm">No roles assigned</span>';
      }

      hide('loading');
      show('content');
    } catch (err) {
      hide('loading');
      document.getElementById('error-msg').textContent =
        'Failed to load your profile: ' + err.message;
      show('error-state');
    }
  }

  loadProfile();
})();
