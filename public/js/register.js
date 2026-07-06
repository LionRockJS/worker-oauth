// Registration page behaviour. External (no inline script) so the CSP can
// forbid 'unsafe-inline'.
(function () {
  const errorTextEl = document.getElementById('error-text');
  if (errorTextEl && errorTextEl.textContent.trim()) {
    document.getElementById('error-banner').classList.remove('hidden');
  }

  document.getElementById('register-form').addEventListener('submit', function (e) {
    const pw = document.getElementById('password').value;
    const cpw = document.getElementById('confirm_password').value;
    if (pw !== cpw) {
      e.preventDefault();
      const banner = document.getElementById('error-banner');
      document.getElementById('error-text').textContent = 'Passwords do not match.';
      banner.classList.remove('hidden');
      return;
    }
    const btn = document.getElementById('submit-btn');
    btn.disabled = true;
    btn.textContent = 'Creating account…';
  });
})();
