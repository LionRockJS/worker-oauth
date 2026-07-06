// Login page behaviour. Moved out of the HTML so the CSP can forbid inline
// scripts ('unsafe-inline'). The reCAPTCHA site key is read from the submit
// button's data-sitekey attribute (rendered server-side).
(function () {
  const submitBtn = document.getElementById('submit-btn');
  const recaptchaSiteKey = submitBtn ? submitBtn.dataset.sitekey || '' : '';

  // Show server-side error if present
  const errorTextEl = document.getElementById('error-text');
  if (errorTextEl && errorTextEl.textContent.trim()) {
    document.getElementById('error-banner').classList.remove('hidden');
  }

  function showClientError(message) {
    document.getElementById('error-text').textContent = message;
    document.getElementById('error-banner').classList.remove('hidden');
  }

  function setSubmitting(isSubmitting, label) {
    submitBtn.disabled = isSubmitting;
    submitBtn.textContent = label;
  }

  function onSubmit(token) {
    document.getElementById('recaptcha-token').value = token;
    setSubmitting(true, 'Signing in…');
    document.getElementById('login-form').submit();
  }
  // reCAPTCHA's data-callback resolves callbacks by global name.
  window.onSubmit = onSubmit;

  document.getElementById('login-form').addEventListener('submit', function (event) {
    if (document.getElementById('recaptcha-token').value) {
      setSubmitting(true, 'Signing in…');
      return;
    }

    event.preventDefault();
    setSubmitting(true, 'Checking…');

    if (!window.grecaptcha || !window.grecaptcha.enterprise) {
      setSubmitting(false, 'Sign in');
      showClientError('reCAPTCHA is still loading. Please try again.');
      return;
    }

    window.grecaptcha.enterprise.ready(function () {
      window.grecaptcha.enterprise.execute(recaptchaSiteKey, { action: 'submit' })
        .then(onSubmit)
        .catch(function () {
          setSubmitting(false, 'Sign in');
          showClientError('reCAPTCHA verification could not start. Please try again.');
        });
    });
  });
})();
