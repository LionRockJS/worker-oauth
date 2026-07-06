// Consent page behaviour. External (no inline script) so the CSP can forbid
// 'unsafe-inline'.
//
// Disable both buttons after the form is submitted to prevent double-submit.
// Disabled submit buttons are excluded from form data, so mirror the selected
// submitter in a hidden field before disabling the buttons.
(function () {
  const form = document.querySelector('form');
  const selectedAction = document.getElementById('selected-action');

  form.addEventListener('submit', function (event) {
    const clicked = event.submitter;
    if (!clicked || clicked.name !== 'action') {
      return;
    }

    selectedAction.name = 'action';
    selectedAction.value = clicked.value;

    if (clicked.value === 'approve') {
      clicked.textContent = 'Authorizing…';
    }

    document.querySelectorAll('button[type="submit"]').forEach(function (btn) {
      btn.disabled = true;
    });
  });
})();
