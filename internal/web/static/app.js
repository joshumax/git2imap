(() => {
  function syncAuthForm(form) {
    const selected = form.querySelector('input[name="auth_type"]:checked');
    const mode = selected ? selected.value : "none";
    form.querySelectorAll("[data-auth-fields]").forEach((group) => {
      group.disabled = group.dataset.authFields !== mode;
    });
  }

  function syncAuthFields(root) {
    if (root.matches?.("[data-auth-form]")) {
      syncAuthForm(root);
    }
    root.querySelectorAll("[data-auth-form]").forEach(syncAuthForm);
  }

  document.addEventListener("change", (event) => {
    if (event.target.matches('input[name="auth_type"]')) {
      syncAuthFields(event.target.form);
    }
  });
  document.addEventListener("DOMContentLoaded", () => syncAuthFields(document));
  document.addEventListener("htmx:load", (event) => syncAuthFields(event.target));
})();
