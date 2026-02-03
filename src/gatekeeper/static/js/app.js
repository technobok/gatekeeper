/* Gatekeeper client-side helpers */

// Auto-dismiss flash messages after 5 seconds
document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("[class^='flash-']").forEach(function (el) {
        setTimeout(function () {
            el.style.transition = "opacity 0.3s";
            el.style.opacity = "0";
            setTimeout(function () {
                el.remove();
            }, 300);
        }, 5000);
    });
});

// Handle HTMX 401 responses (redirect to login)
document.body.addEventListener("htmx:responseError", function (event) {
    if (event.detail.xhr.status === 401) {
        window.location.href = "/auth/login";
    }
});
