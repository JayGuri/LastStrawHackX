import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App.jsx";
import "./index.css";

// ─── OAuth token pre-mount interception ───────────────────────────────────────
// Google OAuth redirects back to {FRONTEND_URL}?token=<jwt>.
// We intercept it here, BEFORE React.createRoot, so there is no race condition
// between multiple useEffect calls that might read/clear the URL at different
// times. By the time any component renders, auth data is already in localStorage
// and the Zustand store's initializer will pick it up synchronously.
(function interceptOAuthToken() {
  const params = new URLSearchParams(window.location.search);
  const oauthToken = params.get("token");
  if (!oauthToken) return;

  try {
    const parts = oauthToken.split(".");
    if (parts.length === 3) {
      const payload = JSON.parse(atob(parts[1]));
      const userInfo = {
        id: payload.user_id,
        email: payload.email,
        subscription_level: payload.subscription_level,
        auth_provider: payload.auth_provider,
      };
      localStorage.setItem("hackx_auth_token", oauthToken);
      localStorage.setItem("hackx_user", JSON.stringify(userInfo));
      // Flag so App.jsx can show the welcome notification exactly once
      window.__ambrosia_oauth_just_logged_in = userInfo;
    }
  } catch (_) {
    // Malformed token — ignore and let the user land unauthenticated
  }

  // Strip the token from the URL before React renders
  // (replaceState is synchronous and won't trigger a re-navigation)
  window.history.replaceState({}, "", "/");
})();
// ─────────────────────────────────────────────────────────────────────────────

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
