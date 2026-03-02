import React, { useEffect } from "react";
import { AnimatePresence, motion } from "framer-motion";
import Nav from "./components/common/Nav.jsx";
import Landing from "./pages/Landing.jsx";
import Login from "./pages/Login.jsx";
import Signup from "./pages/Signup.jsx";
import GlobeAnalysis from "./pages/GlobeAnalysis.jsx";
import FloodInsights from "./pages/FloodInsights.jsx";
import { useAppStore } from "./stores/appStore.js";
import { useAuth } from "./hooks/useAuth.js";
import { useInsightsStore } from "./stores/insightsStore.js";

const PAGES = {
  landing: Landing,
  login: Login,
  signup: Signup,
  globe: GlobeAnalysis,
  insights: FloodInsights,
};

function Notification() {
  const notification = useAppStore((s) => s.notification);
  const COLORS = {
    info: { bg: "bg-ice/10", border: "border-ice/20", text: "text-ice" },
    success: { bg: "bg-low/10", border: "border-low/20", text: "text-low" },
    warning: {
      bg: "bg-medium/10",
      border: "border-medium/20",
      text: "text-medium",
    },
    error: {
      bg: "bg-critical/10",
      border: "border-critical/20",
      text: "text-critical",
    },
  };
  const c = COLORS[notification?.type] ?? COLORS.info;

  return (
    <AnimatePresence>
      {notification && (
        <motion.div
          key={notification.id}
          initial={{ opacity: 0, y: -12, scale: 0.96 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: -8, scale: 0.96 }}
          className={`fixed top-16 sm:top-20 right-3 sm:right-5 z-[200] px-3 sm:px-4 py-2.5 sm:py-3 rounded-xl
                      border text-xs sm:text-sm font-medium max-w-[calc(100vw-24px)] sm:max-w-xs shadow-card
                      backdrop-blur-md ${c.bg} ${c.border} ${c.text}`}
        >
          {notification.msg}
        </motion.div>
      )}
    </AnimatePresence>
  );
}

export default function App() {
  const activeTab = useAppStore((s) => s.activeTab);
  const setActiveTab = useAppStore((s) => s.setActiveTab);
  const showNotification = useAppStore((s) => s.showNotification);
  const { isAuthenticated, user } = useAuth();
  const fetchRuns = useInsightsStore((s) => s.fetchRuns);

  // Preload historical runs as soon as the user is authenticated,
  // so the insights page list is ready before they navigate there.
  useEffect(() => {
    if (isAuthenticated) fetchRuns();
  }, [isAuthenticated, fetchRuns]);

  // Scroll to top on every page change
  useEffect(() => {
    window.scrollTo({ top: 0, behavior: "instant" });
  }, [activeTab]);

  // Post-OAuth welcome notification.
  // main.jsx already stored the token synchronously before React mounted,
  // so we only need to surface the welcome toast here — no URL parsing.
  useEffect(() => {
    const oauthUser = window.__ambrosia_oauth_just_logged_in;
    if (oauthUser) {
      delete window.__ambrosia_oauth_just_logged_in;
      showNotification(`Welcome, ${oauthUser.email.split("@")[0]}`, "success");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Initialization: Read the current URL path to set the tab correctly on load
  useEffect(() => {
    const path = window.location.pathname;
    const isProtected = path === "/globe" || path === "/insights";

    if (isProtected && !isAuthenticated) {
      setTimeout(
        () => showNotification("Please sign in to access this page", "warning"),
        100,
      );
      setActiveTab("login");
      return;
    }

    // Only force initial sync to routes other than what might be active
    if (path === "/login") setActiveTab("login");
    else if (path === "/signup") setActiveTab("signup");
    else if (path === "/globe") setActiveTab("globe");
    else if (path === "/insights") setActiveTab("insights");
    else if (path === "/") setActiveTab("landing");
  }, [setActiveTab, isAuthenticated, showNotification]);

  // Sync state to URL whenever it changes
  useEffect(() => {
    const routeMap = {
      landing: "/",
      login: "/login",
      signup: "/signup",
      globe: "/globe",
      insights: "/insights",
    };

    // Auth check before tab change takes effect
    if (
      (activeTab === "globe" || activeTab === "insights") &&
      !isAuthenticated
    ) {
      showNotification("Please sign in to access this page", "warning");
      setActiveTab("login");
      return;
    }

    const targetPath = routeMap[activeTab] || "/";
    if (window.location.pathname !== targetPath) {
      window.history.pushState({}, "", targetPath);
    }
  }, [activeTab, isAuthenticated, setActiveTab, showNotification]);

  const PageComponent = PAGES[activeTab] ?? Landing;
  const isAuthPage = activeTab === "login" || activeTab === "signup";

  return (
    <div className="relative min-h-screen app-gradient">
      {!isAuthPage && <Nav />}
      <Notification />
      <AnimatePresence mode="wait">
        <motion.div
          key={activeTab}
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -8 }}
          transition={{ duration: 0.25, ease: "easeOut" }}
        >
          <PageComponent />
        </motion.div>
      </AnimatePresence>
    </div>
  );
}
