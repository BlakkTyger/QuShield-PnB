"use client";

import { useState, FormEvent, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Shield, Lock, Mail, Eye, EyeOff, ArrowRight, Loader2, CheckCircle, AlertTriangle, Sun, Moon } from "lucide-react";
import { loginUser, registerUser } from "@/lib/auth";

type Mode = "login" | "register";

export default function LoginPage() {
  const router = useRouter();
  const [mode, setMode] = useState<Mode>("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [theme, setTheme] = useState<"dark" | "light">("dark");

  useEffect(() => {
    // Check initial theme from document (if any) or localStorage
    const savedTheme = localStorage.getItem("theme") as "dark" | "light" | null;
    if (savedTheme) {
      setTheme(savedTheme);
      document.documentElement.setAttribute("data-theme", savedTheme);
    }
  }, []);

  const toggleTheme = () => {
    const newTheme = theme === "dark" ? "light" : "dark";
    setTheme(newTheme);
    document.documentElement.setAttribute("data-theme", newTheme);
    localStorage.setItem("theme", newTheme);
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    if (!email.trim() || !password.trim()) {
      setError("Please fill in all fields.");
      return;
    }

    if (mode === "register" && password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setIsLoading(true);
    try {
      if (mode === "login") {
        await loginUser(email, password);
        router.push("/");
      } else {
        await registerUser(email, password);
        setSuccess("Account created successfully. You can now sign in.");
        setMode("login");
        setPassword("");
        setConfirmPassword("");
      }
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { detail?: string } } };
      setError(
        axiosErr?.response?.data?.detail ||
        (mode === "login"
          ? "Invalid credentials. Please try again."
          : "Registration failed. Please try again.")
      );
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="login-page">
      {/* Theme Toggle Button */}
      <button
        onClick={toggleTheme}
        className="absolute top-6 right-6 p-2.5 rounded-lg transition-colors z-50 shadow-md backdrop-blur-md"
        style={{
          background: "var(--bg-card)",
          border: "1px solid var(--border-subtle)",
          color: "var(--text-primary)",
        }}
        title={`Switch to ${theme === "dark" ? "Light" : "Dark"} Mode`}
      >
        {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
      </button>

      {/* Animated background */}
      <div className="login-bg">
        <div className="login-bg-orb login-bg-orb--1" />
        <div className="login-bg-orb login-bg-orb--2" />
        <div className="login-bg-orb login-bg-orb--3" />
        <div className="login-bg-grid" />
      </div>

      <div className="login-container">
        {/* Left panel — Branding */}
        <div className="login-brand">
          <div className="login-brand-content">
            <div className="login-brand-logo">
              <div className="login-brand-icon">
                <Shield size={28} strokeWidth={2.5} />
              </div>
              <div>
                <h1 className="login-brand-title">QuShield</h1>
                <p className="login-brand-subtitle">PnB Banking</p>
              </div>
            </div>

            <h2 className="login-brand-heading">
              Quantum-Safe
              <br />
              <span>Crypto Intelligence</span>
            </h2>

            <p className="login-brand-desc">
              Post-Quantum Cryptographic Bill of Materials Scanner for Indian
              Banking Infrastructure. Discover, inventory, and assess your
              organization&apos;s quantum risk posture.
            </p>

            <div className="login-brand-features">
              <div className="login-feature">
                <CheckCircle size={16} />
                <span>FIPS 203/204/205 Compliance</span>
              </div>
              <div className="login-feature">
                <CheckCircle size={16} />
                <span>Mosca Risk Assessment</span>
              </div>
              <div className="login-feature">
                <CheckCircle size={16} />
                <span>RBI &amp; SEBI Regulatory Alignment</span>
              </div>
              <div className="login-feature">
                <CheckCircle size={16} />
                <span>Real-time CBOM Generation</span>
              </div>
            </div>
          </div>

          <div className="login-brand-footer">
            <Lock size={12} />
            <span>Protected by Post-Quantum Encryption</span>
          </div>
        </div>

        {/* Right panel — Form */}
        <div className="login-form-panel">
          <div className="login-form-wrapper">
            {/* Mobile logo */}
            <div className="login-mobile-logo">
              <div className="login-brand-icon login-brand-icon--sm">
                <Shield size={20} strokeWidth={2.5} />
              </div>
              <span className="login-brand-title" style={{ fontSize: "1.25rem", color: "var(--text-primary)" }}>
                QuShield
              </span>
            </div>

            <div className="login-form-header">
              <h2>{mode === "login" ? "Welcome Back" : "Create Account"}</h2>
              <p>
                {mode === "login"
                  ? "Sign in to access your quantum security dashboard"
                  : "Register for enterprise access to QuShield"}
              </p>
            </div>

            {/* Error / Success alerts */}
            {error && (
              <div className="login-alert login-alert--error animate-fade-in">
                <AlertTriangle size={16} />
                <span>{error}</span>
              </div>
            )}
            {success && (
              <div className="login-alert login-alert--success animate-fade-in">
                <CheckCircle size={16} />
                <span>{success}</span>
              </div>
            )}

            <form onSubmit={handleSubmit} className="login-form">
              {/* Email */}
              <div className="login-field">
                <label htmlFor="email">Email Address</label>
                <div className="login-input-wrap">
                  <Mail size={18} className="login-input-icon" />
                  <input
                    id="email"
                    type="email"
                    placeholder="you@organization.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    autoComplete="email"
                    required
                  />
                </div>
              </div>

              {/* Password */}
              <div className="login-field">
                <label htmlFor="password">Password</label>
                <div className="login-input-wrap">
                  <Lock size={18} className="login-input-icon" />
                  <input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    placeholder="Enter your password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    autoComplete={
                      mode === "login" ? "current-password" : "new-password"
                    }
                    required
                  />
                  <button
                    type="button"
                    className="login-eye-btn"
                    onClick={() => setShowPassword(!showPassword)}
                    tabIndex={-1}
                  >
                    {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                </div>
              </div>

              {/* Confirm Password (register only) */}
              {mode === "register" && (
                <div className="login-field animate-fade-in">
                  <label htmlFor="confirmPassword">Confirm Password</label>
                  <div className="login-input-wrap">
                    <Lock size={18} className="login-input-icon" />
                    <input
                      id="confirmPassword"
                      type={showPassword ? "text" : "password"}
                      placeholder="Re-enter your password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      autoComplete="new-password"
                      required
                    />
                  </div>
                </div>
              )}

              {/* Submit */}
              <button
                type="submit"
                className="login-submit-btn"
                disabled={isLoading}
              >
                {isLoading ? (
                  <Loader2 size={20} className="animate-spin" />
                ) : (
                  <ArrowRight size={20} />
                )}
                {isLoading
                  ? mode === "login"
                    ? "Authenticating..."
                    : "Creating Account..."
                  : mode === "login"
                    ? "Sign In"
                    : "Create Account"}
              </button>
            </form>

            {/* Toggle mode */}
            <div className="login-toggle">
              <span>
                {mode === "login"
                  ? "Don't have an account?"
                  : "Already have an account?"}
              </span>
              <button
                type="button"
                onClick={() => {
                  setMode(mode === "login" ? "register" : "login");
                  setError(null);
                  setSuccess(null);
                }}
              >
                {mode === "login" ? "Register" : "Sign In"}
              </button>
            </div>

            <div className="login-form-footer">
              <span>Secured with AES-256 &amp; Quantum-Resistant Protocols</span>
            </div>
          </div>
        </div>
      </div>

      <style jsx>{`
        /* ─── Page Shell ──────────────────────────────────────────────── */
        .login-page {
          position: fixed;
          inset: 0;
          display: flex;
          align-items: center;
          justify-content: center;
          background: var(--bg-primary);
          font-family: "Inter", -apple-system, BlinkMacSystemFont, sans-serif;
          overflow: hidden;
          z-index: 9999;
          transition: background-color 0.3s;
        }

        /* ─── Animated Background ─────────────────────────────────────── */
        .login-bg {
          position: absolute;
          inset: 0;
          overflow: hidden;
          z-index: 0;
        }
        .login-bg-orb {
          position: absolute;
          border-radius: 50%;
          filter: blur(120px);
          opacity: var(--orb-opacity);
          transition: opacity 0.5s;
        }
        .login-bg-orb--1 {
          width: 600px;
          height: 600px;
          background: var(--accent-magenta);
          top: -15%;
          left: -10%;
          animation: orbFloat1 18s ease-in-out infinite;
        }
        .login-bg-orb--2 {
          width: 400px;
          height: 400px;
          background: var(--accent-gold);
          bottom: -10%;
          right: -5%;
          animation: orbFloat2 22s ease-in-out infinite;
        }
        .login-bg-orb--3 {
          width: 300px;
          height: 300px;
          background: var(--sidebar-bg);
          top: 40%;
          left: 50%;
          animation: orbFloat3 15s ease-in-out infinite;
        }
        .login-bg-grid {
          position: absolute;
          inset: 0;
          background-image: radial-gradient(
            var(--border-active) 1px,
            transparent 1px
          );
          background-size: 40px 40px;
          opacity: 0.3;
        }

        @keyframes orbFloat1 {
          0%, 100% { transform: translate(0, 0) scale(1); }
          50% { transform: translate(60px, 40px) scale(1.15); }
        }
        @keyframes orbFloat2 {
          0%, 100% { transform: translate(0, 0) scale(1); }
          50% { transform: translate(-50px, -30px) scale(1.1); }
        }
        @keyframes orbFloat3 {
          0%, 100% { transform: translate(0, 0) scale(1); }
          50% { transform: translate(40px, -50px) scale(0.9); }
        }

        /* ─── Container ───────────────────────────────────────────────── */
        .login-container {
          position: relative;
          z-index: 1;
          display: flex;
          width: 960px;
          max-width: 95vw;
          min-height: 600px;
          max-height: 90vh;
          border-radius: 24px;
          overflow: hidden;
          background: var(--bg-card);
          border: 1px solid var(--border-subtle);
          box-shadow: 0 32px 80px rgba(0, 0, 0, 0.15);
          animation: containerIn 0.6s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }
        @keyframes containerIn {
          from { opacity: 0; transform: translateY(20px) scale(0.98); }
          to { opacity: 1; transform: translateY(0) scale(1); }
        }

        /* ─── Brand Panel (Left) ──────────────────────────────────────── */
        .login-brand {
          flex: 0 0 420px;
          background: linear-gradient(160deg, #a4123f 0%, #7d002c 70%, #400012 100%);
          padding: 48px 40px;
          display: flex;
          flex-direction: column;
          justify-content: space-between;
          position: relative;
          overflow: hidden;
        }
        .login-brand::after {
          content: "";
          position: absolute;
          bottom: -60px;
          right: -60px;
          width: 250px;
          height: 250px;
          background: rgba(253, 185, 19, 0.12);
          border-radius: 50%;
          filter: blur(80px);
        }

        .login-brand-content { position: relative; z-index: 1; }

        .login-brand-logo {
          display: flex;
          align-items: center;
          gap: 14px;
          margin-bottom: 48px;
        }
        .login-brand-icon {
          width: 48px;
          height: 48px;
          border-radius: 14px;
          display: flex;
          align-items: center;
          justify-content: center;
          background: linear-gradient(135deg, #fdb913, #e6a800);
          color: #000;
        }
        .login-brand-icon--sm {
          width: 36px;
          height: 36px;
          border-radius: 10px;
        }
        .login-brand-title {
          font-size: 1.5rem;
          font-weight: 800;
          color: #fff;
          letter-spacing: -0.02em;
        }
        .login-brand-subtitle {
          font-size: 0.7rem;
          font-weight: 600;
          text-transform: uppercase;
          letter-spacing: 0.15em;
          color: #fdb913;
        }

        .login-brand-heading {
          font-size: 2rem;
          font-weight: 800;
          line-height: 1.2;
          color: #fff;
          margin-bottom: 20px;
          letter-spacing: -0.02em;
        }
        .login-brand-heading span {
          color: #fdb913;
        }

        .login-brand-desc {
          font-size: 0.875rem;
          line-height: 1.7;
          color: rgba(255, 255, 255, 0.7);
          margin-bottom: 32px;
        }

        .login-brand-features {
          display: flex;
          flex-direction: column;
          gap: 12px;
        }
        .login-feature {
          display: flex;
          align-items: center;
          gap: 10px;
          font-size: 0.8rem;
          font-weight: 500;
          color: rgba(255, 255, 255, 0.85);
        }
        .login-feature :global(svg) {
          color: #fdb913;
          flex-shrink: 0;
        }

        .login-brand-footer {
          position: relative;
          z-index: 1;
          display: flex;
          align-items: center;
          gap: 8px;
          font-size: 0.7rem;
          color: rgba(255, 255, 255, 0.4);
          margin-top: 32px;
        }

        /* ─── Form Panel (Right) ──────────────────────────────────────── */
        .login-form-panel {
          flex: 1;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 48px 40px;
          background: var(--bg-secondary);
        }
        .login-form-wrapper {
          width: 100%;
          max-width: 380px;
        }

        .login-mobile-logo {
          display: none;
          align-items: center;
          gap: 10px;
          margin-bottom: 32px;
        }

        .login-form-header {
          margin-bottom: 32px;
        }
        .login-form-header h2 {
          font-size: 1.75rem;
          font-weight: 700;
          color: var(--text-primary);
          margin-bottom: 8px;
          letter-spacing: -0.02em;
        }
        .login-form-header p {
          font-size: 0.875rem;
          color: var(--text-secondary);
          line-height: 1.5;
        }

        /* ─── Alerts ──────────────────────────────────────────────────── */
        .login-alert {
          display: flex;
          align-items: center;
          gap: 10px;
          padding: 12px 16px;
          border-radius: 12px;
          font-size: 0.8rem;
          font-weight: 500;
          margin-bottom: 24px;
        }
        .login-alert--error {
          background: rgba(239, 68, 68, 0.12);
          color: #ef4444;
          border: 1px solid rgba(239, 68, 68, 0.2);
        }
        .login-alert--success {
          background: rgba(34, 197, 94, 0.12);
          color: #22c55e;
          border: 1px solid rgba(34, 197, 94, 0.2);
        }

        /* ─── Form ────────────────────────────────────────────────────── */
        .login-form {
          display: flex;
          flex-direction: column;
          gap: 20px;
        }

        .login-field label {
          display: block;
          font-size: 0.8rem;
          font-weight: 600;
          color: var(--text-secondary);
          margin-bottom: 8px;
          text-transform: uppercase;
          letter-spacing: 0.05em;
        }
        .login-input-wrap {
          position: relative;
          display: flex;
          align-items: center;
          background: var(--input-bg);
          border: 1px solid var(--border-subtle);
          border-radius: 12px;
          transition: all 0.25s;
          padding-left: 16px;
        }
        .login-input-wrap:focus-within {
          border-color: var(--accent-gold);
          box-shadow: 0 0 0 3px var(--accent-gold-dim);
        }
        .login-input-icon {
          color: var(--text-muted);
          pointer-events: none;
          z-index: 1;
          flex-shrink: 0;
        }
        .login-input-wrap input {
          width: 100%;
          padding: 14px 16px 14px 12px;
          background: transparent;
          border: none;
          color: var(--text-primary);
          font-size: 0.95rem;
          outline: none;
        }
        .login-input-wrap input::placeholder {
          color: var(--text-muted);
        }

        .login-eye-btn {
          position: absolute;
          right: 14px;
          background: none;
          border: none;
          color: var(--text-muted);
          cursor: pointer;
          padding: 4px;
          display: flex;
          align-items: center;
          transition: color 0.2s;
        }
        .login-eye-btn:hover {
          color: var(--text-primary);
        }

        /* ─── Submit Button ───────────────────────────────────────────── */
        .login-submit-btn {
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 10px;
          width: 100%;
          padding: 16px;
          background: linear-gradient(135deg, #a4123f 0%, #7d002c 100%);
          color: #fff;
          font-size: 0.95rem;
          font-weight: 700;
          border: none;
          border-radius: 12px;
          cursor: pointer;
          transition: all 0.3s;
          text-transform: uppercase;
          letter-spacing: 0.04em;
          margin-top: 4px;
        }
        .login-submit-btn:hover:not(:disabled) {
          transform: translateY(-1px);
          box-shadow: 0 8px 32px rgba(164, 18, 63, 0.4);
        }
        .login-submit-btn:active {
          transform: translateY(0);
        }
        .login-submit-btn:disabled {
          opacity: 0.6;
          cursor: not-allowed;
        }

        /* ─── Toggle ──────────────────────────────────────────────────── */
        .login-toggle {
          text-align: center;
          margin-top: 28px;
          font-size: 0.85rem;
          color: var(--text-muted);
        }
        .login-toggle button {
          background: none;
          border: none;
          color: var(--accent-gold);
          font-weight: 600;
          cursor: pointer;
          margin-left: 6px;
          transition: color 0.2s;
        }
        .login-toggle button:hover {
          text-decoration: underline;
        }

        .login-form-footer {
          text-align: center;
          margin-top: 32px;
          font-size: 0.7rem;
          color: var(--text-secondary);
          letter-spacing: 0.03em;
        }

        /* ─── Responsive ──────────────────────────────────────────────── */
        @media (max-width: 768px) {
          .login-container {
            flex-direction: column;
            max-height: unset;
            min-height: unset;
            border-radius: 0;
            max-width: 100vw;
            width: 100vw;
            height: 100vh;
          }
          .login-brand {
            flex: 0 0 auto;
            display: none;
          }
          .login-mobile-logo {
            display: flex;
          }
          .login-form-panel {
            flex: 1;
            padding: 32px 24px;
          }
        }
      `}</style>
    </div>
  );
}
