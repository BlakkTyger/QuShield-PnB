/**
 * Auth API client and token management for QuShield-PnB.
 * Connects to backend POST /api/v1/auth/login and /api/v1/auth/register.
 */
import api from "./api";

// ─── Types ──────────────────────────────────────────────────────────────────
export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface UserResponse {
  id: string;
  email: string;
  email_verified: boolean;
}

// ─── Token helpers ──────────────────────────────────────────────────────────
const TOKEN_KEY = "qushield_access_token";
const REFRESH_KEY = "qushield_refresh_token";

export function saveTokens(tokens: AuthTokens) {
  localStorage.setItem(TOKEN_KEY, tokens.access_token);
  localStorage.setItem(REFRESH_KEY, tokens.refresh_token);
}

export function getAccessToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(TOKEN_KEY);
}

export function clearTokens() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(REFRESH_KEY);
}

export function isLoggedIn(): boolean {
  return !!getAccessToken();
}

// ─── API calls ──────────────────────────────────────────────────────────────

/**
 * Login with email/password.
 * Backend expects OAuth2 form-encoded body (username = email).
 */
export async function loginUser(
  email: string,
  password: string
): Promise<AuthTokens> {
  const formData = new URLSearchParams();
  formData.append("username", email);
  formData.append("password", password);

  const { data } = await api.post<AuthTokens>("/auth/login", formData, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
  });
  saveTokens(data);
  return data;
}

/**
 * Register a new user.
 */
export async function registerUser(
  email: string,
  password: string
): Promise<UserResponse> {
  const { data } = await api.post<UserResponse>("/auth/register", {
    email,
    password,
  });
  return data;
}

/**
 * Fetch current user profile.
 */
export async function fetchCurrentUser(): Promise<UserResponse> {
  const token = getAccessToken();
  const { data } = await api.get<UserResponse>("/auth/me", {
    headers: { Authorization: `Bearer ${token}` },
  });
  return data;
}
