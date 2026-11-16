const TIMEOUT_MS = 8000;

export const API_URL = (
  process.env.EXPO_PUBLIC_API_URL || "http://localhost:8000"
).replace(/\/+$/, "");

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number | null,
    public code: string,
    public fields: unknown = null
  ) {
    super(message);
    this.name = "ApiError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function request<T>(
  path: string,
  method = "GET",
  payload?: unknown,
  csrfToken?: string
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  const headers: Record<string, string> = {
    Accept: "application/json",
  };
  if (payload !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (csrfToken) {
    headers["X-CSRFToken"] = csrfToken;
  }

  try {
    const response = await fetch(`${API_URL}${path}`, {
      method,
      credentials: "include",
      headers,
      signal: controller.signal,
      body: payload === undefined ? undefined : JSON.stringify(payload),
    });

    let body: unknown = null;
    try {
      body = await response.json();
    } catch {
      // Django middleware can return HTML for CSRF failures.
    }

    if (!response.ok) {
      const error = isRecord(body) && isRecord(body.error) ? body.error : null;

      let message =
        typeof error?.message === "string"
          ? error.message
          : `Request failed (${response.status}).`;

      if (!error && response.status === 403) {
        message =
          "Access was denied. Refresh the page and check your session or CSRF settings.";
      }
      if (response.status === 429) {
        message = "Too many requests. Wait before trying again.";
      }

      throw new ApiError(
        message,
        response.status,
        typeof error?.code === "string" ? error.code : "http_error",
        error?.fields ?? null
      );
    }

    return body as T;
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }
    if (error instanceof Error && error.name === "AbortError") {
      throw new ApiError(
        "The server did not respond in time.",
        null,
        "timeout"
      );
    }
    throw new ApiError(
      "Could not reach the server. Check that Django is running.",
      null,
      "network_error"
    );
  } finally {
    clearTimeout(timer);
  }
}

type CSRFResponse = { csrf_token: string };

async function csrfPost<T>(path: string, payload: unknown): Promise<T> {
  const { csrf_token } = await request<CSRFResponse>("/api/auth/csrf/");
  return request<T>(path, "POST", payload, csrf_token);
}

export type User = {
  id: number;
  username: string;
  email: string;
  role: "user" | "company";
};

type AuthResponse = {
  user: User;
  csrf_token: string;
};

export type Registration = {
  username: string;
  email: string;
  password: string;
  password_confirm: string;
};

export const getMe = () =>
  request<{ user: User }>("/api/auth/me/");

export const loginUser = (username: string, password: string) =>
  csrfPost<AuthResponse>("/api/auth/login/", { username, password });

export const registerUser = (data: Registration) =>
  csrfPost<AuthResponse>("/api/auth/register/", data);

export const logoutUser = () =>
  csrfPost<{ message: string; csrf_token: string }>(
    "/api/auth/logout/",
    {}
  );

export type AlertSummary = {
  id: number;
  scan_id: string;
  severity: string;
  title: string;
  message: string;
  is_read: boolean;
  created_at: string;
};

export type DashboardResponse = {
  period: {
    days: number;
    date_from: string;
    date_to: string;
    timezone: string;
  };
  total_scans: number;
  period_scans: number;
  period_high_risk_scans: number;
  unread_alerts: number;
  by_module: Record<string, number>;
  by_risk: Record<string, number>;
  daily_scans: { date: string; scans: number }[];
  recent_alerts: AlertSummary[];
  note: string;
};

export const getDashboard = () =>
  request<DashboardResponse>("/api/web/dashboard/?days=7");

export const getHealth = () =>
  request<{ status: string; service: string }>("/api/health/");