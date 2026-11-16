const DEFAULT_API_URL = "http://127.0.0.1:8000";
const TIMEOUT_MS = 8000;

export const API_URL = (
  process.env.EXPO_PUBLIC_API_URL || DEFAULT_API_URL
).replace(/\/+$/, "");

export class ApiError extends Error {
  status: number | null;
  code: string;

  constructor(message: string, status: number | null, code: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

type ErrorBody = { error?: { code?: string; message?: string } };

async function request<T>(path: string): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const response = await fetch(`${API_URL}${path}`, {
      signal: controller.signal,
      headers: { Accept: "application/json" },
    });

    let body: unknown = null;
    try {
      body = await response.json();
    } catch {
      body = null;
    }

    if (!response.ok) {
      const detail = (body as ErrorBody | null)?.error;
      throw new ApiError(
        detail?.message ?? `Request failed (${response.status}).`,
        response.status,
        detail?.code ?? "http_error"
      );
    }
    return body as T;
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }
    if (error instanceof Error && error.name === "AbortError") {
      throw new ApiError("The server did not respond in time.", null, "timeout");
    }
    throw new ApiError("Could not reach the server.", null, "network_error");
  } finally {
    clearTimeout(timer);
  }
}

export type HealthResponse = { status: string; service: string };

export const getHealth = () => request<HealthResponse>("/api/health/");