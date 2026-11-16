import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  ApiError,
  getMe,
  loginUser,
  logoutUser,
  registerUser,
  type Registration,
  type User,
} from "../api/client";

type AuthState =
  | { phase: "loading" }
  | { phase: "anonymous" }
  | { phase: "authenticated"; user: User }
  | { phase: "error"; message: string };

type AuthContextValue = {
  state: AuthState;
  restoreSession: () => Promise<void>;
  signIn: (username: string, password: string) => Promise<void>;
  signUp: (data: Registration) => Promise<void>;
  signOut: () => Promise<void>;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<AuthState>({ phase: "loading" });

  const restoreSession = useCallback(async () => {
    setState({ phase: "loading" });
    try {
      const result = await getMe();
      setState({ phase: "authenticated", user: result.user });
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        setState({ phase: "anonymous" });
      } else {
        setState({
          phase: "error",
          message:
            error instanceof Error
              ? error.message
              : "Could not check your session.",
        });
      }
    }
  }, []);

  useEffect(() => {
    void restoreSession();
  }, [restoreSession]);

  const signIn = useCallback(async (username: string, password: string) => {
    const result = await loginUser(username, password);
    setState({ phase: "authenticated", user: result.user });
  }, []);

  const signUp = useCallback(async (data: Registration) => {
    const result = await registerUser(data);
    setState({ phase: "authenticated", user: result.user });
  }, []);

  const signOut = useCallback(async () => {
    await logoutUser();
    setState({ phase: "anonymous" });
  }, []);

  const value = useMemo(
    () => ({ state, restoreSession, signIn, signUp, signOut }),
    [state, restoreSession, signIn, signUp, signOut]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (context === null) {
    throw new Error("useAuth must be used inside AuthProvider.");
  }
  return context;
}