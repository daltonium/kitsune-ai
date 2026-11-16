import React, { useCallback, useEffect, useState } from "react";
import { ActivityIndicator } from "react-native";

import { ApiError, API_URL, getHealth } from "../api/client";
import { Body, Heading, Muted } from "../components/Typography";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { Screen } from "../components/Screen";
import { useTheme } from "../theme/ThemeContext";

type HealthState =
  | { phase: "loading" }
  | { phase: "ok"; service: string }
  | { phase: "error"; message: string };

export function DashboardScreen() {
  const { theme, mode, toggleMode } = useTheme();
  const [health, setHealth] = useState<HealthState>({ phase: "loading" });

  const check = useCallback(async () => {
    setHealth({ phase: "loading" });
    try {
      const result = await getHealth();
      if (result.status === "ok") {
        setHealth({ phase: "ok", service: result.service });
      } else {
        setHealth({ phase: "error", message: "Unexpected health response." });
      }
    } catch (error) {
      setHealth({
        phase: "error",
        message: error instanceof ApiError ? error.message : "Unexpected error.",
      });
    }
  }, []);

  useEffect(() => {
    void check();
  }, [check]);

  return (
    <Screen>
      <Card>
        <Heading>KITSUNE AI</Heading>
        <Muted>Outsmart every threat.</Muted>
      </Card>

      <Card>
        <Heading>Backend connection</Heading>
        {health.phase === "loading" && (
          <ActivityIndicator color={theme.accentPrimary} />
        )}
        {health.phase === "ok" && (
          <Body>Connected to {health.service}.</Body>
        )}
        {health.phase === "error" && (
          <>
            <Body>{health.message}</Body>
            <Muted>
              Make sure the Django server is running (python manage.py
              runserver).
            </Muted>
          </>
        )}
        <Muted>API address: {API_URL}</Muted>
        <Button title="Check again" onPress={() => void check()} />
      </Card>

      <Card>
        <Heading>Appearance</Heading>
        <Muted>Current mode: {mode}</Muted>
        <Button
          title={mode === "dark" ? "Switch to light mode" : "Switch to dark mode"}
          onPress={toggleMode}
        />
      </Card>

      <Card>
        <Heading>Coming next</Heading>
        <Muted>
          Sign-in and live scan statistics arrive in Phase 14. This screen only
          checks that the backend is reachable.
        </Muted>
      </Card>
    </Screen>
  );
}