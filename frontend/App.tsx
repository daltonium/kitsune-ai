import React from "react";
import { ActivityIndicator } from "react-native";
import { StatusBar } from "expo-status-bar";

import { AuthProvider, useAuth } from "./src/auth/AuthContext";
import { BrandLogo } from "./src/components/BrandLogo";
import { Button } from "./src/components/Button";
import { Card } from "./src/components/Card";
import { Screen } from "./src/components/Screen";
import { Heading, Muted } from "./src/components/Typography";
import { AppNavigator } from "./src/navigation/AppNavigator";
import { AuthScreen } from "./src/screens/AuthScreen";
import { ThemeProvider, useTheme } from "./src/theme/ThemeContext";

function SessionGate() {
  const { state, restoreSession } = useAuth();
  const { theme } = useTheme();

  if (state.phase === "loading") {
    return (
      <Screen>
        <Card>
          <BrandLogo size={112} />
          <Heading>Checking your session</Heading>
          <ActivityIndicator color={theme.accentPrimary} />
        </Card>
      </Screen>
    );
  }

  if (state.phase === "error") {
    return (
      <Screen>
        <Card>
          <Heading>Could not connect</Heading>
          <Muted>{state.message}</Muted>
          <Button
            title="Try again"
            onPress={() => void restoreSession()}
          />
        </Card>
      </Screen>
    );
  }

  return state.phase === "authenticated"
    ? <AppNavigator />
    : <AuthScreen />;
}

function Root() {
  const { mode } = useTheme();
  return (
    <>
      <SessionGate />
      <StatusBar style={mode === "dark" ? "light" : "dark"} />
    </>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <Root />
      </AuthProvider>
    </ThemeProvider>
  );
}