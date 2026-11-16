import React, { useState } from "react";
import { StyleSheet, TextInput, View } from "react-native";

import { ApiError } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { BrandLogo } from "../components/BrandLogo";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { Screen } from "../components/Screen";
import { Body, Heading, Muted } from "../components/Typography";
import { useTheme } from "../theme/ThemeContext";

function fieldMessages(value: unknown, path = ""): string[] {
  if (typeof value === "string") {
    return [path ? `${path}: ${value}` : value];
  }
  if (Array.isArray(value)) {
    return value.flatMap((item) => fieldMessages(item, path));
  }
  if (typeof value === "object" && value !== null) {
    return Object.entries(value).flatMap(([key, item]) =>
      fieldMessages(item, key === "non_field_errors" ? "" : key)
    );
  }
  return [];
}

export function AuthScreen() {
  const { signIn, signUp } = useAuth();
  const { theme } = useTheme();

  const [registering, setRegistering] = useState(false);
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);

  const inputStyle = [
    styles.input,
    {
      color: theme.textPrimary,
      backgroundColor: theme.bgSecondary,
      borderColor: theme.borderColor,
    },
  ];

  async function submit() {
    if (busy) return;

    setErrors([]);
    if (!username.trim() || !password) {
      setErrors(["Enter your username and password."]);
      return;
    }
    if (registering && (!email.trim() || password !== confirmation)) {
      setErrors(["Enter your email and make sure the passwords match."]);
      return;
    }

    setBusy(true);
    try {
      if (registering) {
        await signUp({
          username: username.trim(),
          email: email.trim(),
          password,
          password_confirm: confirmation,
        });
      } else {
        await signIn(username.trim(), password);
      }
    } catch (error) {
      const fields =
        error instanceof ApiError ? fieldMessages(error.fields) : [];
      setErrors(
        fields.length
          ? fields
          : [error instanceof Error ? error.message : "Request failed."]
      );
      setPassword("");
      setConfirmation("");
    } finally {
      setBusy(false);
    }
  }

  function changeMode() {
    setRegistering((value) => !value);
    setErrors([]);
    setPassword("");
    setConfirmation("");
  }

  return (
    <Screen compact>
      <Card>
        <BrandLogo size={144} />
        <Heading>{registering ? "Create your account" : "Welcome back"}</Heading>
        <Muted>
          {registering
            ? "Register a personal KITSUNE AI account."
            : "Sign in with your KITSUNE AI username."}
        </Muted>

        <Body>Username</Body>
        <TextInput
          accessibilityLabel="Username"
          style={inputStyle}
          value={username}
          onChangeText={setUsername}
          autoCapitalize="none"
          autoCorrect={false}
          editable={!busy}
          maxLength={150}
        />

        {registering && (
          <>
            <Body>Email</Body>
            <TextInput
              accessibilityLabel="Email"
              style={inputStyle}
              value={email}
              onChangeText={setEmail}
              keyboardType="email-address"
              autoCapitalize="none"
              autoCorrect={false}
              editable={!busy}
              maxLength={254}
            />
          </>
        )}

        <Body>Password</Body>
        <TextInput
          accessibilityLabel="Password"
          style={inputStyle}
          value={password}
          onChangeText={setPassword}
          secureTextEntry
          autoCapitalize="none"
          autoCorrect={false}
          editable={!busy}
          maxLength={128}
          onSubmitEditing={() => {
            if (!registering) void submit();
          }}
        />

        {registering && (
          <>
            <Body>Confirm password</Body>
            <TextInput
              accessibilityLabel="Confirm password"
              style={inputStyle}
              value={confirmation}
              onChangeText={setConfirmation}
              secureTextEntry
              autoCapitalize="none"
              autoCorrect={false}
              editable={!busy}
              maxLength={128}
              onSubmitEditing={() => void submit()}
            />
            <Muted>
              Use a strong, unique password. Server-side password rules apply.
            </Muted>
          </>
        )}

        {errors.length > 0 && (
          <View accessibilityRole="alert" style={styles.errors}>
            {errors.map((message, index) => (
              <Body key={`${index}-${message}`}>{message}</Body>
            ))}
          </View>
        )}

        <Button
          title={busy ? "Please wait..." : registering ? "Create account" : "Sign in"}
          disabled={busy}
          fullWidth
          onPress={() => void submit()}
        />

        <Button
          title={registering ? "Already registered? Sign in" : "Create an account"}
          disabled={busy}
          variant="secondary"
          fullWidth
          onPress={changeMode}
        />
      </Card>
    </Screen>
  );
}

const styles = StyleSheet.create({
  input: {
    borderWidth: 1,
    borderRadius: 8,
    paddingHorizontal: 12,
    paddingVertical: 10,
    fontSize: 16,
    marginBottom: 6,
  },
  errors: {
    borderLeftWidth: 3,
    borderLeftColor: "#D5151E",
    paddingLeft: 12,
    marginVertical: 8,
    gap: 4,
  },
});