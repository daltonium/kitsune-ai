import React from "react";
import { StyleSheet, Text, TextProps } from "react-native";

import { useTheme } from "../theme/ThemeContext";

export function Heading(props: TextProps) {
  const { theme } = useTheme();
  return (
    <Text
      {...props}
      style={[styles.heading, { color: theme.textPrimary }, props.style]}
    />
  );
}

export function Body(props: TextProps) {
  const { theme } = useTheme();
  return (
    <Text
      {...props}
      style={[styles.body, { color: theme.textPrimary }, props.style]}
    />
  );
}

export function Muted(props: TextProps) {
  const { theme } = useTheme();
  return (
    <Text
      {...props}
      style={[styles.muted, { color: theme.textSecondary }, props.style]}
    />
  );
}

const styles = StyleSheet.create({
  heading: { fontSize: 18, fontWeight: "700" },
  body: { fontSize: 15, lineHeight: 22 },
  muted: { fontSize: 13, lineHeight: 19 },
});