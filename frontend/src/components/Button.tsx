import React from "react";
import { Pressable, StyleSheet, Text } from "react-native";

import { useTheme } from "../theme/ThemeContext";

type Props = {
  title: string;
  onPress: () => void;
  disabled?: boolean;
  variant?: "primary" | "secondary";
  fullWidth?: boolean;
};

export function Button({
  title,
  onPress,
  disabled = false,
  variant = "primary",
  fullWidth = false,
}: Props) {
  const { theme } = useTheme();
  const secondary = variant === "secondary";

  return (
    <Pressable
      accessibilityRole="button"
      accessibilityState={{ disabled }}
      disabled={disabled}
      onPress={onPress}
      style={({ pressed }) => [
        styles.button,
        {
          alignSelf: fullWidth ? "stretch" : "flex-start",
          backgroundColor: secondary
            ? pressed
              ? theme.bgHover
              : theme.bgCard
            : pressed
              ? theme.accentHover
              : theme.accentPrimary,
          borderColor: secondary
            ? theme.borderColor
            : theme.accentPrimary,
          opacity: disabled ? 0.5 : 1,
        },
      ]}
    >
      <Text
        style={[
          styles.label,
          { color: secondary ? theme.textPrimary : "#FFFFFF" },
        ]}
      >
        {title}
      </Text>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  button: {
    minHeight: 44,
    justifyContent: "center",
    alignItems: "center",
    borderWidth: 1,
    borderRadius: 10,
    paddingHorizontal: 18,
    paddingVertical: 10,
  },
  label: {
    fontSize: 14,
    fontWeight: "600",
  },
});