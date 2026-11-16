import React from "react";
import { Pressable, StyleSheet, Text } from "react-native";

import { useTheme } from "../theme/ThemeContext";

type Props = {
  title: string;
  onPress: () => void;
};

export function Button({ title, onPress }: Props) {
  const { theme } = useTheme();
  return (
    <Pressable
      accessibilityRole="button"
      onPress={onPress}
      style={({ pressed }) => [
        styles.button,
        { backgroundColor: pressed ? theme.accentHover : theme.accentPrimary },
      ]}
    >
      <Text style={[styles.label, { color: theme.kitsuneWhite }]}>{title}</Text>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  button: {
    alignSelf: "flex-start",
    borderRadius: 8,
    paddingHorizontal: 16,
    paddingVertical: 10,
  },
  label: { fontSize: 14, fontWeight: "600" },
});