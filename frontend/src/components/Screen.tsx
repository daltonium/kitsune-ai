import React from "react";
import { ScrollView, StyleSheet, View } from "react-native";

import { useTheme } from "../theme/ThemeContext";

export function Screen({ children }: { children: React.ReactNode }) {
  const { theme } = useTheme();
  return (
    <ScrollView
      style={[styles.scroll, { backgroundColor: theme.bgPrimary }]}
      contentContainerStyle={styles.content}
    >
      <View style={styles.inner}>{children}</View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  scroll: { flex: 1 },
  content: { padding: 16, alignItems: "center" },
  inner: { width: "100%", maxWidth: 720, gap: 12 },
});