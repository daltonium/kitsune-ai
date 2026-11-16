import React from "react";
import {
  Image,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  useWindowDimensions,
  View,
} from "react-native";

import { useTheme } from "../theme/ThemeContext";

type Props = {
  children: React.ReactNode;
  compact?: boolean;
};

export function Screen({ children, compact = false }: Props) {
  const { theme, mode, toggleMode } = useTheme();
  const { width } = useWindowDimensions();
  const small = width < 600;

  return (
    <View style={[styles.root, { backgroundColor: theme.bgPrimary }]}>
      <View
        style={[
          styles.header,
          {
            backgroundColor: theme.bgSecondary,
            borderBottomColor: theme.borderColor,
            paddingHorizontal: small ? 16 : 32,
          },
        ]}
      >
        <View style={styles.headerInner}>
          <View style={styles.brand}>
            <Image
              source={require("../../assets/kitsune-logo.png")}
              accessibilityLabel="KITSUNE AI logo"
              resizeMode="contain"
              style={styles.logo}
            />

            <View style={styles.brandText}>
              <Text style={[styles.brandName, { color: theme.textPrimary }]}>
                KITSUNE AI
              </Text>
              {!small && (
                <Text
                  style={[styles.tagline, { color: theme.textSecondary }]}
                >
                  Security intelligence workspace
                </Text>
              )}
            </View>
          </View>

          <Pressable
            accessibilityRole="button"
            accessibilityLabel={
              mode === "dark" ? "Switch to light mode" : "Switch to dark mode"
            }
            onPress={toggleMode}
            style={({ pressed }) => [
              styles.themeButton,
              {
                borderColor: theme.borderColor,
                backgroundColor: pressed ? theme.bgHover : theme.bgCard,
              },
            ]}
          >
            <Text
              style={[styles.themeLabel, { color: theme.textPrimary }]}
            >
              {mode === "dark" ? "Light mode" : "Dark mode"}
            </Text>
          </Pressable>
        </View>
      </View>

      <ScrollView
        style={styles.scroll}
        keyboardShouldPersistTaps="handled"
        contentContainerStyle={[
          styles.content,
          {
            paddingHorizontal: small ? 16 : 32,
            paddingTop: small ? 20 : 32,
          },
        ]}
      >
        <View
          style={[
            styles.inner,
            compact && styles.compact,
          ]}
        >
          {children}
        </View>
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1 },
  header: {
    borderBottomWidth: 1,
    paddingVertical: 12,
  },
  headerInner: {
    width: "100%",
    maxWidth: 1360,
    alignSelf: "center",
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    gap: 12,
  },
  brand: {
    flexDirection: "row",
    alignItems: "center",
    gap: 12,
    flexShrink: 1,
  },
  brandText: { flexShrink: 1, gap: 2 },
  logo: {
    width: 44,
    height: 44,
    borderRadius: 10,
    backgroundColor: "#050505",
  },
  brandName: {
    fontSize: 16,
    fontWeight: "800",
    letterSpacing: 1,
  },
  tagline: { fontSize: 12 },
  themeButton: {
    borderWidth: 1,
    paddingHorizontal: 14,
    paddingVertical: 10,
    borderRadius: 10,
    flexShrink: 0,
  },
  themeLabel: { fontSize: 13, fontWeight: "600" },
  scroll: { flex: 1 },
  content: {
    alignItems: "center",
    paddingBottom: 40,
  },
  inner: {
    width: "100%",
    maxWidth: 1360,
    gap: 20,
  },
  compact: {
    maxWidth: 480,
  },
});