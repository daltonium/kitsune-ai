import React from "react";
import {
  Pressable,
  StyleSheet,
  Text,
  useWindowDimensions,
  View,
} from "react-native";
import { useNavigation } from "@react-navigation/native";
import type { NativeStackNavigationProp } from "@react-navigation/native-stack";

import { Card } from "../components/Card";
import { Screen } from "../components/Screen";
import {
  Body,
  Heading,
  Muted,
} from "../components/Typography";
import { MODULES } from "../constants/modules";
import type { RootStackParamList } from "../navigation/types";
import { useTheme } from "../theme/ThemeContext";

export function ScansScreen() {
  const { width } = useWindowDimensions();
  const { theme } = useTheme();

  const navigation =
    useNavigation<NativeStackNavigationProp<RootStackParamList>>();

  return (
    <Screen>
      <View style={styles.heading}>
        <Heading style={styles.title}>Detection workspace</Heading>
        <Muted>
          Five analysis modules. Predictions are risk estimates,
          not proof of safety or compromise.
        </Muted>
      </View>

      <View style={styles.grid}>
        {MODULES.map((module, index) => (
          <Pressable
            key={module.key}
            accessibilityRole="button"
            accessibilityLabel={`Open ${module.title}`}
            onPress={() =>
              navigation.navigate("Module", { moduleKey: module.key })
            }
            style={({ pressed }) => ({
              flexBasis:
                width >= 1200 ? "31%" : width >= 700 ? "47%" : "100%",
              flexGrow: 1,
              opacity: pressed ? 0.8 : 1,
            })}
          >
            <Card style={styles.moduleCard}>
              <Text
                style={[
                  styles.number,
                  { color: theme.accentPrimary },
                ]}
              >
                0{index + 1}
              </Text>
              <Heading>{module.title}</Heading>
              <Body>{module.summary}</Body>
              <View style={styles.footer}>
                <Muted>Input: {module.input}</Muted>
                <Text
                  style={[
                    styles.open,
                    { color: theme.accentPrimary },
                  ]}
                >
                  Open module
                </Text>
              </View>
            </Card>
          </Pressable>
        ))}
      </View>
    </Screen>
  );
}

const styles = StyleSheet.create({
  heading: { gap: 8 },
  title: { fontSize: 28, lineHeight: 36 },
  grid: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 18,
  },
  moduleCard: {
    flex: 1,
    minHeight: 250,
  },
  number: {
    fontSize: 18,
    fontWeight: "800",
    letterSpacing: 2,
  },
  footer: {
    marginTop: "auto",
    paddingTop: 18,
    gap: 8,
  },
  open: {
    fontSize: 14,
    fontWeight: "600",
  },
});