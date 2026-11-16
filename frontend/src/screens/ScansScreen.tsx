import React from "react";
import { Pressable } from "react-native";
import { useNavigation } from "@react-navigation/native";
import type { NativeStackNavigationProp } from "@react-navigation/native-stack";

import { Body, Heading, Muted } from "../components/Typography";
import { Card } from "../components/Card";
import { Screen } from "../components/Screen";
import { MODULES } from "../constants/modules";
import type { RootStackParamList } from "../navigation/types";

export function ScansScreen() {
  const navigation =
    useNavigation<NativeStackNavigationProp<RootStackParamList>>();

  return (
    <Screen>
      {MODULES.map((module) => (
        <Pressable
          key={module.key}
          accessibilityRole="button"
          onPress={() => navigation.navigate("Module", { moduleKey: module.key })}
        >
          <Card>
            <Heading>{module.title}</Heading>
            <Body>{module.summary}</Body>
            <Muted>Input: {module.input}</Muted>
          </Card>
        </Pressable>
      ))}
    </Screen>
  );
}