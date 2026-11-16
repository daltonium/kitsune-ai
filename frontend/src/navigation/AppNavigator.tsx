import React from "react";
import {
  DarkTheme as NavDarkTheme,
  DefaultTheme as NavLightTheme,
  NavigationContainer,
  type Theme as NavTheme,
} from "@react-navigation/native";
import { createBottomTabNavigator } from "@react-navigation/bottom-tabs";
import { createNativeStackNavigator } from "@react-navigation/native-stack";

import { getModule } from "../constants/modules";
import { CompanyScreen } from "../screens/CompanyScreen";
import { DashboardScreen } from "../screens/DashboardScreen";
import { HistoryScreen } from "../screens/HistoryScreen";
import { ModuleScreen } from "../screens/ModuleScreen";
import { ScansScreen } from "../screens/ScansScreen";
import type { Theme, ThemeMode } from "../theme/colors";
import { useTheme } from "../theme/ThemeContext";
import type { RootStackParamList, TabParamList } from "./types";

const Tab = createBottomTabNavigator<TabParamList>();
const Stack = createNativeStackNavigator<RootStackParamList>();

function buildNavigationTheme(mode: ThemeMode, theme: Theme): NavTheme {
  const base = mode === "dark" ? NavDarkTheme : NavLightTheme;
  return {
    ...base,
    colors: {
      ...base.colors,
      primary: theme.accentPrimary,
      background: theme.bgPrimary,
      card: theme.bgSecondary,
      text: theme.textPrimary,
      border: theme.borderColor,
      notification: theme.accentPremium,
    },
  };
}

function Tabs() {
  return (
    <Tab.Navigator
      screenOptions={{
        tabBarIcon: () => null,
        tabBarIconStyle: { display: "none" },
      }}
    >
      <Tab.Screen name="Dashboard" component={DashboardScreen} />
      <Tab.Screen name="Scans" component={ScansScreen} />
      <Tab.Screen name="History" component={HistoryScreen} />
      <Tab.Screen name="Company" component={CompanyScreen} />
    </Tab.Navigator>
  );
}

export function AppNavigator() {
  const { mode, theme } = useTheme();

  return (
    <NavigationContainer theme={buildNavigationTheme(mode, theme)}>
      <Stack.Navigator>
        <Stack.Screen
          name="Tabs"
          component={Tabs}
          options={{ headerShown: false }}
        />
        <Stack.Screen
          name="Module"
          component={ModuleScreen}
          options={({ route }) => ({
            title: getModule(route.params.moduleKey)?.title ?? "Module",
          })}
        />
      </Stack.Navigator>
    </NavigationContainer>
  );
}