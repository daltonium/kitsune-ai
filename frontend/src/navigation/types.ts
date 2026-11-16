import type { ModuleKey } from "../constants/modules";

export type RootStackParamList = {
  Tabs: undefined;
  Module: { moduleKey: ModuleKey };
};

export type TabParamList = {
  Dashboard: undefined;
  Scans: undefined;
  History: undefined;
  Company: undefined;
};