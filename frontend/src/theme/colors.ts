export interface Theme {
  kitsuneBlack: string;
  kitsuneCrimson: string;
  kitsuneWhite: string;
  kitsuneGold: string;
  kitsuneDeepRed: string;
  kitsunePanel: string;
  kitsuneBorder: string;
  kitsuneMuted: string;
  bgPrimary: string;
  bgSecondary: string;
  bgCard: string;
  bgHover: string;
  textPrimary: string;
  textSecondary: string;
  accentPrimary: string;
  accentHover: string;
  accentPremium: string;
  borderColor: string;
  shadowColor: string;
}

export const DarkTheme: Theme = {
  kitsuneBlack: "#050505",
  kitsuneCrimson: "#D5151E",
  kitsuneWhite: "#F8F7F4",
  kitsuneGold: "#D6A84F",
  kitsuneDeepRed: "#7C0102",
  kitsunePanel: "#121318",
  kitsuneBorder: "#292929",
  kitsuneMuted: "#A1A1AA",
  bgPrimary: "#050505",
  bgSecondary: "#0B0B0E",
  bgCard: "#121318",
  bgHover: "#1B1B21",
  textPrimary: "#F8F7F4",
  textSecondary: "#A1A1AA",
  accentPrimary: "#D5151E",
  accentHover: "#F0202A",
  accentPremium: "#D6A84F",
  borderColor: "#292929",
  shadowColor: "rgba(0, 0, 0, 0.45)",
};

export const LightTheme: Theme = {
  kitsuneBlack: "#171719",
  kitsuneCrimson: "#C4141D",
  kitsuneWhite: "#FFFFFF",
  kitsuneGold: "#936B25",
  kitsuneDeepRed: "#7C0102",
  kitsunePanel: "#FFFFFF",
  kitsuneBorder: "#E4DFDA",
  kitsuneMuted: "#686873",
  bgPrimary: "#F7F5F2",
  bgSecondary: "#EFEBE6",
  bgCard: "#FFFFFF",
  bgHover: "#F0EAE5",
  textPrimary: "#171719",
  textSecondary: "#686873",
  accentPrimary: "#C4141D",
  accentHover: "#A80F17",
  accentPremium: "#936B25",
  borderColor: "#E4DFDA",
  shadowColor: "rgba(35, 20, 20, 0.08)",
};

export const Themes = {
  dark: DarkTheme,
  light: LightTheme,
} as const;

export type ThemeMode = keyof typeof Themes;

export const getTheme = (mode: ThemeMode): Theme => Themes[mode];

export const DefaultTheme: Theme = DarkTheme;