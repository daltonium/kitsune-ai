export type ModuleKey =
  | "phishing_url"
  | "network_intrusion"
  | "phishing_email"
  | "malware_risk"
  | "suspicious_login";

export type ModuleInfo = {
  key: ModuleKey;
  title: string;
  summary: string;
  input: string;
};

export const MODULES: readonly ModuleInfo[] = [
  {
    key: "phishing_url",
    title: "Phishing URL",
    summary: "Checks the text of a URL for phishing patterns. The URL is never visited.",
    input: "A URL",
  },
  {
    key: "network_intrusion",
    title: "Network Intrusion",
    summary: "Scores network-flow records from an uploaded CSV file.",
    input: "A CSV file",
  },
  {
    key: "phishing_email",
    title: "Phishing Email",
    summary: "Scores an email's subject and body. Links are counted, never opened.",
    input: "Subject and body",
  },
  {
    key: "malware_risk",
    title: "Malware Risk",
    summary: "Static analysis of a Windows .exe file. The file is never run.",
    input: "A .exe file",
  },
  {
    key: "suspicious_login",
    title: "Suspicious Login",
    summary: "Flags unusual login behavior in login-event data.",
    input: "A CSV file",
  },
];

export function getModule(key: ModuleKey): ModuleInfo | undefined {
  return MODULES.find((module) => module.key === key);
}