import React, {
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
import {
  ActivityIndicator,
  StyleSheet,
  Text,
  useWindowDimensions,
  View,
} from "react-native";

import {
  ApiError,
  getDashboard,
  type DashboardResponse,
} from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { Screen } from "../components/Screen";
import {
  Body,
  Heading,
  Muted,
} from "../components/Typography";
import { MODULES } from "../constants/modules";
import { useTheme } from "../theme/ThemeContext";

export function DashboardScreen() {
  const { state, signOut, restoreSession } = useAuth();
  const { theme } = useTheme();
  const { width } = useWindowDimensions();

  const wide = width >= 1000;
  const small = width < 600;

  const [data, setData] = useState<DashboardResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [logoutBusy, setLogoutBusy] = useState(false);

  const mounted = useRef(false);
  const requestId = useRef(0);

  const load = useCallback(async () => {
    const id = ++requestId.current;
    setLoading(true);
    setError("");

    try {
      const result = await getDashboard();
      if (mounted.current && id === requestId.current) {
        setData(result);
      }
    } catch (failure) {
      if (!mounted.current || id !== requestId.current) return;

      if (
        failure instanceof ApiError &&
        (failure.status === 401 || failure.status === 403)
      ) {
        void restoreSession();
        return;
      }

      setError(
        failure instanceof Error
          ? failure.message
          : "Could not load the dashboard."
      );
    } finally {
      if (mounted.current && id === requestId.current) {
        setLoading(false);
      }
    }
  }, [restoreSession]);

  useEffect(() => {
    mounted.current = true;
    void load();

    return () => {
      mounted.current = false;
      requestId.current += 1;
    };
  }, [load]);

  async function logout() {
    setLogoutBusy(true);
    setError("");

    try {
      await signOut();
    } catch (failure) {
      if (mounted.current) {
        setError(
          failure instanceof Error
            ? failure.message
            : "Could not sign out."
        );
        setLogoutBusy(false);
      }
    }
  }

  const username =
    state.phase === "authenticated" ? state.user.username : "";

  const metrics = data
    ? [
        {
          label: "Total scans",
          value: data.total_scans,
          detail: "All-time activity",
        },
        {
          label: "Recent scans",
          value: data.period_scans,
          detail: `Last ${data.period.days} days`,
        },
        {
          label: "High / critical",
          value: data.period_high_risk_scans,
          detail: "Scans in selected period",
        },
        {
          label: "Unread alerts",
          value: data.unread_alerts,
          detail: "All-time unread alerts",
        },
      ]
    : [];

  const maxDaily = Math.max(
    1,
    ...(data?.daily_scans.map((day) => day.scans) ?? [])
  );

  return (
    <Screen>
      <View
        style={[
          styles.pageHeader,
          small && styles.pageHeaderSmall,
        ]}
      >
        <View style={styles.titleBlock}>
          <Muted>YOUR WORKSPACE</Muted>
          <Text
            style={[
              styles.pageTitle,
              { color: theme.textPrimary },
            ]}
          >
            Security overview
          </Text>
          <Muted>Welcome back, {username}.</Muted>
        </View>

        <View style={styles.actions}>
          <Button
            title={loading ? "Refreshing..." : "Refresh"}
            disabled={loading || logoutBusy}
            onPress={() => void load()}
          />
          <Button
            title={logoutBusy ? "Signing out..." : "Sign out"}
            variant="secondary"
            disabled={logoutBusy}
            onPress={() => void logout()}
          />
        </View>
      </View>

      {error !== "" && (
        <Card style={{ borderColor: theme.accentPrimary }}>
          <Body accessibilityRole="alert">{error}</Body>
          {data && (
            <Muted>
              Previously loaded figures may be outdated.
            </Muted>
          )}
        </Card>
      )}

      {loading && !data && (
        <Card>
          <ActivityIndicator color={theme.accentPrimary} />
          <Muted>Loading your security overview...</Muted>
        </Card>
      )}

      {data && (
        <>
          <View style={styles.metrics}>
            {metrics.map((metric) => (
              <Card
                key={metric.label}
                style={{
                  flexBasis: wide ? "23%" : small ? "100%" : "47%",
                  flexGrow: 1,
                }}
              >
                <Muted>{metric.label}</Muted>
                <Text
                  style={[
                    styles.metricValue,
                    { color: theme.textPrimary },
                  ]}
                >
                  {metric.value.toLocaleString()}
                </Text>
                <Muted>{metric.detail}</Muted>
              </Card>
            ))}
          </View>

          <View
            style={[
              styles.columns,
              !wide && styles.stacked,
            ]}
          >
            <View style={styles.mainColumn}>
              <Card>
                <View style={styles.panelHeader}>
                  <Heading>Scan activity</Heading>
                  <Muted>Last {data.period.days} days</Muted>
                </View>

                <Muted>
                  {data.period.date_from} — {data.period.date_to}
                  {" · "}{data.period.timezone}
                </Muted>

                {data.period_scans === 0 && (
                  <Muted>
                    No scans yet in this period. Your activity will
                    appear here after scanning.
                  </Muted>
                )}

                <View style={styles.activity}>
                  {data.daily_scans.map((day) => (
                    <View key={day.date} style={styles.activityRow}>
                      <Text
                        style={[
                          styles.dateLabel,
                          { color: theme.textSecondary },
                        ]}
                      >
                        {day.date.slice(5)}
                      </Text>

                      <View
                        style={[
                          styles.track,
                          { backgroundColor: theme.bgHover },
                        ]}
                      >
                        <View
                          style={{
                            width: `${(day.scans / maxDaily) * 100}%`,
                            height: "100%",
                            borderRadius: 5,
                            backgroundColor: theme.accentPrimary,
                          }}
                        />
                      </View>

                      <Text
                        style={[
                          styles.countLabel,
                          { color: theme.textPrimary },
                        ]}
                      >
                        {day.scans}
                      </Text>
                    </View>
                  ))}
                </View>
              </Card>

              <Card>
                <Heading>Detection modules</Heading>
                <Muted>Scan volume in the selected period.</Muted>

                {MODULES.map((module) => (
                  <View
                    key={module.key}
                    style={[
                      styles.listRow,
                      { borderBottomColor: theme.borderColor },
                    ]}
                  >
                    <Body style={styles.rowText}>
                      {module.title}
                    </Body>
                    <Body style={styles.rowCount}>
                      {data.by_module[module.key] ?? 0}
                    </Body>
                  </View>
                ))}
              </Card>
            </View>

            <View style={styles.sideColumn}>
              <Card>
                <Heading>Risk distribution</Heading>
                <Muted>Model outputs, not confirmed incidents.</Muted>

                {Object.entries(data.by_risk).map(([risk, count]) => (
                  <View key={risk} style={styles.riskRow}>
                    <View style={styles.riskLabel}>
                      <View
                        style={[
                          styles.dot,
                          {
                            backgroundColor:
                              risk === "critical" || risk === "high"
                                ? theme.accentPrimary
                                : risk === "medium"
                                  ? theme.accentPremium
                                  : theme.textSecondary,
                          },
                        ]}
                      />
                      <Body style={styles.capitalize}>{risk}</Body>
                    </View>
                    <Body>{count}</Body>
                  </View>
                ))}
              </Card>

              <Card>
                <Heading>Recent alerts</Heading>
                <Muted>Latest model-generated notifications.</Muted>

                {data.recent_alerts.length === 0 && (
                  <View style={styles.emptyState}>
                    <Body>No alerts yet</Body>
                    <Muted>
                      Alerts will appear here when a scan meets
                      the configured risk threshold.
                    </Muted>
                  </View>
                )}

                {data.recent_alerts.map((alert) => (
                  <View
                    key={alert.id}
                    style={[
                      styles.alert,
                      { borderTopColor: theme.borderColor },
                    ]}
                  >
                    <View style={styles.panelHeader}>
                      <Muted style={styles.capitalize}>
                        {alert.severity}
                      </Muted>
                      <Muted>
                        {alert.is_read ? "Read" : "Unread"}
                      </Muted>
                    </View>
                    <Body>{alert.title}</Body>
                    <Muted>{alert.message}</Muted>
                  </View>
                ))}
              </Card>
            </View>
          </View>

          <Muted>{data.note}</Muted>
        </>
      )}
    </Screen>
  );
}

const styles = StyleSheet.create({
  pageHeader: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    gap: 20,
  },
  pageHeaderSmall: {
    flexDirection: "column",
    alignItems: "stretch",
  },
  titleBlock: {
    flex: 1,
    gap: 5,
    minWidth: 0,
  },
  pageTitle: {
    fontSize: 30,
    lineHeight: 38,
    fontWeight: "800",
  },
  actions: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 10,
  },
  metrics: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 16,
  },
  metricValue: {
    fontSize: 36,
    lineHeight: 44,
    fontWeight: "700",
  },
  columns: {
    flexDirection: "row",
    alignItems: "flex-start",
    gap: 20,
  },
  stacked: {
    flexDirection: "column",
    alignItems: "stretch",
  },
  mainColumn: {
    flex: 2,
    minWidth: 0,
    gap: 20,
  },
  sideColumn: {
    flex: 1,
    minWidth: 0,
    gap: 20,
  },
  panelHeader: {
    flexDirection: "row",
    flexWrap: "wrap",
    justifyContent: "space-between",
    alignItems: "center",
    gap: 8,
  },
  activity: {
    gap: 16,
    paddingVertical: 16,
  },
  activityRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: 12,
  },
  dateLabel: {
    width: 44,
    fontSize: 12,
  },
  track: {
    flex: 1,
    height: 10,
    borderRadius: 5,
    overflow: "hidden",
  },
  countLabel: {
    minWidth: 28,
    textAlign: "right",
    fontSize: 13,
  },
  listRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    paddingVertical: 12,
    borderBottomWidth: 1,
    gap: 12,
  },
  rowText: { flex: 1 },
  rowCount: { fontWeight: "700" },
  riskRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    paddingVertical: 8,
    gap: 12,
  },
  riskLabel: {
    flexDirection: "row",
    alignItems: "center",
    gap: 10,
  },
  dot: {
    width: 8,
    height: 8,
    borderRadius: 4,
  },
  capitalize: { textTransform: "capitalize" },
  alert: {
    borderTopWidth: 1,
    paddingTop: 16,
    marginTop: 6,
    gap: 6,
  },
  emptyState: {
    paddingVertical: 22,
    gap: 6,
  },
});