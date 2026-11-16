import React from "react";

import { Heading, Muted } from "../components/Typography";
import { Card } from "../components/Card";
import { Screen } from "../components/Screen";

export function HistoryScreen() {
  return (
    <Screen>
      <Card>
        <Heading>Scan history</Heading>
        <Muted>
          Your past scans and alerts appear here once sign-in is built. Scan
          history screens are completed in Phase 16.
        </Muted>
      </Card>
    </Screen>
  );
}