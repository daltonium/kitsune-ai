import React from "react";

import { Heading, Muted } from "../components/Typography";
import { Card } from "../components/Card";
import { Screen } from "../components/Screen";

export function CompanyScreen() {
  return (
    <Screen>
      <Card>
        <Heading>Company portal</Heading>
        <Muted>
          API keys, plans and usage appear here after sign-in. The company
          portal is built in Phase 16.
        </Muted>
      </Card>
    </Screen>
  );
}