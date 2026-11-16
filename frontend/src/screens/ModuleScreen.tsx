import React from "react";
import type { NativeStackScreenProps } from "@react-navigation/native-stack";

import { Body, Heading, Muted } from "../components/Typography";
import { Card } from "../components/Card";
import { Screen } from "../components/Screen";
import { getModule } from "../constants/modules";
import type { RootStackParamList } from "../navigation/types";

type Props = NativeStackScreenProps<RootStackParamList, "Module">;

export function ModuleScreen({ route }: Props) {
  const module = getModule(route.params.moduleKey);

  if (module === undefined) {
    return (
      <Screen>
        <Card>
          <Heading>Unknown module</Heading>
        </Card>
      </Screen>
    );
  }

  return (
    <Screen>
      <Card>
        <Heading>{module.title}</Heading>
        <Body>{module.summary}</Body>
        <Muted>Input: {module.input}</Muted>
      </Card>
      <Card>
        <Muted>
          The scan form for this module is built in Phase 15. Results are risk
          estimates, not proof that something is safe or malicious.
        </Muted>
      </Card>
    </Screen>
  );
}