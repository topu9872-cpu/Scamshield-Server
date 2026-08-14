import { test } from "node:test";
import assert from "node:assert/strict";

import { scoreUrlRisk } from "../riskScoring.js";

test("suspicious phishing URL keeps a high risk score even without threat intelligence hits", () => {
  const score = scoreUrlRisk(
    "url",
    "https://payment-confirmation.example/login",
    0,
    0,
    0,
  );

  assert.ok(
    score > 60,
    `expected a suspicious URL to score above 60, got ${score}`,
  );
});
