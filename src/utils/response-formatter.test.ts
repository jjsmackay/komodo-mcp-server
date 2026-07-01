import { test } from "node:test";
import assert from "node:assert/strict";
import { buildApplyResult, buildDeleteResult } from "./response-formatter.js";

test("buildApplyResult scrubs secret env in the returned resource", () => {
  const built = buildApplyResult("update", "stack", "s", { config: { environment: "API_KEY=abc123" } });
  const env = (built.payload.resource as any).config.environment;
  assert.doesNotMatch(env, /abc123/);
  assert.doesNotMatch(built.text, /abc123/);
});

test("buildDeleteResult scrubs webhook_secret in the returned resource", () => {
  const built = buildDeleteResult("build", "b", { config: { webhook_secret: "shh-987" } });
  assert.notEqual((built.payload.resource as any).config.webhook_secret, "shh-987");
  assert.doesNotMatch(built.text, /shh-987/);
});
