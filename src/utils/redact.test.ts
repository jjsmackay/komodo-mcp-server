import { test } from "node:test";
import assert from "node:assert/strict";
import { scrubResource, redactAlerterEndpoint } from "./redact.js";

test("scrubs a sensitively-named field (webhook_secret)", () => {
  const out = scrubResource({ config: { webhook_secret: "shhh-123" } }) as any;
  assert.notEqual(out.config.webhook_secret, "shhh-123");
});

test("scrubs secret lines inside an env block string", () => {
  const out = scrubResource({ config: { environment: "HOST=h\nAPI_KEY=abc123\nDB_PASSWORD=hunter2" } }) as any;
  assert.doesNotMatch(out.config.environment, /abc123|hunter2/);
  assert.match(out.config.environment, /HOST=h/);
});

test("scrubs a connection-string value (git clone token)", () => {
  const out = scrubResource({ config: { command: "git clone https://x:ghp_TOKEN@github.com/o/r.git" } }) as any;
  assert.doesNotMatch(out.config.command, /ghp_TOKEN/);
});

test("false-positive gate: benign resource-config fields survive", () => {
  const input = {
    name: "my-stack",
    config: { server_id: "srv-1", builder_id: "b-2", branch: "main", git_account: "octocat", repo: "o/r" },
    info: { state: "running" },
  };
  const out = scrubResource(input) as any;
  assert.equal(out.name, "my-stack");
  assert.equal(out.config.server_id, "srv-1");
  assert.equal(out.config.builder_id, "b-2");
  assert.equal(out.config.branch, "main");
  assert.equal(out.config.git_account, "octocat");
  assert.equal(out.config.repo, "o/r");
  assert.equal(out.info.state, "running");
});

test("false-positive gate: allowlisted public-key/flag fields survive, control field stays redacted", () => {
  const input = {
    config: {
      webhook_secret: "shh",
      secret_args: true,
      skip_secret_interp: true,
      auto_rotate_keys: false,
    },
    info: {
      public_key: "ssh-ed25519 AAAA...",
      attempted_public_key: "ssh-ed25519 BBBB...",
    },
  };
  const out = scrubResource(input) as any;
  // Allowlisted benign fields survive unredacted.
  assert.equal(out.info.public_key, "ssh-ed25519 AAAA...");
  assert.equal(out.info.attempted_public_key, "ssh-ed25519 BBBB...");
  assert.equal(out.config.skip_secret_interp, true);
  assert.equal(out.config.auto_rotate_keys, false);
  // Control: fields NOT on the allowlist stay redacted.
  assert.notEqual(out.config.webhook_secret, "shh");
  assert.notEqual(out.config.secret_args, true);
});

test("passes input through unchanged when a plain object has no secrets (enable-gate itself verified by inspection)", () => {
  // This does NOT exercise KOMODO_SECRET_SCRUB_ENABLED=false — `config` is a frozen
  // singleton parsed at module load, so toggling it here would need a brittle
  // env-reload harness. The gate at scrubResource's `if (!config.KOMODO_SECRET_SCRUB_ENABLED)
  // return result;` is verified by inspection instead. This test only asserts that
  // scrubbing a secret-free object is a no-op.
  const input = { a: 1, b: "hello" };
  assert.deepEqual(scrubResource(input), input);
});

test("redactAlerterEndpoint masks endpoint url and email", () => {
  const out: any = redactAlerterEndpoint({
    config: { endpoint: { type: "Slack", params: { url: "https://hooks.slack.com/services/T/B/xyz" } } },
  } as any);
  assert.notEqual(out.config.endpoint.params.url, "https://hooks.slack.com/services/T/B/xyz");
});

test("redactAlerterEndpoint masks email on an Ntfy endpoint", () => {
  const out: any = redactAlerterEndpoint({
    config: { endpoint: { type: "Ntfy", params: { url: "https://ntfy.sh/x", email: "a@b.com" } } },
  } as any);
  assert.notEqual(out.config.endpoint.params.email, "a@b.com");
});

test("redactAlerterEndpoint passes an alerter with no endpoint through", () => {
  const a: any = { config: {} };
  assert.deepEqual(redactAlerterEndpoint(a), a);
});
