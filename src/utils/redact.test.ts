import { test } from "node:test";
import assert from "node:assert/strict";
import {
  REDACTED,
  DEFAULT_SECRET_KEYWORDS,
  shouldRedactKey,
  shouldRedactValue,
  redactKeyValueLine,
  redactEnvBlock,
  redactEnvList,
  type RedactOptions,
} from "./redact.js";

const opts: RedactOptions = {
  enabled: true,
  keywords: DEFAULT_SECRET_KEYWORDS,
  explicitKeys: [],
};

test("keyword token in key redacts value", () => {
  assert.equal(redactKeyValueLine("API_KEY=abc123", opts), `API_KEY=${REDACTED}`);
  assert.equal(redactKeyValueLine("DB_PASSWORD=hunter2", opts), `DB_PASSWORD=${REDACTED}`);
  assert.equal(redactKeyValueLine("AUTH_TOKEN=xyz", opts), `AUTH_TOKEN=${REDACTED}`);
});

test("substring-only match on a key token does NOT redact", () => {
  // MONKEY contains 'KEY' as a substring but is not the token 'KEY'.
  assert.equal(redactKeyValueLine("MONKEY_NAME=jono", opts), "MONKEY_NAME=jono");
});

test("case-insensitive key matching", () => {
  assert.equal(redactKeyValueLine("api_secret=zzz", opts), `api_secret=${REDACTED}`);
});

test("URL with embedded credentials masks only the credential portion", () => {
  assert.equal(
    redactKeyValueLine("DATABASE_URL=postgres://user:hunter2@db.host:5432/app", opts),
    `DATABASE_URL=postgres://${REDACTED}@db.host:5432/app`,
  );
});

test("JWT-shaped value under an innocuous key redacts fully", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc-_123";
  assert.equal(redactKeyValueLine(`GREETING=${jwt}`, opts), `GREETING=${REDACTED}`);
});

test("PEM private key block redacts fully", () => {
  const pem = "-----BEGIN RSA PRIVATE KEY-----MIIEabc-----END RSA PRIVATE KEY-----";
  assert.equal(redactKeyValueLine(`FOO=${pem}`, opts), `FOO=${REDACTED}`);
});

test("explicit key list redacts a keyword-free key", () => {
  const explicit: RedactOptions = { ...opts, explicitKeys: ["DATABASE_URL", "SESSION_ID"] };
  assert.equal(redactKeyValueLine("SESSION_ID=opaque123", explicit), `SESSION_ID=${REDACTED}`);
});

test("disabled options pass everything through", () => {
  const off: RedactOptions = { ...opts, enabled: false };
  assert.equal(redactKeyValueLine("API_KEY=abc", off), "API_KEY=abc");
});

test("non KEY=value lines are untouched", () => {
  assert.equal(redactKeyValueLine("", opts), "");
  assert.equal(redactKeyValueLine("# a comment", opts), "# a comment");
  assert.equal(redactKeyValueLine("=leadingequals", opts), "=leadingequals");
});

test("empty value is left as-is", () => {
  assert.equal(redactKeyValueLine("API_KEY=", opts), "API_KEY=");
});

test("shouldRedactKey / shouldRedactValue helpers", () => {
  assert.equal(shouldRedactKey("SECRET_FOO", opts), true);
  assert.equal(shouldRedactKey("PLAIN", opts), false);
  assert.equal(shouldRedactValue("eyJa.eyJb.cc-_1"), true);
  assert.equal(shouldRedactValue("just text"), false);
});

test("redactEnvBlock redacts a multi-line block, preserving order and non-secrets", () => {
  const block = "HOST=localhost\nAPI_KEY=abc\nPORT=8080";
  assert.equal(redactEnvBlock(block, opts), `HOST=localhost\nAPI_KEY=${REDACTED}\nPORT=8080`);
});

test("redactEnvList redacts a Docker-style env array", () => {
  const list = ["PATH=/usr/bin", "TOKEN=deadbeef"];
  assert.deepEqual(redactEnvList(list, opts), ["PATH=/usr/bin", `TOKEN=${REDACTED}`]);
});
