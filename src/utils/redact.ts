/**
 * Secret Redaction
 *
 * Best-effort redaction of secret values from Komodo API responses before they
 * reach the MCP client (and therefore the model context). Two mechanisms:
 *
 *   - Key-name match: an env var whose name contains a secret keyword *token*
 *     (KEY, SECRET, PASSWORD, ...) or is on the explicit key list.
 *   - Value-shape match: a value that looks like a credential regardless of key
 *     name (URL with embedded credentials, JWT, PEM private-key block).
 *
 * This is a heuristic, NOT a guarantee. A secret with an innocuous key name and
 * an unremarkable value (e.g. a short opaque token) can still slip through.
 * Komodo Variables marked `is_secret` are redacted separately and exactly.
 *
 * @module utils/redact
 */

import { config } from "../config/index.js";

/** Placeholder substituted for a redacted value. Fixed — never encodes length. */
export const REDACTED = "[redacted]";

/** Default secret keyword tokens matched against `_`-delimited env key tokens. */
export const DEFAULT_SECRET_KEYWORDS: readonly string[] = [
  "KEY",
  "SECRET",
  "PASS",
  "PASSWORD",
  "PWD",
  "TOKEN",
  "CREDENTIAL",
  "CREDENTIALS",
  "AUTH",
  "PRIVATE",
];

export interface RedactOptions {
  /** Master switch. When false, all functions pass input through unchanged. */
  readonly enabled: boolean;
  /** Uppercase keyword tokens matched against key tokens. */
  readonly keywords: readonly string[];
  /** Uppercase explicit key names always redacted. */
  readonly explicitKeys: readonly string[];
}

// Value-shape patterns — a deliberately small curated set. Entropy scoring is
// intentionally omitted (highest false-positive lever, diminishing returns).

const URL_WITH_CREDENTIALS = /^[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:[^/\s@]+@/i;
const JWT = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/;
// eslint-disable-next-line security/detect-unsafe-regex -- single optional group with a bounded literal suffix; no overlapping/nested quantifiers, so no ReDoS
const PEM_PRIVATE_KEY = /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/;

/** True if the env key name signals a secret (explicit list or keyword token). */
export function shouldRedactKey(key: string, opts: RedactOptions): boolean {
  const upper = key.toUpperCase();
  if (opts.explicitKeys.includes(upper)) return true;
  return upper.split("_").some((token) => opts.keywords.includes(token));
}

/** True if the value looks like a credential regardless of key name. */
export function shouldRedactValue(value: string): boolean {
  return URL_WITH_CREDENTIALS.test(value) || JWT.test(value) || PEM_PRIVATE_KEY.test(value);
}

/**
 * Redact a single `KEY=value` line.
 *
 * Non-`KEY=value` lines (blank, comment, or no `=` / leading `=`) are returned
 * unchanged. For URL-with-credentials values only the `user:pass@` portion is
 * masked, so the scheme/host/path stay readable for debugging.
 */
export function redactKeyValueLine(line: string, opts: RedactOptions): string {
  if (!opts.enabled) return line;
  const eq = line.indexOf("=");
  if (eq <= 0) return line;
  const key = line.slice(0, eq);
  const value = line.slice(eq + 1);
  if (value === "") return line;
  if (shouldRedactKey(key, opts)) return `${key}=${REDACTED}`;
  if (URL_WITH_CREDENTIALS.test(value)) {
    return `${key}=${value.replace(/(:\/\/)[^/\s:@]+:[^/\s@]+@/, `$1${REDACTED}@`)}`;
  }
  if (shouldRedactValue(value)) return `${key}=${REDACTED}`;
  return line;
}

/** Redact a `\n`-joined env block (stack/deployment `config.environment`). */
export function redactEnvBlock(block: string, opts: RedactOptions): string {
  return block
    .split("\n")
    .map((line) => redactKeyValueLine(line, opts))
    .join("\n");
}

/** Redact a `["KEY=value", ...]` array (Docker inspect `Config.Env`). */
export function redactEnvList(list: readonly string[], opts: RedactOptions): string[] {
  return list.map((line) => redactKeyValueLine(line, opts));
}

/**
 * Build {@link RedactOptions} from parsed app config. Kept separate from the
 * pure functions so those remain unit-testable without importing app config.
 */
export function getRedactOptions(): RedactOptions {
  return {
    enabled: config.KOMODO_SECRET_SCRUB_ENABLED,
    keywords: config.KOMODO_SECRET_SCRUB_KEYWORDS ?? DEFAULT_SECRET_KEYWORDS,
    explicitKeys: config.KOMODO_SECRET_SCRUB_KEYS ?? [],
  };
}
