/**
 * Secret redaction for tool output.
 *
 * A single choke-point scrub applied inside the shared result builders. Delegates
 * to the framework SecretScrubber (key-name + value-shape heuristics); best-effort,
 * not a guarantee. Gated by KOMODO_SECRET_SCRUB_ENABLED.
 *
 * @module utils/redact
 */
import { SecretScrubber } from "mcp-server-framework/logger";
import type { Types } from "komodo_client";
import { config } from "../config/index.js";

export const REDACTED = "[redacted]";

let scrubber: SecretScrubber | undefined;
function getScrubber(): SecretScrubber {
  if (!scrubber) {
    scrubber = new SecretScrubber(config.KOMODO_SECRET_SCRUB_KEYS ?? []);
  }
  return scrubber;
}

/**
 * Key names that `SecretScrubber` over-redacts via bare-substring matching
 * (`isSensitiveKey`) but which are never actually secret. Restored to their
 * original value after scrubbing. `SecretScrubber` has no blocklist hook, so
 * this is a post-pass rather than an input to the scrubber itself.
 */
const REDACT_ALLOWLIST = new Set([
  "public_key",
  "attempted_public_key",
  "periphery_public_key",
  "skip_secret_interp",
  "auto_rotate_keys",
]);

/** Walk `scrubbed` and `original` in parallel, restoring allowlisted keys' original values. */
function restoreAllowlisted(scrubbed: unknown, original: unknown): unknown {
  if (Array.isArray(scrubbed) && Array.isArray(original)) {
    return scrubbed.map((v, i) => restoreAllowlisted(v, original[i]));
  }
  if (scrubbed && typeof scrubbed === "object" && original && typeof original === "object") {
    const out: Record<string, unknown> = { ...(scrubbed as Record<string, unknown>) };
    const orig = original as Record<string, unknown>;
    for (const k of Object.keys(out)) {
      out[k] = REDACT_ALLOWLIST.has(k) ? orig[k] : restoreAllowlisted(out[k], orig[k]);
    }
    return out;
  }
  return scrubbed;
}

/** Scrub secrets from a tool result before it reaches the client transcript. */
export function scrubResource(result: unknown): unknown {
  if (!config.KOMODO_SECRET_SCRUB_ENABLED) return result;
  return restoreAllowlisted(getScrubber().scrubObject(result), result);
}

/**
 * Mask the alerter webhook URL/email.
 *
 * The generic `scrubResource` heuristics miss this: the key name (`params.url`)
 * is innocuous and the value (a webhook URL) has no detectable secret shape.
 */
export function redactAlerterEndpoint(alerter: Types.Alerter): Types.Alerter {
  const endpoint = alerter.config?.endpoint;
  const params = endpoint?.params as { url?: string; email?: string } | undefined;
  if (!endpoint || !params) return alerter;
  const masked = {
    ...params,
    ...(params.url ? { url: REDACTED } : {}),
    ...(params.email ? { email: REDACTED } : {}),
    // @type-variance — masked values re-widen the discriminated `AlerterEndpoint.params`
    // union (e.g. Pushover requires `url`); the `type` tag is preserved unchanged above.
  } as typeof endpoint.params;
  return {
    ...alerter,
    config: { ...alerter.config, endpoint: { ...endpoint, params: masked } },
  };
}
