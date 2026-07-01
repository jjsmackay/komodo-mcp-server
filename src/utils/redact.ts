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

/** Scrub secrets from a tool result before it reaches the client transcript. */
export function scrubResource(result: unknown): unknown {
  if (!config.KOMODO_SECRET_SCRUB_ENABLED) return result;
  return getScrubber().scrubObject(result);
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
