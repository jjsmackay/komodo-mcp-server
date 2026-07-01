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
import { config } from "../config/index.js";

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
