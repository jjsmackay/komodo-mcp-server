/**
 * API Helpers
 *
 * Low-level utilities for Komodo API interaction including client access,
 * cancellation checks, and error classification/wrapping.
 *
 * @module utils/api-helpers
 */

import type { KomodoClient } from "../client.js";
import {
  ClientNotConfiguredError,
  ApiError,
  ConnectionError,
  AuthenticationError,
  extractKomodoError,
} from "../errors/index.js";
import { OperationCancelledError, getCurrentToolContext } from "mcp-server-framework";
import { connectUserClient, getGlobalClient } from "../client.js";
import { komodoIdentity } from "../auth/komodo-identity.js";

// ============================================================================
// Error Code Sets
// ============================================================================

/** Connection-related Node.js error codes */
const CONNECTION_ERROR_CODES = new Set(["ECONNREFUSED", "ECONNRESET", "ENOTFOUND", "ERR_NETWORK"]);

/** Timeout-related Node.js error codes */
const TIMEOUT_ERROR_CODES = new Set(["ECONNABORTED", "UND_ERR_CONNECT_TIMEOUT"]);

// ============================================================================
// Client Access
// ============================================================================

/**
 * Returns the Komodo client for the current tool call, resolved by operating mode.
 *
 * Reads the current tool context's auth (via AsyncLocalStorage, set by the framework
 * before each handler runs):
 * - **Authenticated** request → a client scoped to that user's minted Komodo JWT, built
 *   fresh from the request's own `auth.extra` so users are strictly isolated.
 * - **Anonymous** request (stdio, or HTTP with auth disabled) → the global service
 *   connection from the `[komodo]` credentials.
 *
 * Synchronous by design (no `await` at the ~80 call sites): the per-user client is a thin,
 * stateless JWT wrapper, and the global connection is already established at startup.
 */
export function requireClient(): KomodoClient {
  const auth = getCurrentToolContext()?.auth;
  const identity = komodoIdentity.read(auth);

  if (identity) {
    // Authenticated Komodo user → their own JWT-scoped client.
    return connectUserClient(identity.komodoJwt);
  }

  if (auth) {
    // Authenticated to the MCP server but no Komodo identity is bound. This should not
    // occur — the OAuth hooks deny sessions for users that don't exist in Komodo — so
    // treat it as a misconfiguration rather than silently falling back to global creds.
    throw ClientNotConfiguredError.notConfigured();
  }

  // Anonymous request → global service connection (stdio / auth-disabled HTTP).
  const client = getGlobalClient();
  if (!client) throw ClientNotConfiguredError.notConfigured();
  return client;
}

// ============================================================================
// Cancellation
// ============================================================================

/**
 * Checks if an operation was cancelled via AbortSignal.
 */
export function checkCancelled(signal: AbortSignal | undefined, operation: string): void {
  if (signal?.aborted) {
    throw new OperationCancelledError(operation);
  }
}

// ============================================================================
// API Call Wrapper
// ============================================================================

/**
 * Extracts the HTTP status code from a komodo_client plain-object rejection.
 * Returns undefined if the error is not a komodo_client response.
 */
function getKomodoStatus(error: unknown): number | undefined {
  if (typeof error === "object" && error !== null) {
    const status = (error as Record<string, unknown>).status;
    if (typeof status === "number") return status;
  }
  return undefined;
}

/**
 * Extracts a Node.js error code from an Error instance, including nested cause chains.
 * Node.js fetch wraps the real error (ECONNREFUSED, etc.) in error.cause.
 */
function getErrorCode(error: unknown): string | undefined {
  if (error instanceof Error) {
    const code = (error as Error & { code?: string }).code;
    if (code) return code;
    if (error.cause instanceof Error) {
      return (error.cause as Error & { code?: string }).code;
    }
  }
  return undefined;
}

/**
 * Wraps an API call with error handling and cancellation support.
 *
 * Properly handles komodo_client rejections which are plain objects:
 * - HTTP errors: { status: 4xx|5xx, result: { error: "message", trace?: [...] } }
 * - Network errors: { status: 1, result: { error: "..." }, error: <Error> }
 */
export async function wrapApiCall<T>(operation: string, apiCall: () => Promise<T>, signal?: AbortSignal): Promise<T> {
  checkCancelled(signal, operation);

  try {
    return await apiCall();
  } catch (error) {
    checkCancelled(signal, operation);

    // Already-typed errors pass through unchanged
    if (OperationCancelledError.isCancellation(error)) {
      throw new OperationCancelledError(operation);
    }
    if (error instanceof ApiError || error instanceof ConnectionError || error instanceof AuthenticationError) {
      throw error;
    }

    // komodo_client plain-object rejections
    const status = getKomodoStatus(error);
    if (status !== undefined) {
      const message = extractKomodoError(error);

      // Network failure (status === 1)
      if (status === 1) {
        throw ConnectionError.failed(operation, message);
      }
      // Authentication errors
      if (status === 401) {
        throw AuthenticationError.unauthorized();
      }
      if (status === 403) {
        throw AuthenticationError.forbidden();
      }
      // HTTP errors (4xx, 5xx)
      if (status >= 400) {
        throw ApiError.fromResponse(status, message);
      }
    }

    // Standard Error instances (e.g. from fetch or other Node.js APIs)
    if (error instanceof Error) {
      const code = getErrorCode(error);

      if (code && CONNECTION_ERROR_CODES.has(code)) {
        throw ConnectionError.failed(operation, `${code}: ${error.message}`);
      }
      if (code && TIMEOUT_ERROR_CODES.has(code)) {
        throw ConnectionError.timeout(operation);
      }
      if (error.message.includes("timeout") || error.name === "TimeoutError") {
        throw ConnectionError.timeout(operation);
      }

      throw ApiError.requestFailed(`${operation}: ${error.message}`);
    }

    throw ApiError.requestFailed(`${operation}: ${String(error)}`);
  }
}
