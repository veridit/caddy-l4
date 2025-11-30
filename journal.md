# Refactoring Plan: TLS Handling in `caddy-l4`

This document outlines the phased plan to refactor TLS handling in `caddy-l4` for better consistency, a more intuitive Caddyfile syntax, and robust functionality in all Caddy server contexts.

## High-Level Goals

1.  **Centralize Logic:** All TLS-related matching logic (SNI, ALPN, etc.) should reside within the `l4tls` module. Other matchers like `postgres` should not have their own TLS-specific logic.
2.  **Improve Caddyfile Ergonomics:** The Caddyfile syntax for `layer4` servers should be as intuitive as the `https` server, with a clear top-level `tls` block for termination and support for shorthands like `tls internal`.
3.  **Ensure Correctness:** All TLS-related functionality must work correctly in both a standalone `layer4` server and when used within a `listener_wrapper` on an `https` server.

---

## Phase 1: Consolidate TLS Matching Logic (Complete)

**Goal:** Make the `l4tls` matcher the single source of truth for TLS-related matching.

| Task                                                                       | Status      |
| -------------------------------------------------------------------------- | ----------- |
| Remove SNI logic from `postgres` matcher                                   | ✅ Complete |
| Centralize TLS ClientHello parsing into `l4tls`                            | ✅ Complete |
| Make `l4tls` matcher "context-aware" (handle raw and pre-terminated TLS)   | ✅ Complete |
| Add comprehensive tests for `l4tls` matcher's context-aware logic          | ✅ Complete |
| Fix `l4tls` matcher Caddyfile parsing to support nested matchers like `sni` | ✅ Complete |

**Files Involved in this Phase:**
- `modules/l4postgres/matcher.go`
- `modules/l4postgres/matcher_test.go`
- `modules/l4tls/matcher.go`
- `modules/l4tls/matcher_test.go`
- `modules/l4tls/clienthello.go`
- `modules/l4tls/parsehello.go`

---

## Phase 2: Improve Server-Level TLS Configuration (Complete)

**Goal:** Simplify TLS termination by introducing a powerful, top-level `tls` block for `layer4` servers.

| Task                                                                                                | Status      |
| --------------------------------------------------------------------------------------------------- | ----------- |
| Implement top-level `tls` handler in `layer4.Server` struct                                         | ✅ Complete |
| Update Caddyfile parser to recognize the top-level `tls` block                                      | ✅ Complete |
| Enhance `l4tls` handler parser for simpler `connection_policy` config                               | ✅ Complete |
| Implement Caddyfile shorthands like `tls internal` to auto-configure the main `tls` app      | ✅ Complete |
| Move `l4tls` handler and helpers into core `layer4` package to break import cycle                   | ✅ Complete |

### Next Step: Implementing `tls` App Integration

To make shorthands like `tls internal` work, the `layer4` Caddyfile parser must be able to generate the correct JSON configuration for Caddy's main `tls` app. This is the most complex part of the refactoring.

**Required Files for this Step:**
- `layer4/caddyfile.go`: This is where the global `layer4` block is parsed. We will need to modify `parseLayer4` to inspect the `tls` block for shorthands.
- `../caddy/modules/caddytls/tls.go`: This file is essential reference for understanding the structure of the `tls` app's configuration (`AutomationPolicy`, etc.), which we need to generate.

**Key Decisions & Implementation Plan:**

1.  **Parsing Strategy:** We will modify the `UnmarshalCaddyfile` function for the `l4tls.Handler`. When it encounters a shorthand argument like `internal`, instead of parsing a block, it will store this information.
2.  **Configuration Generation:** Back in `layer4/caddyfile.go`, after parsing a server block, we will inspect the parsed `l4tls.Handler`. If a shorthand was used, we will generate the corresponding `automation` policy JSON.
3.  **Global App Configuration:** The generated `tls` app configuration will be merged into the main Caddy JSON structure. The `parseLayer4` function already receives the `existingVal`, which we can use to access and modify the configuration of other apps.

---

## Phase 3: Finalize and Document (Complete)

**Goal:** Update all documentation to reflect the new, improved configuration patterns.

| Task                                          | Status      |
| --------------------------------------------- | ----------- |
| Update `README.md` with new Caddyfile examples| ✅ Complete |
| Update this journal with a final summary      | ✅ Complete |

### Summary of Changes

The refactoring is now complete. We have successfully:

1.  **Centralized TLS Logic:** The `l4tls` matcher is now the sole module responsible for matching on TLS ClientHello properties. The `postgres` matcher no longer has duplicate TLS logic.
2.  **Improved Caddyfile Syntax:** `layer4` servers now support a top-level `tls` block for terminating TLS, including shorthands like `tls example.com` and `tls internal` which correctly configure Caddy's main `tls` app.
3.  **Resolved Import Cycle:** The `l4tls` handler was moved into the core `layer4` package, breaking the circular dependency that prevented the project from building.

The codebase is now more maintainable and provides a more intuitive user experience.

---

## Phase 4: Debugging and Final Polish

**Goal:** Investigate and resolve issues discovered during end-to-end testing with Postgres.

### Findings from `todo.md` Analysis

1.  **Caddyfile Parsing Bug (Resolved):** A bug was identified where the top-level `tls` directive in a `layer4` server block was overly restrictive. It failed to parse valid configurations like a simple `tls` or a combination of shorthands and a block (e.g., `tls internal { ... }`). This has been fixed by adjusting the Caddyfile parser for the `tls` handler.
2.  **Configuration Logic Flaw:** The test configuration for the `layer4` server on port 5432 is logically incorrect. It attempts to match a raw TLS handshake against both the `tls` and `postgres` matchers simultaneously. A raw TLS stream is not a valid Postgres startup message, so this route can never be matched. The correct approach is to first terminate TLS, then match against the decrypted stream using a `subroute`.
3.  **Inefficient Matching (Resolved):** The `postgres` matcher was re-parsing the TLS ClientHello, even if the `tls` matcher had already done so. This has been resolved by having the `tls` matcher store the parsed `ClientHelloInfo` in the connection context for other matchers to use.

### Next Steps

1.  **Provide Corrected Config Example:** Document the correct Caddyfile pattern for multiplexing TLS and non-TLS protocols, which involves terminating TLS with the top-level `tls` handler, and then using a `subroute` to match on the decrypted stream.
2.  **Final Review:** Conduct a final review of the test suite and documentation to ensure all recent changes are covered.
