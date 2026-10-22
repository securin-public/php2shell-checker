// Checker Worker base URL. Overwritten at deploy time by the Pages workflow from the
// CHECKER_API_URL repository variable; local development talks to `wrangler dev`.
export const API_BASE = ["localhost", "127.0.0.1"].includes(location.hostname) ? "http://localhost:8787" : "";
