// Verdict buckets used for anonymous usage counts.
export const VERDICTS = ["vulnerable", "patched", "unknown", "out-of-range", "unreachable", "rejected"];

// Collapse detailed assessment statuses into the buckets shown on the stats page.
export function bucketFor(status) {
  if (status === "vulnerable" || status === "patched" || status === "out-of-range") return status;
  return "unknown"; // no-header, no-php-header, unrecognised
}
