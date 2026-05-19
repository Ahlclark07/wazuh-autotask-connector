export function severityFromRuleLevel(level) {
  const numeric = Number.parseInt(level, 10);
  if (!Number.isFinite(numeric)) return "info";
  if (numeric >= 13) return "critical";
  if (numeric >= 10) return "high";
  if (numeric >= 7) return "medium";
  if (numeric >= 3) return "low";
  return "info";
}
