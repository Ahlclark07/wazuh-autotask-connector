export function getPath(source, dottedPath, fallback = undefined) {
  if (!source || !dottedPath) return fallback;

  let current = source;
  for (const part of dottedPath.split(".")) {
    if (
      current === null ||
      current === undefined ||
      typeof current !== "object" ||
      !(part in current)
    ) {
      return fallback;
    }
    current = current[part];
  }

  return current ?? fallback;
}
