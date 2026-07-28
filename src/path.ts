/**
 * Minimal POSIX path helpers.
 *
 * mountx paths are always absolute, POSIX-style and platform independent —
 * transports speak kernel paths, and a driver must never have to care what the
 * host platform's separator is. `..` is resolved lexically and clamped at the
 * root, so no normalized path can ever escape it.
 */

/** Split a path into its meaningful segments, resolving `.` and `..`. */
export function splitPath(path: string): string[] {
  const segments: string[] = [];
  for (const segment of path.split("/")) {
    if (segment === "" || segment === ".") {
      continue;
    }
    if (segment === "..") {
      segments.pop();
      continue;
    }
    segments.push(segment);
  }
  return segments;
}

/** Absolute, POSIX-style, no trailing slash, no `.` or `..` segments. */
export function normalizePath(path: string): string {
  const segments = splitPath(path);
  return segments.length === 0 ? "/" : `/${segments.join("/")}`;
}

/** Join and normalize. */
export function joinPath(...parts: string[]): string {
  return normalizePath(parts.join("/"));
}

/** The parent of a normalized path (`/` is its own parent). */
export function dirname(path: string): string {
  const segments = splitPath(path);
  segments.pop();
  return segments.length === 0 ? "/" : `/${segments.join("/")}`;
}

/** The last segment of a path (`/` for the root). */
export function basename(path: string): string {
  return splitPath(path).at(-1) ?? "/";
}

/** Is `path` `parent` itself or below it? Both must be normalized. */
export function isPathInside(path: string, parent: string): boolean {
  return path === parent || path.startsWith(parent === "/" ? "/" : `${parent}/`);
}
