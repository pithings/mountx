/**
 * Minimal POSIX path helpers.
 *
 * mountx paths are always absolute, POSIX-style and platform independent —
 * transports speak kernel paths, and a driver must never have to care what the
 * host platform's separator is. `..` is resolved lexically and clamped at the
 * root, so no normalized path can ever escape it.
 */

const SLASH = 0x2f; // "/"
const DOT = 0x2e; // "."

/**
 * Is `path` already in the exact form {@link normalizePath} would produce?
 *
 * Absolute, no empty segment (so no `//` and no trailing `/`), no `.` and no
 * `..`. Equivalent to `normalizePath(path) === path` and the same answer, but
 * in one allocation-free pass rather than a split and a rejoin — which is the
 * point: a path arriving from a session has already been through `joinPath`,
 * so a driver normalizing it again is the common case, not the exception.
 *
 * ```ts
 * isNormalizedPath("/a/b"); // true
 * isNormalizedPath("/a//b"); // false
 * isNormalizedPath("a/b"); // false — not absolute
 * ```
 */
export function isNormalizedPath(path: string): boolean {
  const { length } = path;
  if (length === 0 || path.charCodeAt(0) !== SLASH) {
    return false;
  }
  if (length === 1) {
    return true; // "/"
  }
  let start = 1;
  for (let index = 1; index <= length; index++) {
    if (index !== length && path.charCodeAt(index) !== SLASH) {
      continue;
    }
    const size = index - start;
    if (size === 0) {
      return false; // "//" or a trailing "/"
    }
    if (
      path.charCodeAt(start) === DOT &&
      (size === 1 || (size === 2 && path.charCodeAt(start + 1) === DOT))
    ) {
      return false; // "." or ".."
    }
    start = index + 1;
  }
  return true;
}

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

/**
 * Absolute, POSIX-style, no trailing slash, no `.` or `..` segments.
 *
 * Already normalized is the common case — a session hands the driver a path it
 * built with `joinPath`, and the driver normalizes it again — so
 * {@link isNormalizedPath} is asked first and the split and rejoin skipped.
 * That is an optimization and nothing more: the result is the same string
 * value either way, and reference identity is not a contract (JavaScript gives
 * no way to observe it on a primitive string anyway). A caller asking "is this
 * already normal?" should call {@link isNormalizedPath} rather than compare.
 */
export function normalizePath(path: string): string {
  if (isNormalizedPath(path)) {
    return path;
  }
  const segments = splitPath(path);
  return segments.length === 0 ? "/" : `/${segments.join("/")}`;
}

/** A path in canonical form together with the segments it is made of. */
export interface ResolvedPath {
  /** The path as {@link normalizePath} would return it. */
  readonly path: string;
  /**
   * The same path as {@link splitPath} would return it. A fresh array the
   * caller owns and may mutate; `[]` for the root.
   */
  readonly segments: string[];
}

/**
 * Normalize and split in one go, for the callers that want both.
 *
 * `normalizePath(p)` followed by `splitPath(p)` walks the string twice and
 * throws the first array away; every driver that resolves a path component by
 * component needs exactly this pair.
 */
export function resolvePath(path: string): ResolvedPath {
  if (isNormalizedPath(path)) {
    return { path, segments: path === "/" ? [] : path.slice(1).split("/") };
  }
  const segments = splitPath(path);
  return { path: segments.length === 0 ? "/" : `/${segments.join("/")}`, segments };
}

/** Join and normalize. */
export function joinPath(...parts: string[]): string {
  return normalizePath(parts.join("/"));
}

/** The parent of a normalized path (`/` is its own parent). */
export function dirname(path: string): string {
  if (isNormalizedPath(path)) {
    const cut = path.lastIndexOf("/");
    return cut <= 0 ? "/" : path.slice(0, cut);
  }
  const segments = splitPath(path);
  segments.pop();
  return segments.length === 0 ? "/" : `/${segments.join("/")}`;
}

/** The last segment of a path (`/` for the root). */
export function basename(path: string): string {
  if (isNormalizedPath(path)) {
    return path.length === 1 ? "/" : path.slice(path.lastIndexOf("/") + 1);
  }
  return splitPath(path).at(-1) ?? "/";
}

/** Is `path` `parent` itself or below it? Both must be normalized. */
export function isPathInside(path: string, parent: string): boolean {
  return path === parent || path.startsWith(parent === "/" ? "/" : `${parent}/`);
}
