export * from "./errors.ts";
export * from "./harness.ts";
export * from "./lock.ts";
export * from "./path.ts";
export * from "./types.ts";

// `mount` deliberately stays on `mountx/fuse` rather than being re-exported
// here. Re-exporting it pulls the protocol layer, the session and
// `node:child_process` into every `import … from "mountx"` — ~90 kB — for a
// name that has to change shape anyway.
//
// There are three transports now — `mountx/fuse`, `mountx/9p` and `mountx/nfs`
// — and the chooser this comment used to predict exists too: it is
// `mountx/auto`, not the root export, for the same reason — `src/auto.ts`
// reaches every transport through `await import()`, so a caller pays for the
// one it mounts with and nothing else. Importing it from here would undo that.
