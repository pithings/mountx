export * from "./errors.ts";
export * from "./harness.ts";
export * from "./lock.ts";
export * from "./path.ts";
export * from "./types.ts";

// `mount` deliberately stays on `unimount/fuse` rather than being re-exported
// here. Re-exporting it pulls the protocol layer, the session and
// `node:child_process` into every `import … from "unimount"` — ~90 kB — for a
// name that has to change shape anyway: once there is a second transport, the
// root `mount` should be the one that chooses between them, and inventing that
// facade before NFS exists would be guessing at its requirements.
