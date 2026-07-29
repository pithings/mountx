import { defineBuildConfig } from "obuild/config";

export default defineBuildConfig({
  entries: [
    {
      type: "bundle",
      input: [
        "./src/index.ts",
        "./src/auto.ts",
        "./src/cli/index.ts",
        "./src/fuse/index.ts",
        "./src/nfs/index.ts",
        "./src/9p/index.ts",
        "./src/s3/index.ts",
        "./src/exec/index.ts",
        // Not a subpath export: `execUserns()` spawns it, so it has to survive
        // the build as its own file beside `dist/exec/index.mjs` rather than
        // being bundled into it.
        "./src/exec/userns-relay.ts",
        "./src/drivers/memory.ts",
        "./src/drivers/node-fs.ts",
        "./src/drivers/unstorage.ts",
      ],
    },
  ],
});
