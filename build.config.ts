import { defineBuildConfig } from "obuild/config";

export default defineBuildConfig({
  entries: [
    {
      type: "bundle",
      input: [
        "./src/index.ts",
        "./src/auto.ts",
        "./src/fuse/index.ts",
        "./src/nfs/index.ts",
        "./src/drivers/memory.ts",
        "./src/drivers/node-fs.ts",
      ],
    },
  ],
});
