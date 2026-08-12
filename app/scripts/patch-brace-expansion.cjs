"use strict";

const fs = require("node:fs");
const path = require("node:path");

const packagePath = require.resolve("brace-expansion/package.json");
const commonJsPath = path.join(
  path.dirname(packagePath),
  "dist",
  "commonjs",
  "index.js",
);
const marker = "// AgentSec CommonJS compatibility shim";
const source = fs.readFileSync(commonJsPath, "utf8");

if (!source.includes(marker)) {
  fs.appendFileSync(
    commonJsPath,
    `

${marker}
// brace-expansion v5 uses named exports, while legacy minimatch versions call
// require("brace-expansion") directly. Preserve both interfaces without
// replacing the patched v5 expansion implementation or its resource limits.
const agentsecExpand = module.exports.expand;
const agentsecExpansionMax = module.exports.EXPANSION_MAX;
const agentsecExpansionMaxLength = module.exports.EXPANSION_MAX_LENGTH;
module.exports = agentsecExpand;
module.exports.default = agentsecExpand;
module.exports.expand = agentsecExpand;
module.exports.EXPANSION_MAX = agentsecExpansionMax;
module.exports.EXPANSION_MAX_LENGTH = agentsecExpansionMaxLength;
`,
    "utf8",
  );
}
