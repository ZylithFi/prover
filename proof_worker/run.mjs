#!/usr/bin/env node
// runs the disposable worker bundle only from immutable image digests.

import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

for (const name of ["ZYLITH_PROOF_WORKER_IMAGE", "ZYLITH_STWO_IMAGE"]) {
  const value = process.env[name]?.trim() ?? "";
  if (!/@sha256:[0-9a-f]{64}$/i.test(value)) {
    throw new Error(`${name} must be an immutable sha256 image reference`);
  }
}

const compose = join(dirname(fileURLToPath(import.meta.url)), "compose.yml");
const result = spawnSync(
  "docker",
  ["compose", "-f", compose, "up", "--abort-on-container-exit", "--remove-orphans"],
  { stdio: "inherit", env: process.env },
);
if (result.error) throw result.error;
process.exit(result.status ?? 1);
