import { createHash } from "node:crypto";
import { chmod, cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";

const version = process.argv[2];
const output = path.resolve(process.argv[3] ?? "dist");
if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version ?? "")) {
  throw new Error("usage: node scripts/build-release.mjs <version> [output]");
}

const root = path.resolve(import.meta.dirname, "..");
const targets = [
  ["darwin", "arm64"],
  ["darwin", "amd64"],
  ["linux", "arm64"],
  ["linux", "amd64"],
  ["windows", "arm64"],
  ["windows", "amd64"],
];

await rm(output, { recursive: true, force: true });
await mkdir(path.join(output, "artifacts"), { recursive: true });
await mkdir(path.join(output, "npm"), { recursive: true });

const checksums = [];
for (const [goos, goarch] of targets) {
  const npmArch = goarch === "amd64" ? "x64" : goarch;
  const npmOS = goos === "windows" ? "win32" : goos;
  const packageName = `oe-${npmOS}-${npmArch}`;
  const executable = goos === "windows" ? "oe.exe" : "oe";
  const binaryDirectory = path.join(output, "npm", packageName, "bin");
  await cp(
    path.join(root, "packages", packageName),
    path.join(output, "npm", packageName),
    { recursive: true },
  );
  await rm(path.join(binaryDirectory, "README.md"), { force: true });
  const binary = path.join(binaryDirectory, executable);
  const build = spawnSync(
    "go",
    [
      "build",
      "-trimpath",
      "-ldflags",
      `-s -w -X main.version=${version}`,
      "-o",
      binary,
      "./cmd/oe",
    ],
    {
      cwd: root,
      env: { ...process.env, CGO_ENABLED: "0", GOOS: goos, GOARCH: goarch },
      stdio: "inherit",
    },
  );
  if (build.status !== 0) process.exit(build.status ?? 1);
  if (goos !== "windows") await chmod(binary, 0o755);
  await setPackageVersion(
    path.join(output, "npm", packageName, "package.json"),
    version,
  );

  const archive = `oe_${version}_${goos}_${goarch}.tar.gz`;
  const archived = spawnSync(
    "tar",
    [
      "-czf",
      path.join(output, "artifacts", archive),
      "-C",
      binaryDirectory,
      executable,
    ],
    {
      stdio: "inherit",
    },
  );
  if (archived.status !== 0) process.exit(archived.status ?? 1);
  const bytes = await readFile(path.join(output, "artifacts", archive));
  checksums.push(
    `${createHash("sha256").update(bytes).digest("hex")}  ${archive}`,
  );
}

// The release serves the config schema at the $id in schema/config-v2.json.
const schema = await readFile(path.join(root, "schema/config-v2.json"));
await writeFile(path.join(output, "artifacts", "config-v2.json"), schema);
checksums.push(
  `${createHash("sha256").update(schema).digest("hex")}  config-v2.json`,
);

await cp(path.join(root, "packages", "oe"), path.join(output, "npm", "oe"), {
  recursive: true,
});
await setPackageVersion(
  path.join(output, "npm", "oe", "package.json"),
  version,
  true,
);

await writeFile(
  path.join(output, "artifacts", "checksums.txt"),
  checksums.sort().join("\n") + "\n",
);

async function setPackageVersion(
  packagePath,
  nextVersion,
  rewriteDependencies = false,
) {
  const value = JSON.parse(await readFile(packagePath, "utf8"));
  value.version = nextVersion;
  if (rewriteDependencies) {
    for (const key of ["dependencies", "optionalDependencies"]) {
      for (const name of Object.keys(value[key] ?? {})) {
        if (name === "@open-e2ee/oe" || name.startsWith("@open-e2ee/oe-"))
          value[key][name] = nextVersion;
      }
    }
  }
  await writeFile(packagePath, JSON.stringify(value, null, 2) + "\n");
}
