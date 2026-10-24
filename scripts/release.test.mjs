import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { access, mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("stages six native optional packages without a postinstall downloader", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "oe-release-"));
  try {
    const result = spawnSync(
      process.execPath,
      ["scripts/build-release.mjs", "0.1.0-test.1", directory],
      {
        cwd: path.resolve(import.meta.dirname, ".."),
        encoding: "utf8",
      },
    );
    assert.equal(result.status, 0, result.stderr || result.stdout);
    const cli = JSON.parse(
      await readFile(path.join(directory, "npm/oe/package.json"), "utf8"),
    );
    assert.equal(cli.version, "0.1.0-test.1");
    assert.equal(cli.scripts?.postinstall, undefined);
    assert.equal(Object.keys(cli.optionalDependencies).length, 6);
    for (const target of [
      "oe-darwin-arm64/bin/oe",
      "oe-darwin-x64/bin/oe",
      "oe-linux-arm64/bin/oe",
      "oe-linux-x64/bin/oe",
      "oe-win32-arm64/bin/oe.exe",
      "oe-win32-x64/bin/oe.exe",
    ]) {
      await access(path.join(directory, "npm", target));
    }
    const checksums = await readFile(
      path.join(directory, "artifacts/checksums.txt"),
      "utf8",
    );
    assert.equal(checksums.trim().split("\n").length, 7);
    const schema = JSON.parse(
      await readFile(path.join(directory, "artifacts/config-v2.json"), "utf8"),
    );
    assert.equal(
      schema.$id,
      "https://github.com/open-e2ee/oe/releases/latest/download/config-v2.json",
    );

    const platformPackage = `oe-${process.platform}-${process.arch}`;
    const tarballs = [];
    for (const packageName of [platformPackage, "oe"]) {
      const packageDirectory = path.join(directory, "npm", packageName);
      const packed = spawnSync("npm", ["pack", "--silent"], {
        cwd: packageDirectory,
        encoding: "utf8",
      });
      assert.equal(packed.status, 0, packed.stderr);
      tarballs.push(path.join(packageDirectory, packed.stdout.trim()));
    }
    const notice = await readFile(
      path.join(import.meta.dirname, "../licenses/purego-v0.11.1.txt"),
    );
    assert.equal(notice.length, 13211);
    assert.equal(
      createHash("sha256").update(notice).digest("hex"),
      "293dc5471fc6bf3e3002e6115e3b9fbea1c2817b7878ab8d8e3dffedbd7bfd04",
    );
    for (const [goos, goarch, npmName] of [
      ["darwin", "arm64", "oe-darwin-arm64"],
      ["darwin", "amd64", "oe-darwin-x64"],
      ["linux", "arm64", "oe-linux-arm64"],
      ["linux", "amd64", "oe-linux-x64"],
      ["windows", "arm64", "oe-win32-arm64"],
      ["windows", "amd64", "oe-win32-x64"],
    ]) {
      const archive = path.join(
        directory,
        "artifacts",
        `oe_0.1.0-test.1_${goos}_${goarch}.tar.gz`,
      );
      const listed = spawnSync("tar", ["-tzf", archive], {
        encoding: "utf8",
        timeout: 30000,
        maxBuffer: 1024 * 1024,
      });
      assert.equal(listed.status, 0, listed.stderr);
      const executable = goos === "windows" ? "oe.exe" : "oe";
      assert.deepEqual(
        listed.stdout.trim().split("\n").sort(),
        (goos === "darwin"
          ? [executable, "THIRD_PARTY_NOTICES.txt"]
          : [executable]
        ).sort(),
      );
      if (goos !== "darwin") continue;
      const archivedNotice = spawnSync(
        "tar",
        ["-xOzf", archive, "THIRD_PARTY_NOTICES.txt"],
        { timeout: 30000, maxBuffer: 1024 * 1024 },
      );
      assert.equal(archivedNotice.status, 0, archivedNotice.stderr?.toString());
      assert.deepEqual(archivedNotice.stdout, notice);
      const packageDirectory = path.join(directory, "npm", npmName);
      const packed = spawnSync(
        "npm",
        ["pack", "--silent", "--ignore-scripts"],
        {
          cwd: packageDirectory,
          encoding: "utf8",
          timeout: 30000,
        },
      );
      assert.equal(packed.status, 0, packed.stderr);
      const packedNotice = spawnSync(
        "tar",
        [
          "-xOzf",
          path.join(packageDirectory, packed.stdout.trim()),
          "package/bin/THIRD_PARTY_NOTICES.txt",
        ],
        { timeout: 30000, maxBuffer: 1024 * 1024 },
      );
      assert.equal(packedNotice.status, 0, packedNotice.stderr?.toString());
      assert.deepEqual(packedNotice.stdout, notice);
    }
    const install = path.join(directory, "install");
    const installed = spawnSync(
      "npm",
      ["install", "--prefix", install, "--silent", ...tarballs],
      { encoding: "utf8" },
    );
    assert.equal(installed.status, 0, installed.stderr);
    const version = spawnSync(
      process.execPath,
      [
        path.join(install, "node_modules/@open-e2ee/oe/bin/oe.js"),
        "--json",
        "version",
      ],
      { encoding: "utf8" },
    );
    assert.equal(version.status, 0, version.stderr);
    assert.equal(JSON.parse(version.stdout).data.version, "0.1.0-test.1");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("npm shim executes an explicitly selected native binary", async () => {
  const root = path.resolve(import.meta.dirname, "..");
  const binary = path.join(
    root,
    "bin",
    process.platform === "win32" ? "oe.exe" : "oe",
  );
  await mkdir(path.dirname(binary), { recursive: true });
  const built = spawnSync("go", ["build", "-o", binary, "./cmd/oe"], {
    cwd: root,
    encoding: "utf8",
  });
  assert.equal(built.status, 0, built.stderr);
  const result = spawnSync(
    process.execPath,
    ["packages/oe/bin/oe.js", "--json", "version"],
    {
      cwd: root,
      env: { ...process.env, OE_BINARY_PATH: binary },
      encoding: "utf8",
    },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /"command":"version"/);
});
