import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const tsc = path.join(root, "node_modules/typescript/bin/tsc");

function config(deliveryRetention) {
  return `import { defineConfig } from "@open-e2ee/oe/config";

export default defineConfig({
  product: "signal-relay",
  project: "typed-chat",
  relay: { deliveryRetention: "${deliveryRetention}", attachmentRetention: "7d" },
  environments: { sandbox: {} },
});
`;
}

// installPackedCLI packs packages/oe and extracts the tarball into
// directory/node_modules, as npm install puts it.
async function installPackedCLI(directory) {
  const packed = spawnSync(
    "npm",
    ["pack", "--silent", "--pack-destination", directory],
    { cwd: path.join(root, "packages/oe"), encoding: "utf8" },
  );
  assert.equal(packed.status, 0, packed.stderr);
  const target = path.join(directory, "node_modules/@open-e2ee/oe");
  await mkdir(target, { recursive: true });
  const extracted = spawnSync(
    "tar",
    [
      "-xzf",
      path.join(directory, packed.stdout.trim()),
      "-C",
      target,
      "--strip-components=1",
    ],
    { encoding: "utf8" },
  );
  assert.equal(extracted.status, 0, extracted.stderr);
}

test("the ./config export resolves from a packed tarball", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "oe-config-export-"));
  try {
    await installPackedCLI(directory);
    await writeFile(path.join(directory, "open-e2ee.config.ts"), config("7d"));
    const resolved = spawnSync(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        `const { defineConfig } = await import("@open-e2ee/oe/config");
const { default: value } = await import("./open-e2ee.config.ts");
process.stdout.write(JSON.stringify({ defineConfig: typeof defineConfig, value }));`,
      ],
      { cwd: directory, encoding: "utf8" },
    );
    assert.equal(resolved.status, 0, resolved.stderr);
    const { defineConfig, value } = JSON.parse(resolved.stdout);
    assert.equal(defineConfig, "function");
    assert.equal(value.relay.deliveryRetention, "7d");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a wrong enumerated value fails tsc --noEmit", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "oe-config-types-"));
  try {
    await installPackedCLI(directory);
    await writeFile(
      path.join(directory, "tsconfig.json"),
      JSON.stringify({
        compilerOptions: { module: "nodenext", strict: true },
        files: ["open-e2ee.config.ts"],
      }),
    );
    const check = () =>
      spawnSync(process.execPath, [tsc, "--noEmit", "-p", directory], {
        encoding: "utf8",
      });

    await writeFile(path.join(directory, "open-e2ee.config.ts"), config("7d"));
    const valid = check();
    assert.equal(valid.status, 0, valid.stdout + valid.stderr);

    await writeFile(path.join(directory, "open-e2ee.config.ts"), config("2d"));
    const wrong = check();
    assert.notEqual(wrong.status, 0, "tsc accepted deliveryRetention 2d");
    assert.match(
      wrong.stdout,
      /open-e2ee\.config\.ts\(6,\d+\): error TS2322: Type '"2d"' is not assignable to type 'Retention'/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

const identityKey = {
  kty: "EC",
  crv: "P-256",
  x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  y: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  kid: "key-one",
  alg: "ES256",
  use: "sig",
  key_ops: ["verify"],
  ext: true,
};

const supportedIdentities = [
  { mode: "device-owned" },
  {
    mode: "custom-token",
    algorithms: ["ES256"],
    issuer: "https://members.example",
    audience: "members",
    subjectClaim: "sub",
    keys: [identityKey],
  },
  {
    mode: "provider-bound",
    provider: "clerk",
    algorithms: ["RS256"],
    issuer: "https://members.clerk.accounts.dev",
    subjectClaim: "sub",
    authorizedParties: ["https://chat.example"],
    allowMissingAuthorizedParty: false,
  },
  {
    mode: "provider-bound",
    provider: "firebase",
    algorithms: ["RS256"],
    issuer: "https://securetoken.google.com/my-project",
    audience: "my-project",
    subjectClaim: "sub",
  },
  {
    mode: "provider-bound",
    algorithms: ["ES256"],
    issuer: "https://members.example",
    audience: "members",
    subjectClaim: "sub",
    keys: [identityKey],
  },
];

function identityConfig(identity) {
  return `import { defineConfig } from "@open-e2ee/oe/config";
export default defineConfig({
  product: "signal-relay",
  project: "typed-chat",
  relay: { deliveryRetention: "7d", attachmentRetention: "7d" },
  environments: { sandbox: { identity: ${JSON.stringify(identity)} } },
});
`;
}

test("packed public identity types qualify every supported variant before invalid cases", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "oe-identity-types-"));
  try {
    await installPackedCLI(directory);
    await writeFile(
      path.join(directory, "tsconfig.json"),
      JSON.stringify({
        compilerOptions: { module: "nodenext", strict: true },
        files: ["open-e2ee.config.ts"],
      }),
    );
    const check = () =>
      spawnSync(process.execPath, [tsc, "--noEmit", "-p", directory], {
        encoding: "utf8",
      });
    for (const identity of supportedIdentities) {
      await writeFile(
        path.join(directory, "open-e2ee.config.ts"),
        identityConfig(identity),
      );
      const result = check();
      assert.equal(result.status, 0, result.stdout + result.stderr);
    }
    const invalid = [
      null,
      { mode: "device-owned", issuer: "https://members.example" },
      { ...supportedIdentities[1], provider: "clerk" },
      {
        ...supportedIdentities[1],
        keys: [{ ...identityKey, d: "PRIVATE_KEY_SENTINEL" }],
      },
      { ...supportedIdentities[1], keys: [{ ...identityKey, ext: false }] },
      {
        ...supportedIdentities[1],
        keys: [{ ...identityKey, key_ops: ["sign"] }],
      },
      { ...supportedIdentities[2], keys: [identityKey] },
      { ...supportedIdentities[2], allowMissingAuthorizedParty: true },
      {
        ...supportedIdentities[3],
        authorizedParties: ["https://chat.example"],
      },
      { ...supportedIdentities[3], algorithms: ["ES256"] },
      {
        ...supportedIdentities[4],
        authorizedParties: ["https://chat.example"],
      },
      { ...supportedIdentities[4], allowMissingAuthorizedParty: false },
    ];
    for (const [index, identity] of invalid.entries()) {
      await writeFile(
        path.join(directory, "open-e2ee.config.ts"),
        identityConfig(identity),
      );
      const result = check();
      assert.notEqual(
        result.status,
        0,
        `packed types accepted an unsupported identity shape (case ${index})`,
      );
      assert.match(result.stdout, /error TS\d+:/);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("packed public identity config uses only the public config export", async () => {
  const directory = await mkdtemp(
    path.join(os.tmpdir(), "oe-identity-export-"),
  );
  try {
    await installPackedCLI(directory);
    for (const identity of supportedIdentities) {
      await writeFile(
        path.join(directory, "open-e2ee.config.ts"),
        identityConfig(identity),
      );
      const result = spawnSync(
        process.execPath,
        [
          "--input-type=module",
          "--eval",
          'const {default:value}=await import("./open-e2ee.config.ts"); process.stdout.write(JSON.stringify(value));',
        ],
        { cwd: directory, encoding: "utf8" },
      );
      assert.equal(result.status, 0, result.stderr);
      assert.deepEqual(
        JSON.parse(result.stdout).environments.sandbox.identity,
        identity,
      );
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
