/** A retention period that the managed Relay accepts. */
export type Retention =
  "1h" | "6h" | "12h" | "1d" | "3d" | "7d" | "14d" | "30d";

/** The products that a project config can name. */
export type Product = "signal-relay";

/**
 * How long the Relay keeps undelivered messages and attachments, and whether
 * it sends Relay delivery receipts.
 */
export interface RelayPolicy {
  deliveryRetention: Retention;
  attachmentRetention: Retention;
  /**
   * Turns Relay delivery receipts on or off. A Relay delivery receipt means
   * that the recipient device stored and acknowledged the message. It never
   * proves decryption. Each stored Relay delivery receipt uses one delivery
   * unit for each sender device. The default is `true`.
   */
  relayReceipts?: boolean;
}

/**
 * One environment section. A field that the section leaves out takes the
 * value of the shared `relay` policy. Sandbox accepts at most 7d.
 */
export interface Environment {
  relay?: Partial<RelayPolicy>;
  /** A complete public desired identity. Absence leaves identity unmanaged. */
  identity?: Identity;
}

/** The default export of `open-e2ee.config.ts`. */
export interface Config {
  product: Product;
  /** The project slug: lowercase letters, digits, and single hyphens. */
  project: string;
  /** The Relay policy that each environment shares. */
  relay: RelayPolicy;
  /**
   * The environments that `oe` syncs. Add `production: {}` to put
   * Production in the sync.
   */
  environments: {
    sandbox: Environment;
    production?: Environment;
  };
}

/** Returns the project config unchanged, with its types checked. */
export declare function defineConfig(config: Config): Config;

/** A public ES256 verification key. Private key members are not supported. */
export interface IdentityPublicKey {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
  kid: string;
  alg?: "ES256";
  use?: "sig";
  key_ops?: ["verify"];
  ext?: true;
}

/** A configured public ES256 policy. */
export interface ConfiguredIdentity {
  mode: "custom-token" | "provider-bound";
  provider?: never;
  authorizedParties?: never;
  allowMissingAuthorizedParty?: never;
  algorithms: ["ES256"];
  issuer: string;
  audience: string;
  subjectClaim: string;
  keys: IdentityPublicKey[];
}

/** The native Clerk policy uses the maintained fixed provider key source. */
export type ClerkIdentity = {
  mode: "provider-bound";
  provider: "clerk";
  algorithms: ["RS256"];
  issuer: string;
  subjectClaim: "sub";
  authorizedParties: string[];
  keys?: never;
} & (
  | { audience?: string; allowMissingAuthorizedParty?: false }
  | { audience: string; allowMissingAuthorizedParty: true }
);

/** The native Firebase policy uses the maintained fixed provider key source. */
export interface FirebaseIdentity {
  mode: "provider-bound";
  provider: "firebase";
  algorithms: ["RS256"];
  issuer: string;
  audience: string;
  subjectClaim: "sub";
  keys?: never;
  authorizedParties?: never;
  allowMissingAuthorizedParty?: never;
}

/** A complete desired policy for one environment. */
export type Identity =
  | { mode: "device-owned" }
  | ConfiguredIdentity
  | ClerkIdentity
  | FirebaseIdentity;
