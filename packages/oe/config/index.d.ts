/** A retention period that the OpenE2EE Signal Protocol Relay accepts. */
export type Retention =
  "1h" | "6h" | "12h" | "1d" | "3d" | "7d" | "14d" | "30d";

/** The products that a project config can name. */
export type Product = "signal-relay";

/**
 * How long the Relay keeps undelivered messages and attachments, and whether
 * it sends Relay delivery receipts.
 */
export interface SignalProtocolRelayPolicy {
  deliveryRetention: Retention;
  attachmentRetention: Retention;
  /**
   * Turns Relay delivery receipts on or off. A Relay delivery receipt means
   * that the recipient device stored and acknowledged the message. It never
   * proves decryption. Each stored Relay delivery receipt uses one delivery
   * unit for each sender device. The default is `true`.
   */
  signalRelayReceipts?: boolean;
  /** The deprecated name of `signalRelayReceipts`, in a `relay` section only. */
  relayReceipts?: never;
}

/**
 * One environment section. A field that the section leaves out takes the
 * value of the shared `signalRelay` policy. Sandbox accepts at most 7d.
 */
export interface Environment {
  signalRelay?: Partial<SignalProtocolRelayPolicy>;
  /** The deprecated name of `signalRelay`. A section uses one name only. */
  relay?: never;
  /** A complete public desired identity. Absence leaves identity unmanaged. */
  identity?: Identity;
}

/** The default export of `open-e2ee.config.ts`. */
export interface SignalProtocolRelayConfig {
  product: Product;
  /** The project slug: lowercase letters, digits, and single hyphens. */
  project: string;
  /** The Relay policy that each environment shares. */
  signalRelay: SignalProtocolRelayPolicy;
  /** The deprecated name of `signalRelay`. A file uses one name only. */
  relay?: never;
  /**
   * The environments that `oe` syncs. Add `production: {}` to put
   * Production in the sync.
   */
  environments: {
    sandbox: Environment;
    production?: Environment;
  };
}

/**
 * The shared policy of a file that uses the deprecated `relay` key.
 *
 * @deprecated Use `SignalProtocolRelayPolicy` and rename `relayReceipts` to
 * `signalRelayReceipts`. oe v7.0.0 stops reading `relayReceipts`.
 */
export interface RelayPolicy {
  deliveryRetention: Retention;
  attachmentRetention: Retention;
  /** Turns Relay delivery receipts on or off. The default is `true`. */
  relayReceipts?: boolean;
  signalRelayReceipts?: never;
}

/**
 * An environment section of a file that uses the deprecated `relay` key.
 *
 * @deprecated Use `Environment` and rename `relay` to `signalRelay`. oe
 * v7.0.0 stops reading `relay`.
 */
export interface RelayEnvironment {
  relay?: Partial<RelayPolicy>;
  signalRelay?: never;
  /** A complete public desired identity. Absence leaves identity unmanaged. */
  identity?: Identity;
}

/**
 * The default export of a file that uses the deprecated `relay` key.
 *
 * @deprecated Use `SignalProtocolRelayConfig`: rename `relay` to
 * `signalRelay` and `relayReceipts` to `signalRelayReceipts` in every
 * section. oe v7.0.0 stops reading `relay`.
 */
export interface RelayConfig {
  product: Product;
  project: string;
  relay: RelayPolicy;
  signalRelay?: never;
  environments: {
    sandbox: RelayEnvironment;
    production?: RelayEnvironment;
  };
}

/**
 * The default export of `open-e2ee.config.ts`, with the `signalRelay` key or
 * the deprecated `relay` key.
 */
export type Config = SignalProtocolRelayConfig | RelayConfig;

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
