//! Proof-of-Evolution: a verifiable-lineage identity chain for Agents.
//!
//! This library implements the core mechanism described in the project's
//! whitepaper (README.md, section 6): an Agent is born with a signed
//! `GenesisNode`, and every later `VersionNode` must prove it is a
//! legitimate, signed, security-non-regressing continuation of the
//! previous node. `Chain` is the rule engine that accepts or rejects each
//! proposed version. `merkle` provides the Merkle-root activity
//! commitments used to anchor off-chain EventStore batches on-chain.

pub const hash = @import("hash.zig");
pub const identity = @import("identity.zig");
pub const capability = @import("capability.zig");
pub const genesis = @import("genesis.zig");
pub const version = @import("version.zig");
pub const chain = @import("chain.zig");
pub const merkle = @import("merkle.zig");

pub const Digest = hash.Digest;
pub const Did = identity.Did;
pub const KeyPair = identity.KeyPair;
pub const PublicKey = identity.PublicKey;
pub const Capability = capability.Capability;
pub const CapabilityDiff = capability.CapabilityDiff;
pub const GenesisNode = genesis.GenesisNode;
pub const VersionNode = version.VersionNode;
pub const Chain = chain.Chain;
pub const ActivityCommitment = merkle.ActivityCommitment;

test {
    @import("std").testing.refAllDecls(@This());
}
