//! The Proof-of-Evolution rule engine (whitepaper section 6): given a
//! `GenesisNode` and a sequence of `VersionNode`s, decides whether each new
//! version is a legitimate continuation of the agent's identity.
//!
//! A version is accepted only if, relative to the chain's current head:
//!   * it names the same agent and chains to the current head hash;
//!   * it is signed by the currently active controller key;
//!   * its security level does not regress;
//!   * every capability it revokes is currently active, and it does not
//!     re-grant a capability that is already active.
//! On acceptance the chain's active key (if the version rotates it) and
//! active capability set are updated, so identity survives key rotation and
//! capability changes exactly as section 2 of the whitepaper requires.

const std = @import("std");
const hashmod = @import("hash.zig");
const identity = @import("identity.zig");
const capmod = @import("capability.zig");
pub const genesis = @import("genesis.zig");
pub const version = @import("version.zig");

const Digest = hashmod.Digest;
const Capability = capmod.Capability;
const GenesisNode = genesis.GenesisNode;
const VersionNode = version.VersionNode;

pub const Chain = struct {
    gpa: std.mem.Allocator,
    genesis_node: GenesisNode,
    versions: std.ArrayList(VersionNode) = .empty,
    /// The controller key currently authorized to sign the next version.
    active_key: identity.PublicKey,
    /// The agent's currently active capability set.
    capabilities: std.ArrayList(Capability) = .empty,
    security_level: u32 = 0,
    /// `id()` of the most recently accepted node (genesis or version).
    head: Digest,

    /// Verifies `node` and adopts it as the chain, taking ownership.
    pub fn init(gpa: std.mem.Allocator, node: GenesisNode) !Chain {
        const signer = try node.signer(gpa);

        var capabilities: std.ArrayList(Capability) = .empty;
        errdefer {
            for (capabilities.items) |*c| c.deinit(gpa);
            capabilities.deinit(gpa);
        }
        for (node.initial_capabilities) |cap| {
            try capabilities.append(gpa, try cap.dupe(gpa));
        }

        return .{
            .gpa = gpa,
            .genesis_node = node,
            .active_key = signer,
            .capabilities = capabilities,
            .security_level = 0,
            .head = try node.id(gpa),
        };
    }

    pub fn deinit(self: *Chain) void {
        self.genesis_node.deinit(self.gpa);
        for (self.versions.items) |*v| v.deinit(self.gpa);
        self.versions.deinit(self.gpa);
        for (self.capabilities.items) |*c| c.deinit(self.gpa);
        self.capabilities.deinit(self.gpa);
        self.* = undefined;
    }

    pub const AppendError = error{
        AgentMismatch,
        ParentMismatch,
        UnauthorizedSigner,
        SecurityLevelRegression,
        RevokingUnknownCapability,
        DuplicateCapabilityGrant,
    } || std.mem.Allocator.Error || identity.Signature.VerifyError;

    /// Validates `node` against the current chain state and, if it is a
    /// legitimate continuation, appends it and updates chain state
    /// (active key, capabilities, security level, head). Takes ownership
    /// of `node` on success; the caller retains ownership on error.
    pub fn append(self: *Chain, node: VersionNode) AppendError!void {
        if (!std.mem.eql(u8, node.agent_did, self.genesis_node.agent_did)) return error.AgentMismatch;
        if (!hashmod.eql(node.parent_hash, self.head)) return error.ParentMismatch;
        node.verifySignature(self.gpa, self.active_key) catch return error.UnauthorizedSigner;
        if (node.security_level < self.security_level) return error.SecurityLevelRegression;

        // Dry-run the capability diff first so a rejected node never
        // partially mutates chain state.
        for (node.capability_diff.revoked) |rev| {
            if (indexOfCapability(self.capabilities.items, rev) == null) return error.RevokingUnknownCapability;
        }
        for (node.capability_diff.granted) |g| {
            if (indexOfCapability(self.capabilities.items, g) != null) return error.DuplicateCapabilityGrant;
        }

        for (node.capability_diff.revoked) |rev| {
            const idx = indexOfCapability(self.capabilities.items, rev).?;
            var removed = self.capabilities.swapRemove(idx);
            removed.deinit(self.gpa);
        }
        for (node.capability_diff.granted) |g| {
            try self.capabilities.append(self.gpa, try g.dupe(self.gpa));
        }

        if (node.rotated_public_key) |pk| self.active_key = pk;
        self.security_level = node.security_level;
        self.head = try node.id(self.gpa);
        try self.versions.append(self.gpa, node);
    }

    pub fn hasCapability(self: Chain, cap: Capability) bool {
        return indexOfCapability(self.capabilities.items, cap) != null;
    }

    /// Re-derives chain state from scratch by replaying genesis and every
    /// stored version through the same rules `append` enforces. Since
    /// `append` never lets an invalid node join the chain in the first
    /// place, this mainly serves as an independent auditor: anyone holding
    /// only the on-chain nodes (not this in-memory `Chain`) can call it to
    /// reach the same conclusion about the agent's current key,
    /// capabilities and security level.
    pub fn validate(gpa: std.mem.Allocator, genesis_node: GenesisNode, versions: []const VersionNode) !Chain {
        var replay = try Chain.init(gpa, try dupeGenesisView(gpa, genesis_node));
        errdefer replay.deinit();
        for (versions) |v| {
            try replay.append(try dupeVersionView(gpa, v));
        }
        return replay;
    }
};

fn indexOfCapability(caps: []const Capability, needle: Capability) ?usize {
    for (caps, 0..) |c, i| {
        if (c.eql(needle)) return i;
    }
    return null;
}

fn dupeGenesisView(gpa: std.mem.Allocator, node: GenesisNode) !GenesisNode {
    return .{
        .agent_did = try gpa.dupe(u8, node.agent_did),
        .creator_did = try gpa.dupe(u8, node.creator_did),
        .created_at = node.created_at,
        .initial_public_keys = try gpa.dupe(identity.PublicKey, node.initial_public_keys),
        .behavior_manifest_hash = node.behavior_manifest_hash,
        .runtime_manifest_hash = node.runtime_manifest_hash,
        .initial_capabilities = try dupeCaps(gpa, node.initial_capabilities),
        .governance_policy_hash = node.governance_policy_hash,
        .genesis_signature = node.genesis_signature,
    };
}

fn dupeVersionView(gpa: std.mem.Allocator, node: VersionNode) !VersionNode {
    return .{
        .agent_did = try gpa.dupe(u8, node.agent_did),
        .version_id = try gpa.dupe(u8, node.version_id),
        .parent_hash = node.parent_hash,
        .code_hash = node.code_hash,
        .behavior_manifest_hash = node.behavior_manifest_hash,
        .semantic_diff_hash = node.semantic_diff_hash,
        .capability_diff = .{
            .granted = try dupeCaps(gpa, node.capability_diff.granted),
            .revoked = try dupeCaps(gpa, node.capability_diff.revoked),
        },
        .migration_proof_hash = node.migration_proof_hash,
        .test_receipt_hash = node.test_receipt_hash,
        .security_scan_receipt_hash = node.security_scan_receipt_hash,
        .benchmark_receipt_hash = node.benchmark_receipt_hash,
        .security_level = node.security_level,
        .rotated_public_key = node.rotated_public_key,
        .created_at = node.created_at,
        .controller_signature = node.controller_signature,
    };
}

fn dupeCaps(gpa: std.mem.Allocator, caps: []const Capability) ![]Capability {
    const out = try gpa.alloc(Capability, caps.len);
    var filled: usize = 0;
    errdefer {
        for (out[0..filled]) |*c| c.deinit(gpa);
        gpa.free(out);
    }
    for (caps, 0..) |c, i| {
        out[i] = try c.dupe(gpa);
        filled = i + 1;
    }
    return out;
}

const testing = std.testing;

fn makeGenesis(gpa: std.mem.Allocator, kp: identity.KeyPair) !GenesisNode {
    var keys = [_]identity.PublicKey{kp.public_key};
    return (genesis.Builder{
        .gpa = gpa,
        .agent_did = "did:agentnet:agent:acme.sales.negotiator",
        .creator_did = "did:agentnet:business:acme",
        .created_at = 1_700_000_000,
        .initial_public_keys = &keys,
        .initial_capabilities = &.{.{ .resource = "orders", .action = "read" }},
    }).buildSigned(kp);
}

test "a valid evolution chain is accepted end to end" {
    const gpa = testing.allocator;
    const kp = identity.generateKeyPair();

    var chain = try Chain.init(gpa, try makeGenesis(gpa, kp));
    defer chain.deinit();

    const v1 = try (version.Builder{
        .gpa = gpa,
        .agent_did = chain.genesis_node.agent_did,
        .version_id = "v1",
        .parent_hash = chain.head,
        .security_level = 1,
        .capability_diff = .{
            .granted = try dupeCaps(gpa, &.{.{ .resource = "orders", .action = "negotiate_discount", .limit = "8%" }}),
        },
        .created_at = 1_700_000_100,
    }).buildSigned(kp);
    try chain.append(v1);

    try testing.expect(chain.hasCapability(.{ .resource = "orders", .action = "negotiate_discount", .limit = "8%" }));
    try testing.expectEqual(@as(u32, 1), chain.security_level);
    try testing.expectEqual(@as(usize, 1), chain.versions.items.len);
}

test "a version with the wrong parent hash is rejected" {
    const gpa = testing.allocator;
    const kp = identity.generateKeyPair();

    var chain = try Chain.init(gpa, try makeGenesis(gpa, kp));
    defer chain.deinit();

    var forged = try (version.Builder{
        .gpa = gpa,
        .agent_did = chain.genesis_node.agent_did,
        .version_id = "v1",
        .parent_hash = hashmod.hash("not-the-real-head"),
        .security_level = 1,
        .created_at = 1_700_000_100,
    }).buildSigned(kp);
    defer forged.deinit(gpa);

    try testing.expectError(error.ParentMismatch, chain.append(forged));
}

test "a version signed by a non-controller key is rejected" {
    const gpa = testing.allocator;
    const kp = identity.generateKeyPair();
    const outsider = identity.generateKeyPair();

    var chain = try Chain.init(gpa, try makeGenesis(gpa, kp));
    defer chain.deinit();

    var forged = try (version.Builder{
        .gpa = gpa,
        .agent_did = chain.genesis_node.agent_did,
        .version_id = "v1",
        .parent_hash = chain.head,
        .security_level = 1,
        .created_at = 1_700_000_100,
    }).buildSigned(outsider);
    defer forged.deinit(gpa);

    try testing.expectError(error.UnauthorizedSigner, chain.append(forged));
}

test "a version that lowers the security level is rejected" {
    const gpa = testing.allocator;
    const kp = identity.generateKeyPair();

    var chain = try Chain.init(gpa, try makeGenesis(gpa, kp));
    defer chain.deinit();
    chain.security_level = 5;

    var regressive = try (version.Builder{
        .gpa = gpa,
        .agent_did = chain.genesis_node.agent_did,
        .version_id = "v1",
        .parent_hash = chain.head,
        .security_level = 4,
        .created_at = 1_700_000_100,
    }).buildSigned(kp);
    defer regressive.deinit(gpa);

    try testing.expectError(error.SecurityLevelRegression, chain.append(regressive));
}

test "revoking a capability the agent does not have is rejected" {
    const gpa = testing.allocator;
    const kp = identity.generateKeyPair();

    var chain = try Chain.init(gpa, try makeGenesis(gpa, kp));
    defer chain.deinit();

    var invalid = try (version.Builder{
        .gpa = gpa,
        .agent_did = chain.genesis_node.agent_did,
        .version_id = "v1",
        .parent_hash = chain.head,
        .security_level = 1,
        .capability_diff = .{
            .revoked = try dupeCaps(gpa, &.{.{ .resource = "orders", .action = "issue_charge" }}),
        },
        .created_at = 1_700_000_100,
    }).buildSigned(kp);
    defer invalid.deinit(gpa);

    try testing.expectError(error.RevokingUnknownCapability, chain.append(invalid));
}

test "key rotation transfers control and old key can no longer sign" {
    const gpa = testing.allocator;
    const kp = identity.generateKeyPair();
    const kp2 = identity.generateKeyPair();

    var chain = try Chain.init(gpa, try makeGenesis(gpa, kp));
    defer chain.deinit();

    const rotate = try (version.Builder{
        .gpa = gpa,
        .agent_did = chain.genesis_node.agent_did,
        .version_id = "v1",
        .parent_hash = chain.head,
        .security_level = 1,
        .rotated_public_key = kp2.public_key,
        .created_at = 1_700_000_100,
    }).buildSigned(kp);
    try chain.append(rotate);
    try testing.expect(identity.publicKeyEql(chain.active_key, kp2.public_key));

    var by_old_key = try (version.Builder{
        .gpa = gpa,
        .agent_did = chain.genesis_node.agent_did,
        .version_id = "v2",
        .parent_hash = chain.head,
        .security_level = 1,
        .created_at = 1_700_000_200,
    }).buildSigned(kp);
    defer by_old_key.deinit(gpa);
    try testing.expectError(error.UnauthorizedSigner, chain.append(by_old_key));

    const by_new_key = try (version.Builder{
        .gpa = gpa,
        .agent_did = chain.genesis_node.agent_did,
        .version_id = "v2",
        .parent_hash = chain.head,
        .security_level = 1,
        .created_at = 1_700_000_200,
    }).buildSigned(kp2);
    try chain.append(by_new_key);
    try testing.expectEqual(@as(usize, 2), chain.versions.items.len);
}

test "validate independently replays a chain from raw nodes" {
    const gpa = testing.allocator;
    const kp = identity.generateKeyPair();

    var chain = try Chain.init(gpa, try makeGenesis(gpa, kp));
    defer chain.deinit();

    const v1 = try (version.Builder{
        .gpa = gpa,
        .agent_did = chain.genesis_node.agent_did,
        .version_id = "v1",
        .parent_hash = chain.head,
        .security_level = 1,
        .created_at = 1_700_000_100,
    }).buildSigned(kp);
    try chain.append(v1);

    var replay = try Chain.validate(gpa, chain.genesis_node, chain.versions.items);
    defer replay.deinit();

    try testing.expectEqual(chain.security_level, replay.security_level);
    try testing.expect(hashmod.eql(chain.head, replay.head));
    try testing.expect(identity.publicKeyEql(chain.active_key, replay.active_key));
}
