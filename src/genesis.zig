//! `AgentGenesisNode` (whitepaper section 6): the birth record of an Agent.
//! Every subsequent `AgentVersionNode` must chain back to this node.

const std = @import("std");
const hashmod = @import("hash.zig");
const identity = @import("identity.zig");
const capmod = @import("capability.zig");

const Digest = hashmod.Digest;
const Capability = capmod.Capability;

pub const GenesisNode = struct {
    agent_did: []const u8,
    creator_did: []const u8,
    created_at: i64,
    /// Keys authorized to control the agent from birth. Any one of them may
    /// sign the genesis node and the first version node.
    initial_public_keys: []identity.PublicKey,
    behavior_manifest_hash: Digest,
    runtime_manifest_hash: Digest,
    initial_capabilities: []Capability,
    governance_policy_hash: Digest,
    /// Signature over `id()`, produced by one of `initial_public_keys`.
    genesis_signature: identity.Signature,

    pub fn deinit(self: *GenesisNode, gpa: std.mem.Allocator) void {
        gpa.free(self.agent_did);
        gpa.free(self.creator_did);
        gpa.free(self.initial_public_keys);
        for (self.initial_capabilities) |*cap| cap.deinit(gpa);
        gpa.free(self.initial_capabilities);
        self.* = undefined;
    }

    /// Content-addressed identifier of this node: the hash every version
    /// node ultimately chains back to. Excludes the signature itself, since
    /// the signature is computed *over* this id.
    pub fn id(self: GenesisNode, gpa: std.mem.Allocator) !Digest {
        var c = hashmod.Canonical.init(gpa);
        defer c.deinit();
        try c.bytes(self.agent_did);
        try c.bytes(self.creator_did);
        try c.int(self.created_at);
        for (self.initial_public_keys) |pk| try c.bytes(&pk.toBytes());
        try c.digest(self.behavior_manifest_hash);
        try c.digest(self.runtime_manifest_hash);
        for (self.initial_capabilities) |cap| try cap.hashInto(&c);
        try c.digest(self.governance_policy_hash);
        return c.finish();
    }

    /// True if `key` is one of the keys authorized to control this agent at
    /// genesis time.
    pub fn hasKey(self: GenesisNode, key: identity.PublicKey) bool {
        for (self.initial_public_keys) |pk| {
            if (identity.publicKeyEql(pk, key)) return true;
        }
        return false;
    }

    pub const VerifyError = error{
        UnauthorizedSigner,
    } || identity.Signature.VerifyError || std.mem.Allocator.Error;

    /// Verifies that `genesis_signature` was produced by one of
    /// `initial_public_keys` over this node's `id()`.
    pub fn verify(self: GenesisNode, gpa: std.mem.Allocator) VerifyError!void {
        _ = try self.signer(gpa);
    }

    /// Returns which of `initial_public_keys` actually produced
    /// `genesis_signature`. This becomes the chain's first active
    /// controller key.
    pub fn signer(self: GenesisNode, gpa: std.mem.Allocator) VerifyError!identity.PublicKey {
        const node_id = try self.id(gpa);
        for (self.initial_public_keys) |pk| {
            if (self.genesis_signature.verify(&node_id, pk)) |_| return pk else |_| {}
        }
        return error.UnauthorizedSigner;
    }
};

pub const Builder = struct {
    gpa: std.mem.Allocator,
    agent_did: []const u8,
    creator_did: []const u8,
    created_at: i64,
    initial_public_keys: []identity.PublicKey,
    behavior_manifest_hash: Digest = hashmod.zero,
    runtime_manifest_hash: Digest = hashmod.zero,
    initial_capabilities: []const Capability = &.{},
    governance_policy_hash: Digest = hashmod.zero,

    /// Builds and signs the genesis node with `signer`, which must be one of
    /// `initial_public_keys`.
    pub fn buildSigned(self: Builder, signer: identity.KeyPair) !GenesisNode {
        var node = GenesisNode{
            .agent_did = try self.gpa.dupe(u8, self.agent_did),
            .creator_did = try self.gpa.dupe(u8, self.creator_did),
            .created_at = self.created_at,
            .initial_public_keys = try self.gpa.dupe(identity.PublicKey, self.initial_public_keys),
            .behavior_manifest_hash = self.behavior_manifest_hash,
            .runtime_manifest_hash = self.runtime_manifest_hash,
            .initial_capabilities = try dupeCapabilities(self.gpa, self.initial_capabilities),
            .governance_policy_hash = self.governance_policy_hash,
            .genesis_signature = undefined,
        };
        const node_id = try node.id(self.gpa);
        node.genesis_signature = try signer.sign(&node_id, null);
        return node;
    }
};

fn dupeCapabilities(gpa: std.mem.Allocator, caps: []const Capability) ![]Capability {
    const out = try gpa.alloc(Capability, caps.len);
    var filled: usize = 0;
    errdefer {
        for (out[0..filled]) |*cap| cap.deinit(gpa);
        gpa.free(out);
    }
    for (caps, 0..) |cap, i| {
        out[i] = try cap.dupe(gpa);
        filled = i + 1;
    }
    return out;
}

test "genesis node verifies against its signer and rejects tampering" {
    const gpa = std.testing.allocator;
    const kp = identity.generateKeyPair();
    var keys = [_]identity.PublicKey{kp.public_key};

    var node = try (Builder{
        .gpa = gpa,
        .agent_did = "did:agentnet:agent:acme.sales.negotiator",
        .creator_did = "did:agentnet:business:acme",
        .created_at = 1_700_000_000,
        .initial_public_keys = &keys,
    }).buildSigned(kp);
    defer node.deinit(gpa);

    try node.verify(gpa);

    // Tamper with a field after the fact: verification must fail because
    // the id (and therefore the signed message) changes.
    var tampered = node;
    tampered.created_at += 1;
    try std.testing.expectError(error.UnauthorizedSigner, tampered.verify(gpa));
}

test "genesis node rejects a signature from a non-authorized key" {
    const gpa = std.testing.allocator;
    const kp = identity.generateKeyPair();
    const outsider = identity.generateKeyPair();
    var keys = [_]identity.PublicKey{kp.public_key};

    var node = try (Builder{
        .gpa = gpa,
        .agent_did = "did:agentnet:agent:acme.sales.negotiator",
        .creator_did = "did:agentnet:business:acme",
        .created_at = 1_700_000_000,
        .initial_public_keys = &keys,
    }).buildSigned(outsider);
    defer node.deinit(gpa);

    try std.testing.expectError(error.UnauthorizedSigner, node.verify(gpa));
}
