//! `AgentVersionNode` (whitepaper section 6): a proven, signed continuation
//! of an Agent's identity. Chain-level acceptance rules (parent linkage,
//! signer authorization, security monotonicity, capability consistency)
//! live in `chain.zig`; this file only knows how to hash, sign and verify
//! a single node in isolation.

const std = @import("std");
const hashmod = @import("hash.zig");
const identity = @import("identity.zig");
const capmod = @import("capability.zig");

const Digest = hashmod.Digest;
const CapabilityDiff = capmod.CapabilityDiff;

pub const VersionNode = struct {
    agent_did: []const u8,
    version_id: []const u8,
    /// Hash of the node this version derives from: the genesis node's
    /// `id()` for the first version, or the previous version's `id()`
    /// otherwise. This is what makes the chain a chain.
    parent_hash: Digest,

    code_hash: Digest,
    behavior_manifest_hash: Digest,
    semantic_diff_hash: Digest,
    capability_diff: CapabilityDiff,
    migration_proof_hash: Digest,
    test_receipt_hash: Digest,
    security_scan_receipt_hash: Digest,
    benchmark_receipt_hash: Digest,

    /// Non-decreasing across the chain (`previous_security_level <=
    /// new_security_level`), e.g. a coarse score derived from the security
    /// scan receipt.
    security_level: u32,

    /// If set, this version also rotates control to a new key. The
    /// rotation itself is authorized by `controller_signature`, which is
    /// still produced by the *previously* active key - proving that the
    /// same controller requested the rotation.
    rotated_public_key: ?identity.PublicKey,

    created_at: i64,
    /// Signature over `id()`, produced by the agent's currently active
    /// controller key (before any rotation this node performs).
    controller_signature: identity.Signature,

    pub fn deinit(self: *VersionNode, gpa: std.mem.Allocator) void {
        gpa.free(self.agent_did);
        gpa.free(self.version_id);
        self.capability_diff.deinit(gpa);
        self.* = undefined;
    }

    /// Content-addressed identifier of this node, and the message that
    /// `controller_signature` is computed over. Excludes the signature.
    pub fn id(self: VersionNode, gpa: std.mem.Allocator) !Digest {
        var c = hashmod.Canonical.init(gpa);
        defer c.deinit();
        try c.bytes(self.agent_did);
        try c.bytes(self.version_id);
        try c.digest(self.parent_hash);
        try c.digest(self.code_hash);
        try c.digest(self.behavior_manifest_hash);
        try c.digest(self.semantic_diff_hash);
        try c.digest(try self.capability_diff.hash(gpa));
        try c.digest(self.migration_proof_hash);
        try c.digest(self.test_receipt_hash);
        try c.digest(self.security_scan_receipt_hash);
        try c.digest(self.benchmark_receipt_hash);
        try c.u32v(self.security_level);
        if (self.rotated_public_key) |pk| try c.bytes(&pk.toBytes()) else try c.bytes("");
        try c.int(self.created_at);
        return c.finish();
    }

    pub const VerifyError = error{
        UnauthorizedSigner,
    } || identity.Signature.VerifyError || std.mem.Allocator.Error;

    /// Verifies only the signature over this node, against `signer`. Chain
    /// continuity (parent hash, monotonic security level, capability
    /// consistency) is `chain.zig`'s responsibility.
    pub fn verifySignature(self: VersionNode, gpa: std.mem.Allocator, signer: identity.PublicKey) VerifyError!void {
        const node_id = try self.id(gpa);
        self.controller_signature.verify(&node_id, signer) catch return error.UnauthorizedSigner;
    }
};

pub const Builder = struct {
    gpa: std.mem.Allocator,
    agent_did: []const u8,
    version_id: []const u8,
    parent_hash: Digest,
    code_hash: Digest = hashmod.zero,
    behavior_manifest_hash: Digest = hashmod.zero,
    semantic_diff_hash: Digest = hashmod.zero,
    capability_diff: CapabilityDiff = .{},
    migration_proof_hash: Digest = hashmod.zero,
    test_receipt_hash: Digest = hashmod.zero,
    security_scan_receipt_hash: Digest = hashmod.zero,
    benchmark_receipt_hash: Digest = hashmod.zero,
    security_level: u32 = 0,
    rotated_public_key: ?identity.PublicKey = null,
    created_at: i64,

    /// Builds and signs the version node with `signer`, the currently
    /// active controller key. Takes ownership of `self.capability_diff`.
    pub fn buildSigned(self: Builder, signer: identity.KeyPair) !VersionNode {
        var node = VersionNode{
            .agent_did = try self.gpa.dupe(u8, self.agent_did),
            .version_id = try self.gpa.dupe(u8, self.version_id),
            .parent_hash = self.parent_hash,
            .code_hash = self.code_hash,
            .behavior_manifest_hash = self.behavior_manifest_hash,
            .semantic_diff_hash = self.semantic_diff_hash,
            .capability_diff = self.capability_diff,
            .migration_proof_hash = self.migration_proof_hash,
            .test_receipt_hash = self.test_receipt_hash,
            .security_scan_receipt_hash = self.security_scan_receipt_hash,
            .benchmark_receipt_hash = self.benchmark_receipt_hash,
            .security_level = self.security_level,
            .rotated_public_key = self.rotated_public_key,
            .created_at = self.created_at,
            .controller_signature = undefined,
        };
        const node_id = try node.id(self.gpa);
        node.controller_signature = try signer.sign(&node_id, null);
        return node;
    }
};

test "version node verifies against the signer and detects tampering" {
    const gpa = std.testing.allocator;
    const kp = identity.generateKeyPair();

    var node = try (Builder{
        .gpa = gpa,
        .agent_did = "did:agentnet:agent:acme.sales.negotiator",
        .version_id = "v1",
        .parent_hash = hashmod.hash("genesis"),
        .security_level = 1,
        .created_at = 1_700_000_100,
    }).buildSigned(kp);
    defer node.deinit(gpa);

    try node.verifySignature(gpa, kp.public_key);

    var tampered = node;
    tampered.security_level += 1;
    try std.testing.expectError(error.UnauthorizedSigner, tampered.verifySignature(gpa, kp.public_key));
}
