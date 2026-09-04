//! Merkle roots and `AgentActivityCommitmentNode` (whitepaper sections 7-8):
//! the way an Agent anchors batches of off-chain EventStore activity
//! on-chain without publishing the events themselves.

const std = @import("std");
const hashmod = @import("hash.zig");
const identity = @import("identity.zig");

const Digest = hashmod.Digest;

/// Computes a binary Merkle root over `leaves` (already-hashed event
/// digests). An odd node at any level is promoted by duplicating it, the
/// common convention used by e.g. Bitcoin's Merkle trees. Returns
/// `hash.zero` for an empty input.
pub fn root(gpa: std.mem.Allocator, leaves: []const Digest) !Digest {
    if (leaves.len == 0) return hashmod.zero;

    var level = try gpa.dupe(Digest, leaves);
    defer gpa.free(level);

    while (level.len > 1) {
        const next_len = (level.len + 1) / 2;
        var next = try gpa.alloc(Digest, next_len);
        var i: usize = 0;
        var j: usize = 0;
        while (i < level.len) : (i += 2) {
            const left = level[i];
            const right = if (i + 1 < level.len) level[i + 1] else level[i];
            next[j] = hashmod.hash2(left, right);
            j += 1;
        }
        gpa.free(level);
        level = next;
    }
    return level[0];
}

pub const ActivityCommitment = struct {
    agent_did: []const u8,
    version_id: []const u8,
    batch_start: i64,
    batch_end: i64,
    merkle_root: Digest,
    previous_activity_root: Digest,
    timestamp: i64,
    signature: identity.Signature,

    pub fn deinit(self: *ActivityCommitment, gpa: std.mem.Allocator) void {
        gpa.free(self.agent_did);
        gpa.free(self.version_id);
        self.* = undefined;
    }

    pub fn id(self: ActivityCommitment, gpa: std.mem.Allocator) !Digest {
        var c = hashmod.Canonical.init(gpa);
        defer c.deinit();
        try c.bytes(self.agent_did);
        try c.bytes(self.version_id);
        try c.int(self.batch_start);
        try c.int(self.batch_end);
        try c.digest(self.merkle_root);
        try c.digest(self.previous_activity_root);
        try c.int(self.timestamp);
        return c.finish();
    }

    pub const VerifyError = error{UnauthorizedSigner} || identity.Signature.VerifyError || std.mem.Allocator.Error;

    pub fn verify(self: ActivityCommitment, gpa: std.mem.Allocator, signer: identity.PublicKey) VerifyError!void {
        const commitment_id = try self.id(gpa);
        self.signature.verify(&commitment_id, signer) catch return error.UnauthorizedSigner;
    }
};

pub fn buildSignedCommitment(
    gpa: std.mem.Allocator,
    agent_did: []const u8,
    version_id: []const u8,
    batch_start: i64,
    batch_end: i64,
    event_hashes: []const Digest,
    previous_activity_root: Digest,
    timestamp: i64,
    signer: identity.KeyPair,
) !ActivityCommitment {
    var commitment = ActivityCommitment{
        .agent_did = try gpa.dupe(u8, agent_did),
        .version_id = try gpa.dupe(u8, version_id),
        .batch_start = batch_start,
        .batch_end = batch_end,
        .merkle_root = try root(gpa, event_hashes),
        .previous_activity_root = previous_activity_root,
        .timestamp = timestamp,
        .signature = undefined,
    };
    const commitment_id = try commitment.id(gpa);
    commitment.signature = try signer.sign(&commitment_id, null);
    return commitment;
}

test "merkle root is order sensitive and stable" {
    const gpa = std.testing.allocator;
    const a = hashmod.hash("event-a");
    const b = hashmod.hash("event-b");
    const c = hashmod.hash("event-c");

    const r1 = try root(gpa, &.{ a, b, c });
    const r2 = try root(gpa, &.{ a, b, c });
    const r3 = try root(gpa, &.{ a, c, b });

    try std.testing.expect(hashmod.eql(r1, r2));
    try std.testing.expect(!hashmod.eql(r1, r3));
}

test "merkle root of a single leaf is the leaf" {
    const gpa = std.testing.allocator;
    const a = hashmod.hash("only-event");
    const r = try root(gpa, &.{a});
    try std.testing.expect(hashmod.eql(r, a));
}

test "activity commitment verifies against its signer" {
    const gpa = std.testing.allocator;
    const kp = identity.generateKeyPair();
    const events = [_]Digest{ hashmod.hash("e1"), hashmod.hash("e2") };

    var commitment = try buildSignedCommitment(
        gpa,
        "did:agentnet:agent:acme.sales.negotiator",
        "v1",
        1_700_000_000,
        1_700_000_100,
        &events,
        hashmod.zero,
        1_700_000_100,
        kp,
    );
    defer commitment.deinit(gpa);

    try commitment.verify(gpa, kp.public_key);
}
