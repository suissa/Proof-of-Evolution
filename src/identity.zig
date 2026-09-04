//! Agent identity primitives: DIDs and the Ed25519 keys that back the
//! `genesis_signature` / `controller_signature` fields of the chain.
//!
//! A DID here is kept intentionally simple (an owned string such as
//! `did:agentnet:agent:acme.sales.negotiator`); resolving it to a DID
//! Document is outside the scope of this implementation, which focuses on
//! the Proof-of-Evolution lineage described in the whitepaper.

const std = @import("std");

pub const Ed25519 = std.crypto.sign.Ed25519;
pub const PublicKey = Ed25519.PublicKey;
pub const Signature = Ed25519.Signature;
pub const KeyPair = Ed25519.KeyPair;

/// A decentralized identifier, owned as a plain string.
pub const Did = struct {
    value: []const u8,

    pub fn init(gpa: std.mem.Allocator, value: []const u8) !Did {
        return .{ .value = try gpa.dupe(u8, value) };
    }

    pub fn deinit(self: *Did, gpa: std.mem.Allocator) void {
        gpa.free(self.value);
        self.* = undefined;
    }

    pub fn eql(a: Did, b: Did) bool {
        return std.mem.eql(u8, a.value, b.value);
    }
};

/// Returns a process-wide `std.Io` implementation suitable for the
/// randomness needs of key generation. A single-threaded implementation is
/// enough for this CLI/library; callers that already have an `Io` should
/// use theirs instead.
pub fn defaultIo() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

pub fn generateKeyPair() KeyPair {
    return KeyPair.generate(defaultIo());
}

pub fn publicKeyEql(a: PublicKey, b: PublicKey) bool {
    return std.mem.eql(u8, &a.toBytes(), &b.toBytes());
}

test "keypair can sign and verify" {
    const kp = generateKeyPair();
    const msg = "proof-of-evolution";
    const sig = try kp.sign(msg, null);
    try sig.verify(msg, kp.public_key);
}

test "signature does not verify under a different key" {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    const msg = "proof-of-evolution";
    const sig = try kp1.sign(msg, null);
    try std.testing.expectError(error.SignatureVerificationFailed, sig.verify(msg, kp2.public_key));
}
