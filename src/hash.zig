//! SHA-256 hashing helpers used throughout the Proof-of-Evolution chain.
//! Every node in the chain (genesis, version, activity commitment) is
//! addressed by the digest of its canonical byte encoding.

const std = @import("std");

pub const Digest = [32]u8;
pub const zero: Digest = @splat(0);

pub fn hash(data: []const u8) Digest {
    var out: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &out, .{});
    return out;
}

/// Domain-separated hash of two digests, used to build Merkle trees.
pub fn hash2(a: Digest, b: Digest) Digest {
    var buf: [64]u8 = undefined;
    @memcpy(buf[0..32], &a);
    @memcpy(buf[32..64], &b);
    return hash(&buf);
}

pub fn hex(d: Digest) [64]u8 {
    return std.fmt.bytesToHex(d, .lower);
}

pub fn eql(a: Digest, b: Digest) bool {
    return std.mem.eql(u8, &a, &b);
}

/// Small incremental builder for canonical, unambiguous byte encodings.
/// Every field is length-prefixed (u64 little-endian) before its bytes are
/// appended, so that e.g. ("ab","c") and ("a","bc") never collide.
pub const Canonical = struct {
    buf: std.ArrayList(u8) = .empty,
    gpa: std.mem.Allocator,

    pub fn init(gpa: std.mem.Allocator) Canonical {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Canonical) void {
        self.buf.deinit(self.gpa);
    }

    pub fn bytes(self: *Canonical, b: []const u8) !void {
        var len_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &len_buf, b.len, .little);
        try self.buf.appendSlice(self.gpa, &len_buf);
        try self.buf.appendSlice(self.gpa, b);
    }

    pub fn digest(self: *Canonical, d: Digest) !void {
        try self.buf.appendSlice(self.gpa, &d);
    }

    pub fn int(self: *Canonical, v: i64) !void {
        var b: [8]u8 = undefined;
        std.mem.writeInt(i64, &b, v, .little);
        try self.buf.appendSlice(self.gpa, &b);
    }

    pub fn u32v(self: *Canonical, v: u32) !void {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, v, .little);
        try self.buf.appendSlice(self.gpa, &b);
    }

    pub fn finish(self: *Canonical) Digest {
        return hash(self.buf.items);
    }
};

test "hash is deterministic and content-addressed" {
    const a = hash("hello");
    const b = hash("hello");
    const c = hash("hellO");
    try std.testing.expect(eql(a, b));
    try std.testing.expect(!eql(a, c));
}

test "canonical encoding avoids field-boundary collisions" {
    const gpa = std.testing.allocator;

    var c1 = Canonical.init(gpa);
    defer c1.deinit();
    try c1.bytes("ab");
    try c1.bytes("c");
    const d1 = c1.finish();

    var c2 = Canonical.init(gpa);
    defer c2.deinit();
    try c2.bytes("a");
    try c2.bytes("bc");
    const d2 = c2.finish();

    try std.testing.expect(!eql(d1, d2));
}
