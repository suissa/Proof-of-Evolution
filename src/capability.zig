//! Capabilities: fine-grained, scoped, expirable units of authorization
//! (whitepaper section 5), and the diffs that versions use to grant/revoke
//! them (whitepaper section 6).

const std = @import("std");
const hashmod = @import("hash.zig");

/// A single scoped authorization, e.g.
///   resource="orders", action="negotiate_discount", limit="8%"
pub const Capability = struct {
    resource: []const u8,
    action: []const u8,
    /// Free-form bound on the action, e.g. "R$500" or "8%". Empty if unbounded.
    limit: []const u8 = "",
    /// Unix seconds after which the capability is no longer valid. `null`
    /// means it does not expire on its own (it can still be revoked).
    expires_at: ?i64 = null,

    pub fn dupe(self: Capability, gpa: std.mem.Allocator) !Capability {
        return .{
            .resource = try gpa.dupe(u8, self.resource),
            .action = try gpa.dupe(u8, self.action),
            .limit = try gpa.dupe(u8, self.limit),
            .expires_at = self.expires_at,
        };
    }

    pub fn deinit(self: *Capability, gpa: std.mem.Allocator) void {
        gpa.free(self.resource);
        gpa.free(self.action);
        gpa.free(self.limit);
        self.* = undefined;
    }

    pub fn eql(a: Capability, b: Capability) bool {
        return std.mem.eql(u8, a.resource, b.resource) and
            std.mem.eql(u8, a.action, b.action) and
            std.mem.eql(u8, a.limit, b.limit) and
            a.expires_at == b.expires_at;
    }

    pub fn isExpired(self: Capability, now: i64) bool {
        return if (self.expires_at) |exp| now >= exp else false;
    }

    pub fn hashInto(self: Capability, c: *hashmod.Canonical) !void {
        try c.bytes(self.resource);
        try c.bytes(self.action);
        try c.bytes(self.limit);
        try c.int(self.expires_at orelse -1);
    }
};

/// What a version proposes to change about the agent's active capability
/// set. Both slices are owned by the diff.
pub const CapabilityDiff = struct {
    granted: []Capability = &.{},
    revoked: []Capability = &.{},

    pub fn deinit(self: *CapabilityDiff, gpa: std.mem.Allocator) void {
        for (self.granted) |*cap| cap.deinit(gpa);
        for (self.revoked) |*cap| cap.deinit(gpa);
        gpa.free(self.granted);
        gpa.free(self.revoked);
        self.* = undefined;
    }

    pub fn hash(self: CapabilityDiff, gpa: std.mem.Allocator) !hashmod.Digest {
        var c = hashmod.Canonical.init(gpa);
        defer c.deinit();
        for (self.granted) |cap| try cap.hashInto(&c);
        for (self.revoked) |cap| try cap.hashInto(&c);
        return c.finish();
    }
};

fn ownedOne(gpa: std.mem.Allocator, cap: Capability) ![]Capability {
    const out = try gpa.alloc(Capability, 1);
    out[0] = try cap.dupe(gpa);
    return out;
}

test "capability diff hash is stable and content sensitive" {
    const gpa = std.testing.allocator;

    var diff_a = CapabilityDiff{
        .granted = try ownedOne(gpa, .{ .resource = "orders", .action = "read" }),
    };
    defer diff_a.deinit(gpa);

    var diff_b = CapabilityDiff{
        .granted = try ownedOne(gpa, .{ .resource = "orders", .action = "write" }),
    };
    defer diff_b.deinit(gpa);

    const ha = try diff_a.hash(gpa);
    const hb = try diff_b.hash(gpa);
    try std.testing.expect(!hashmod.eql(ha, hb));
}

test "capability expiry" {
    const cap = Capability{ .resource = "orders", .action = "reserve", .expires_at = 1000 };
    try std.testing.expect(!cap.isExpired(999));
    try std.testing.expect(cap.isExpired(1000));
    try std.testing.expect(cap.isExpired(1001));

    const unbounded = Capability{ .resource = "orders", .action = "reserve" };
    try std.testing.expect(!unbounded.isExpired(1_000_000));
}
