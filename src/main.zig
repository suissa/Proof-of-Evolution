//! Demo CLI for the Proof-of-Evolution library: walks a fictional Agent
//! ("acme.sales.negotiator") through genesis, two legitimate evolutions
//! (a capability grant and a key rotation), a rejected regressive version,
//! and an on-chain activity commitment - then independently re-validates
//! the resulting chain from its raw nodes, exactly as a third-party
//! auditor holding only on-chain data would.

const std = @import("std");
const Io = std.Io;
const poe = @import("poe");

pub fn main(init: std.process.Init) !void {
    const gpa: std.mem.Allocator = init.arena.allocator();
    const io = init.io;

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const w = &stdout_file_writer.interface;
    defer w.flush() catch {};

    try w.print("=== Proof-of-Evolution demo ===\n\n", .{});

    // --- Genesis: the agent is born, controlled by `founder_key`. ---
    const founder_key = poe.identity.generateKeyPair();

    var keys = [_]poe.PublicKey{founder_key.public_key};
    const genesis_node = try (poe.genesis.Builder{
        .gpa = gpa,
        .agent_did = "did:agentnet:agent:acme.sales.negotiator",
        .creator_did = "did:agentnet:business:acme",
        .created_at = 1_700_000_000,
        .initial_public_keys = &keys,
        .initial_capabilities = &.{.{ .resource = "inventory", .action = "check" }},
    }).buildSigned(founder_key);

    var chain = try poe.Chain.init(gpa, genesis_node);
    try w.print("genesis: {s}\n  controller key: {s}\n  id: {s}\n\n", .{
        chain.genesis_node.agent_did,
        poe.hash.hex(founder_key.public_key.toBytes()),
        poe.hash.hex(chain.head),
    });

    // --- v1: grant a scoped negotiation capability. ---
    const negotiate = poe.Capability{ .resource = "orders", .action = "negotiate_discount", .limit = "8%" };
    const v1 = try (poe.version.Builder{
        .gpa = gpa,
        .agent_did = chain.genesis_node.agent_did,
        .version_id = "v1",
        .parent_hash = chain.head,
        .security_level = 1,
        .capability_diff = .{ .granted = try gpa.dupe(poe.Capability, &.{try negotiate.dupe(gpa)}) },
        .created_at = 1_700_000_100,
    }).buildSigned(founder_key);
    try chain.append(v1);
    try w.print("v1: granted capability {s}/{s} (limit {s})\n  security_level={d}  head={s}\n\n", .{
        negotiate.resource, negotiate.action, negotiate.limit, chain.security_level, poe.hash.hex(chain.head),
    });

    // --- v2: rotate to a new operational key; still the same identity. ---
    const rotated_key = poe.identity.generateKeyPair();
    const v2 = try (poe.version.Builder{
        .gpa = gpa,
        .agent_did = chain.genesis_node.agent_did,
        .version_id = "v2",
        .parent_hash = chain.head,
        .security_level = 2,
        .rotated_public_key = rotated_key.public_key,
        .created_at = 1_700_000_200,
    }).buildSigned(founder_key);
    try chain.append(v2);
    try w.print("v2: rotated controller key -> {s}\n  security_level={d}  head={s}\n\n", .{
        poe.hash.hex(rotated_key.public_key.toBytes()), chain.security_level, poe.hash.hex(chain.head),
    });

    // --- v3 (rejected): security downgrade, and signed with the retired key. ---
    var forged = try (poe.version.Builder{
        .gpa = gpa,
        .agent_did = chain.genesis_node.agent_did,
        .version_id = "v3-forged",
        .parent_hash = chain.head,
        .security_level = 1, // regresses from 2
        .created_at = 1_700_000_300,
    }).buildSigned(founder_key); // wrong signer: key was rotated away in v2
    defer forged.deinit(gpa);

    if (chain.append(forged)) |_| {
        try w.print("v3-forged: unexpectedly accepted!\n\n", .{});
    } else |err| {
        try w.print("v3-forged: rejected as expected -> {s}\n\n", .{@errorName(err)});
    }

    // --- Anchor a batch of off-chain EventStore activity on-chain. ---
    const events = [_]poe.Digest{
        poe.hash.hash("negotiation.opened order=1042"),
        poe.hash.hash("negotiation.offer order=1042 discount=6%"),
        poe.hash.hash("negotiation.accepted order=1042 discount=6%"),
    };
    var commitment = try poe.merkle.buildSignedCommitment(
        gpa,
        chain.genesis_node.agent_did,
        "v2",
        1_700_000_200,
        1_700_000_260,
        &events,
        poe.hash.zero,
        1_700_000_260,
        rotated_key,
    );
    try commitment.verify(gpa, chain.active_key);
    try w.print("activity commitment: {d} events -> merkle_root {s}\n\n", .{ events.len, poe.hash.hex(commitment.merkle_root) });

    // --- Independent audit: replay the chain from its raw nodes alone. ---
    var audited = try poe.Chain.validate(gpa, chain.genesis_node, chain.versions.items);
    try w.print(
        "audit: replayed {d} version(s) from raw nodes -> security_level={d}, active_key matches original: {}\n",
        .{
            audited.versions.items.len,
            audited.security_level,
            poe.identity.publicKeyEql(audited.active_key, chain.active_key),
        },
    );
    audited.deinit();
}
