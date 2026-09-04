# Proof-of-Evolution
A Blockchain for Agent Identity, Evolution, and Authorization in the Business-to-Agent Internet

## Implementation

`src/` contains a Zig (0.16) implementation of the core mechanism described
below: an Ed25519-signed `GenesisNode`, `VersionNode`s that must chain back
to it, and a `Chain` rule engine (`src/chain.zig`) that accepts a new
version only if it is signed by the currently active controller key, its
security level does not regress, and its capability diff is consistent
with the agent's active capability set — while still allowing key rotation
and capability changes, since identity is the verifiable lineage, not any
single key (section 2/6). `src/merkle.zig` implements the Merkle-root
`AgentActivityCommitmentNode` used to anchor off-chain EventStore batches
(section 7/8).

Build and run the demo (creates a genesis node, evolves it through a
capability grant and a key rotation, shows a forged version being
rejected, and independently re-validates the resulting chain from its raw
nodes):

```sh
zig build test   # unit tests for every module
zig build run    # end-to-end demo
```

Networking, DID resolution, mTLS/DPoP, and post-quantum key exchange
(sections 3, 9–11) are existing standards the whitepaper composes with
Proof-of-Evolution rather than novel contributions of this project, and are
not implemented here.

## Abstract

The next phase of the internet will probably not be composed only of humans interacting with websites, applications, and APIs. A growing share of digital interactions is likely to be performed by autonomous Agents: systems capable of discovering services, negotiating, authenticating themselves, executing tasks, making decisions constrained by policies, and interacting directly with businesses. There are already strong signs of this transition: interoperability protocols between Agents, standards for connecting models to tools, the growth of automated traffic, and forecasts about the adoption of Agentic AI in enterprise software. However, there is still no universal layer of identity, authorization, evolution, auditability, and revocation designed specifically for Agents.

This article proposes the concept of an authentication and identity blockchain for Agents based on Proof-of-Evolution. The proposal is not to use blockchain as an operational database, nor to record every request on a global network. The blockchain would act as a public trust layer: identity, versions, public keys, capabilities, revocations, relationships between Agents, evolution proofs, and cryptographic audit anchors. The real execution, payloads, routes, snapshots, and internal events would remain off-chain, in local or distributed EventStores.

The central thesis is that an Agent’s identity should not be defined by a public key, domain, server, API key, or isolated certificate. Keys rotate, domains change, servers go down, routes expire, and versions evolve. The real identity of an Agent should be its verifiable continuity: genesis, evolution, behavior, capabilities, controller, proofs, and auditable history.

## 1. The problem: the internet still authenticates machines as if they were traditional users or servers

The current web infrastructure was mainly designed for three types of entities: humans, servers, and applications. Humans use passwords, passkeys, OAuth, sessions, and devices. Servers use DNS, TLS, certificates, and firewalls. Applications use API keys, tokens, service accounts, and permissions. This model works reasonably well for SaaS, microservices, and traditional B2B integrations, but it starts to fail when the entity taking action is not just a passive application, but an autonomous Agent.

An Agent can initiate actions, call tools, negotiate, delegate, execute tasks, maintain memory, change strategy, update its version, consume APIs, communicate with other Agents, and act on behalf of a company or user. This creates a question that today’s internet still does not answer well:

How can we know that an Agent is really who it claims to be, belongs to who it claims to belong to, has the capabilities it claims to have, is running an authorized version, has not been revoked, has not suffered behavioral drift, and can be held accountable afterward?

Emerging protocols such as A2A and MCP solve parts of the interoperability problem. A2A aims to enable communication and coordination between Agents from different providers. MCP aims to standardize the connection between AI applications, tools, and data sources. But interoperability is not the same as universal identity, verifiable authority, auditable evolution, and end-to-end security. The composition of these elements has not yet been standardized as a single trust layer for Agents.

## 2. The difference between identity, authentication, authorization, and evolution

For Agents, four concepts must be separated.

Identity answers: “Who is this Agent?”

Authentication answers: “Can this Agent prove that it controls the keys associated with this identity?”

Authorization answers: “What can this Agent do, on behalf of whom, in which context, and until when?”

Evolution answers: “Is this new version still the same Agent, or is it another system using the same identity?”

In the traditional web, identity and authentication are often coupled to a key, certificate, account, or domain. For Agents, this is insufficient. A sales Agent from a company may change servers, update its model, change its negotiation policy, rotate keys, migrate runtime, and still remain the same logical Agent. What must remain verifiable is its lineage: where it came from, who controls it, which versions were published, which capabilities were granted, which ones were revoked, and which proofs support its continuity.

The proposed conceptual formula is:

AgentIdentity = Genesis + Evolution + Capabilities + Controller + Proofs

In other words, an Agent’s identity is not a key. The key is only a temporary instrument of control. The identity is the verifiable continuity of the agent entity.

## 3. DID as the foundation for universal identity

Decentralized Identifiers, or DIDs, are a natural foundation for this model. A DID is a decentralized identifier that can resolve to a document containing verification methods, cryptographic material, and services associated with the identified subject. This allows an entity to prove control over its identity without depending exclusively on a central provider [R1].

In the context of Agents, a DID can represent three different levels:

BusinessDID: represents the company or organization.

AgentDID: represents the logical Agent, for example, the sales, support, billing, medical triage, or negotiation Agent.

AgentInstanceDID: represents a specific running instance of that Agent, bound to a runtime, region, process, server, or operational environment.

This separation is important because the logical Agent can survive across multiple instances. A company can have the same Agent running in multiple regions, multiple servers, or different isolation environments. The instance changes; the logical identity remains.

A conceptual example:

BusinessDID: did:agentnet:business:acme

AgentDID: did:agentnet:agent:acme.sales.negotiator

AgentInstanceDID: did:agentnet:instance:acme.sales.negotiator.us-east-1.2026-06

## 4. Verifiable Credentials for declaring authority

DIDs solve identity and key control, but they do not solve the authority problem by themselves. For that, Verifiable Credentials are more appropriate. A Verifiable Credential allows verifiable claims to be expressed, cryptographically signed, and machine-readable, such as “this Agent belongs to company X” or “this Agent can execute capability Y” [R2].

In the Business-to-Agent model, a company could issue credentials to its own Agents:

“This Agent belongs to company X.”

“This Agent can negotiate orders.”

“This Agent can check inventory.”

“This Agent can issue charges up to R$ N.”

“This Agent is authorized to run version Y of the behavior manifest.”

“This Agent can communicate with approved suppliers.”

This changes the trust model. The Agent does not merely claim what it can do. It presents a credential signed by a verifiable authority. The other Agent or Business verifies the signature, revocation status, validity period, issuer, subject, branch head, and declared capability.

## 5. Capabilities as the unit of authorization

The capability model is more suitable for Agents than broad permissions or fixed roles. A capability is a specific, scoped, and ideally unforgeable authority to execute an action over a resource. The idea of capability-based security is old and goes back to the work of Dennis and Van Horn on multiprogrammed computation [R3].

For Agents, capabilities should be treated as fine-grained units of authorization. Instead of saying:

“This Agent is admin.”

The system should say:

“This Agent can check inventory for store X for 10 minutes.”

“This Agent can reserve product Y for up to 2 minutes.”

“This Agent can negotiate a discount up to 8%.”

“This Agent can issue a charge up to R$ 500.”

“This Agent can access only orders from tenant Z.”

This granularity is essential because Agents will operate at high frequency and may compose tasks. An authorization mistake in an Agent does not generate only a wrong click; it can generate thousands of automated actions before a human notices.

## 6. Proof-of-Evolution: identity as verifiable lineage

The central concept of the proposal is Proof-of-Evolution.

Proof-of-Evolution is not mining. It is not Proof-of-Work. It is not Proof-of-Stake. It is a proof of semantic continuity between versions of an Agent.

Each Agent is born with a GenesisNode:

AgentGenesisNode {
agent_did
creator_did
created_at
initial_public_keys
behavior_manifest_hash
runtime_manifest_hash
initial_capabilities
governance_policy_hash
genesis_signature
}

Each new version of the Agent creates a VersionNode:

AgentVersionNode {
agent_did
version_id
parent_version_id
code_hash
behavior_manifest_hash
semantic_diff_hash
capability_diff_hash
migration_proof_hash
test_receipt_hash
security_scan_receipt_hash
benchmark_receipt_hash
created_at
controller_signature
}

The new version should only be accepted as a legitimate continuation if it proves that it derives from the previous one. This proof may involve the controller’s signature, code hash, behavior manifest hash, semantic diff, state migration, tests, benchmarks, security validations, and capability compatibility.

The conceptual rule would be:

previous_behavior ⊢ migrated_behavior

previous_state_schema ⊢ migrated_state_schema

previous_capabilities ⊢ declared_capability_diff

previous_security_level <= new_security_level

This means the Agent can evolve, but its evolution must be registered, verifiable, and auditable.

## 7. Blockchain as a trust layer, not as an operational database

A common mistake would be trying to place all Agent interactions on the blockchain. This would likely destroy performance, increase cost, reduce privacy, and create permanent exposure of sensitive data.

The correct proposal is to separate three layers:

On-chain:
identity, versions, public keys, capability commitments, revocations, Agent-to-Agent relationships, snapshot hashes, Merkle roots, Proof-of-Evolution, and audit receipts.

Off-chain:
payloads, real routes, internal messages, complete events, complete snapshots, temporary certificates, and operational state.

Ephemeral:
routes, session keys, DPoP keys, lease tokens, routing capsules, and temporary capabilities.

The blockchain acts as a public layer of commitment and verification. The local EventStore acts as the operational layer for execution, replay, and recovery. Merkle roots allow batches of events to be anchored without publishing the events themselves. This pattern is already used in transparency and audit systems because Merkle trees enable efficient proofs of inclusion and consistency [R9].

## 8. Local EventStore and DAG as the Agent’s operational memory

Stateful Agents need continuity. If an Agent crashes and restarts, it cannot lose its operational context, intention queue, events, valid routes, and derived state. Event Sourcing solves this type of problem by persisting state changes as a sequence of events and reconstructing state by replay [R10].

In the case of Agents, a DAG-based EventStore is even more appropriate than a single event line, because Agents naturally create branches: attempts, forks, retries, relationships, subagents, version branches, parallel executions, and interactions with multiple entities.

The blockchain does not need to know all these details. It only needs to receive periodic cryptographic commitments:

AgentActivityCommitmentNode {
agent_did
version_id
batch_range
merkle_root
previous_activity_root
timestamp
signature
}

This way, the Agent preserves local auditability while also anchoring public proofs of integrity.

## 9. Private, ephemeral, and LinearAutoDestroy routes

In a Business-to-Agent model, routes should not be identities. Routes are ephemeral communication capabilities. The identity is in the DID and in the evolutionary lineage. The route is only the authorized, temporary, and disposable path for communication.

When Agent A wants to use a service from Agent B, the flow would be:

1. Agent A resolves Agent B’s DID.

2. Agent A verifies B’s branch head, capabilities, and credentials.

3. Agent A publishes or sends a ConnectionRequest.

4. Agent B validates A: identity, version, reputation, capabilities, proofs, and policies.

5. Agent B accepts and generates a private RoutingCapsule.

6. Agent A receives the encrypted capsule.

7. Both start communication over mTLS.

8. Each request includes DPoP.

9. Each response may carry a next_route_hash or route_epoch.

10. The previous route is destroyed.

The RoutingCapsule could contain:

RoutingCapsule {
route_id
route_epoch
supported_protocols
unique_routes
mtls_certificate
dpop_public_key_binding
allowed_capabilities
rate_limits
ttl
not_before
expires_at
linear_auto_destroy_policy
}

The blockchain should not store the real route. It should store only a commitment/hash. This prevents permanent data from becoming vulnerable in the future if cryptographic algorithms are broken.

## 10. mTLS, DPoP, and replay defense

mTLS is suitable for Agent-to-Agent communication because it enables mutual authentication at the transport layer. Instead of only the server proving its identity to the client, both sides can present certificates. RFC 8705 defines the use of mutual TLS in OAuth 2.0 and certificate-bound tokens [R5].

DPoP complements mTLS at the application layer. It allows OAuth tokens to be bound to possession of a private key and requires a signed proof in each request. This reduces the value of stolen tokens, because the attacker would also need to control the corresponding private key. RFC 9449 defines DPoP as a proof-of-possession and replay protection mechanism at the application layer [R4].

In the proposed model, mTLS protects the channel and DPoP protects each action. The combination is important because Agents will make high-frequency calls, possibly across different protocols, with ephemeral routes and time-bound capabilities.

## 11. ML-KEM and hybrid post-quantum cryptography

For a project designed for a 5-, 10-, or 15-year horizon, the architecture must consider crypto-agility and post-quantum cryptography. NIST standardized ML-KEM in FIPS 203 as a post-quantum key encapsulation mechanism derived from the CRYSTALS-Kyber family [R6].

However, for practical adoption, the most prudent path is hybrid: combining classical ECDHE with ML-KEM. IETF drafts for TLS 1.3 already define hybrid mechanisms such as X25519MLKEM768, SecP256r1MLKEM768, and SecP384r1MLKEM1024 [R7]. The motivation is simple: during the post-quantum transition, if one of the algorithms is broken, the other can still preserve security.

The recommended composition for Agents would be:

TLS 1.3

mTLS

hybrid ECDHE/ML-KEM

DPoP per request

route_epoch per response

linear destruction of old keys and routes

TLS 1.3 was designed to protect communication against eavesdropping, tampering, and message forgery [R8]. This proposal adds decentralized identity, capabilities, DPoP, and post-quantum crypto-agility to the specific context of Agents.

## 12. Why composition is the correct solution

None of the individual pieces solves the full problem.

DID solves identity, but not behavior.

Verifiable Credentials solve verifiable claims, but not evolution.

mTLS protects the channel, but does not represent semantic capability.

DPoP protects tokens against replay, but does not define universal identity.

Blockchain records public commitments, but should not execute the operational flow.

Event Sourcing preserves history, but does not create public trust.

Merkle roots create compact proofs, but do not define authorization.

A2A and MCP help interoperability, but are not enough as trust infrastructure.

The solution is composition.

The value of the architecture is precisely in combining mature primitives with a new conceptual axis: verifiable semantic evolution. The Agent’s identity stops being a static key and becomes a living, versioned, authorized, revocable, and auditable entity.

This composition is strong because each layer does only what it does well:

DID identifies.

VC declares authority.

Capabilities limit action.

Blockchain anchors trust.

EventStore preserves execution.

Merkle roots summarize auditability.

mTLS protects the channel.

DPoP protects the request.

ML-KEM prepares the post-quantum transition.

Proof-of-Evolution proves continuity.

LinearAutoDestroy reduces the temporal attack surface.

## 13. What already exists and what is still missing

It would not be correct to say that none of this exists. The pieces exist. DID, Verifiable Credentials, DPoP, mTLS, TLS 1.3, ML-KEM, Event Sourcing, Merkle trees, A2A, and MCP already exist at different levels of maturity.

There are also partial works and implementations trying to apply DID, VC, and on-chain anchoring to autonomous Agents. A recent example is MolTrust, described as a trust infrastructure for Agents based on W3C DID, Verifiable Credentials, and on-chain anchoring, including authorization, behavioral logging, and portability [R12].

But this does not invalidate the proposal. On the contrary: it confirms that the problem is emerging.

What still does not exist as a consolidated standard is the complete composition:

universal Agent identity;

verifiable evolutionary lineage;

semantic capabilities;

proof of behavioral continuity;

ephemeral LinearAutoDestroy routes;

mTLS + DPoP per interaction;

on-chain anchors for local EventStores;

global revocation;

compatibility with multiple protocols;

and Business-to-Agent governance.

This composition is the differentiator.

## 14. Why this will probably only be used at scale in five years or more

Adoption should not be immediate, for three reasons.

First, the Agent ecosystem is still consolidating. Protocols such as A2A and MCP are recent. Companies are still learning how to operate Agents in production, integrate tools, control costs, define responsibilities, and handle security.

Second, decentralized identity and Verifiable Credentials still need better UX, governance, and interoperability. The technology exists, but broad enterprise adoption requires standards, libraries, compliance, legal support, and integration with legacy systems.

Third, large-scale Business-to-Agent communication requires economic trust. Companies will only allow Agents to negotiate, buy, sell, issue charges, or make commitments if there is strong authentication, clear revocation, audit trails, and accountability.

For this reason, an infrastructure like this seems too early for immediate mass adoption, but appropriate for a 5- to 15-year horizon.

## 15. Why in 10 or 15 years the internet may have more Agents talking to businesses than humans

The hypothesis that the internet will have more Agent-to-Business interactions than Human-to-Business interactions in 10 or 15 years is speculative, but plausible.

Today, there is already more automated traffic than human traffic in some global web traffic measurements. Recent reports indicate that bots and automations already represent a majority share of traffic in certain periods and categories. At the same time, major consulting firms and vendors project strong growth for Agentic AI in enterprise software, autonomous decisions, and Agent-mediated commerce [R13][R14][R15].

The difference is that much of today’s automated traffic is illegitimate, opaque, or poorly classified: scraping, fraud, malicious bots, crawling, and unauthorized automation. The next phase needs to transform opaque automation into verifiable Agency.

Instead of asking:

“Is this a human or a bot?”

The internet will need to ask:

“Is this Agent legitimate?”

“Who controls this Agent?”

“What capability does it have?”

“Which version is it running?”

“Was this action authorized?”

“Is this route still valid?”

“Can this interaction be audited later?”

This is the reason for a blockchain of identity and evolution for Agents. It is not a blockchain meant to replace the web. It is a layer to make the web secure when the main users of the infrastructure are autonomous entities.

## 16. Conclusion

The current internet does not have a universal layer for Agent identity, evolution, and authorization. It has isolated pieces: certificates, OAuth, API keys, service accounts, DID, VC, mTLS, DPoP, interoperability protocols, and blockchains. The problem is that none of these pieces, by itself, represents the real nature of an Agent.

An Agent is not merely an account. It is not merely an application. It is not merely a key. It is not merely a process. An Agent is an evolving operational entity, capable of acting, delegating, learning, updating itself, negotiating, and representing the interests of third parties.

For that reason, an Agent’s identity should be its verifiable lineage.

Proof-of-Evolution proposes exactly this: a way to prove that a new version still belongs to the same logical identity, preserving authority, behavior, governance, and auditability.

The blockchain enters as a public trust layer, not as an operational database. The local EventStore preserves execution. Verifiable Credentials declare authority. Capabilities limit actions. mTLS protects the channel. DPoP protects each request. ML-KEM prepares the architecture for the post-quantum era. LinearAutoDestroy routes reduce the exploitation window. Merkle roots enable auditability without exposing payloads.

The composition of these technologies forms an infrastructure suitable for an internet where Agents will not be merely auxiliary tools, but active participants in the digital economy.

If this transition happens in 10 years, the infrastructure needs to start being designed now. If it happens in 15, the direction is still the same: the Business-to-Agent internet will need identity, evolution, authorization, revocation, and auditability as native primitives.

