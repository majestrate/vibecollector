# AGENTS.md

Instructions for AI agents working in this repository.

## Product

VibeCollector is a NetFlow collector daemon with a web UI for exploring the data it stores.

The daemon binds a UDP socket and receives NetFlow directly from exporters. It decodes exports into flow records, enriches those records, and stores them in SQLite. Operators inspect the result in a React application: traffic over time, endpoints, and the GeoIP, autonomous system, and network-reputation annotations attached to those endpoints.

## Collector

- This process is the collector. It owns the bound socket.
- Accept NetFlow v5, NetFlow v9 (RFC 3954), and IPFIX (RFC 7011) over UDP. The listen address and port are configurable. Use UDP 2055 as the default port.
- Normalize each export into one canonical flow record. Convert device-relative timestamps to absolute time. Keep sampling information on the record when the exporter provides it, and surface that sampling in the UI.
- Keep socket reads independent of enrichment and database writes. Count packets that are dropped, malformed, or missing a template, and count templates that are withdrawn.
- Cache NetFlow v9 and IPFIX templates per exporter. Key them by exporter identity, observation domain (v9 source ID or IPFIX observation domain ID), and template ID. Replace a template when a new definition arrives for the same ID. Honor IPFIX template withdrawal. Bound any hold buffer for data that arrives before its template. Template state is protocol state: expire it on exporter silence or withdrawal, not with a generic short TTL.

## Enrichment

All enrichment uses one common interface. The three providers behind that interface are:

- GeoIP
- ASN
- Network reputation

Ship each provider as a stub that implements the interface and returns a typed "not configured" result. A stub does no network I/O and reads no vendor credential. The maintainer writes the real provider clients against that same interface.

Store the flow when a provider returns no data or an error, and record that provider's outcome on the flow. Classify private, loopback, link-local, multicast, and other non-global addresses locally, and skip provider lookups for them.

Cache enrichment results in memory. Give each provider its own TTL. Collapse concurrent cache misses for the same key so a cold address causes one lookup.

## Persistence and cache

- SQLite is the system of record for flows, exporter state, and the aggregates the UI reads.
- Put expensive reusable work in an in-memory cache: enrichment results, hot query results, and any other derived data named in the design. Keep template state on the rules in the Collector section.
- The UI reads stored data through an API served by the daemon.

## Web UI

- Build the UI with React.
- Manage JavaScript dependencies with pnpm. The only JavaScript lockfile is `pnpm-lock.yaml`.
- The UI is for operators inspecting collected flows. Provide multiple views of one shared time range and filter set:
  - a filterable flow table
  - traffic over time
  - top talkers
  - an ASN breakdown
  - reputation hits
  - a flat world map
  - a spherical globe
- The flat map and the globe draw the same geographic aggregates for that range. The range control includes a calendar day. The default day boundary is UTC, and the display timezone is configurable.
- Aggregate geography before drawing it. Show countries and the busiest paths between places. Drawing one mark per flow is not a supported view.
- Ship world geometry with the UI. Map and globe rendering stays on the collector host and does not call a tile server.
- In production the daemon serves the built UI. In development, run the UI with pnpm and point it at the daemon API.

## Repository layout

- `docs/` holds human-readable documentation for people operating VibeCollector.
- `agents/` holds markdown for AI agents: the implementation plan, design notes, and review write-ups.
- `AGENTS.md` (this file) is the standing product requirements. Read it before changing the project.

## Component boundaries

Design and build each component on its own. A component calls another component only through that component's public API. Unexported fields, package-internal helpers, and shared mutable structs are not a calling convention.

The public API of every component carries human-readable documentation on the exported types and functions: Go doc comments in the daemon, JSDoc on exported TypeScript. The comment says what the call does, what the arguments mean, what the result means, and which errors a caller has to handle. An implementer should be able to use the component from that comment and the signature without reading the body.

## Implementation rules

- The requirements in this file are fixed. The design document under `agents/` records how to build them. Implement that design.
- Keep `docs/` aligned with the behavior that is actually shipped.
- Ship schema changes as SQLite migrations.
- Keep the enrichment interface stable. Add further external data sources as new stubs on that interface until the maintainer supplies the client.
- Leave third-party provider clients as stubs. The maintainer fills those in.
