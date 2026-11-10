# Overview

VibeCollector is a single-host NetFlow collector. It listens for NetFlow from routers, switches, and probes, stores the flows on disk, and shows them in a web UI.

Network devices already summarize conversations into flows: who talked to whom, on which ports, for how long, and how many packets and bytes moved. VibeCollector receives those summaries. It does not capture packets.

## What it accepts

The collector binds a UDP socket and speaks three export formats:

- NetFlow v5, the fixed IPv4 format used by older gear
- NetFlow v9, the template-based format described in RFC 3954
- IPFIX (RFC 7011), the IETF flow-export standard that current gear usually sends

The listen address and port are configurable. The default port is UDP 2055, which is the port most exporters already use. Point each exporter at the collector's address. The collector is the receiver; there is no separate relay process.

## What it stores

Flows are written to a SQLite database on the collector host. The database is the copy the UI reads. The UI shows stored flows and rollups, so a refresh does not depend on a device exporting at that moment.

Each stored flow keeps the endpoints, ports, protocol, packet and byte counts, timing, the exporter that sent it, and sampling information when the exporter included it. Sampled flows are labeled as sampled. Byte and packet totals on a sampled export are the sampled counts, not a reconstructed full-traffic estimate.

## What it adds to a flow

VibeCollector can attach three kinds of context to an address:

- **GeoIP** — country and related location fields the provider supplies
- **ASN** — the autonomous system number and name for the address
- **Network reputation** — whether a provider considers the address abusive, scanned, or otherwise notable, plus the category it reports

Those lookups share one enrichment interface. Each provider ships as a stub that adds no annotation and makes no outbound request. Annotations appear after a real provider client is configured on that interface. A provider that has no answer, or that fails, leaves the flow in the database and records that outcome.

Addresses that are not globally routable — private, loopback, link-local, and multicast — are classified on the collector. They are not sent to providers.

Lookup results are cached in memory. GeoIP and ASN change slowly. Reputation changes faster. Each provider keeps its own cache lifetime.

## What the UI is for

The web UI is a React application for exploring the collected data. Every view uses the same time range and the same filters, so a day you select is the same day in every view. The range control includes a calendar day. Day boundaries default to UTC, and you can display another timezone.

The views are:

- a filterable table of flows
- traffic volume over time
- top talkers
- an ASN breakdown
- reputation hits
- a flat world map
- a spherical globe

The map and globe routes are in the shell. This build does not draw them and does not contact a tile service. Flows, traffic, top talkers, ASN, and reputation are the views that read the database.

The daemon serves the API behind these views. A production install also serves the built UI from the daemon. During development the UI runs through pnpm and talks to that API.

## What stays on this machine

Flow records describe who communicated with whom. They stay in the local SQLite file. VibeCollector does not phone home.

A configured GeoIP, ASN, or reputation provider receives the IP addresses it is asked to look up. With the shipped stubs, no addresses leave the host for enrichment.
