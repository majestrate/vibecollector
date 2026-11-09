# Usage

This guide is for the person running VibeCollector. It describes the operator workflow the daemon is being built to support.

## Before you start

You need:

- a host where the collector can bind a UDP port and write a SQLite file
- one or more devices that export NetFlow v5, NetFlow v9, or IPFIX
- a browser on a machine that can reach the web UI

The collector and the database run on the same host. Exporters send UDP datagrams to that host. The browser talks to the daemon's HTTP API, and in a production install it also loads the UI from that daemon.

Give the SQLite file and its directory permissions that match who should be able to read traffic metadata. A flow record is enough to see which addresses exchanged traffic, on which ports, and when.

## Start the collector

Run one collector process. It binds the UDP socket, creates or opens the SQLite database, and serves the UI API.

The config file is `./vibecollector.toml` when that file is present. Otherwise the process uses built-in defaults. A missing default file is not an error. `-config PATH` selects a file. A missing file named by `-config` is a startup error.

An unknown key is a startup error. A typo does not silently take effect.

`http.listen` defaults to `127.0.0.1:8080`. `http.token` is required when the HTTP listen address is not loopback. Without it the process exits 2.

If the config file mode is looser than `0600`, the process logs a warning and still starts.

Configuration covers:

- the UDP listen address and port (default port UDP 2055)
- the path to the SQLite database
- the HTTP listen address for the UI and API
- which enrichment providers are enabled
- how long raw flows and UI aggregates are kept

Until a provider client is implemented and enabled, GeoIP, ASN, and reputation stay empty. The collector still stores flows.

Bind the HTTP service to localhost unless you intend other machines to open the UI. Flow data is sensitive. Put a reverse proxy with access control in front of the HTTP port if you expose it beyond the collector host.

## Point exporters at the collector

On each router, switch, or probe, set the NetFlow or IPFIX destination to the collector's IP address and UDP port.

Use a stable source address on the exporter. The collector keeps a template table per exporter and per observation domain. NetFlow v9 and IPFIX send a template that describes later data records. After the collector restarts, decoding resumes when the exporter sends its templates again. Devices that send templates on a timer recover on that timer. Data that arrives without a template is counted and discarded once a small hold buffer fills.

Export a format the collector accepts: NetFlow v5, NetFlow v9, or IPFIX over UDP. Sampled and unsampled exports are both stored. The UI marks sampled data so those counters are not read as complete traffic.

Confirm the host firewall allows the chosen UDP port from the exporters.

## Read the data

Open the web UI and choose a time range. The views read the local database and share that range and the current filters. Choose a calendar day to hold every view to that day. The day is midnight to midnight in the selected timezone, which starts as UTC.

- **Flows** lists individual conversations. Filter by address, port, protocol, exporter, country, ASN, or reputation.
- **Traffic** shows bytes and packets over time for the current filters.
- **Top talkers** ranks sources, destinations, and ports for the selected range.
- **World map** is a flat map. Countries are shaded by traffic volume, and arcs show the busiest paths between places in the selected range.
- **Globe** draws those same country totals and paths on a sphere. Rotate and zoom it. Changing the day, the range, or a filter updates the map and the globe together.
- **ASN** groups addresses by autonomous system.
- **Reputation** lists addresses a reputation provider has marked, with the category that provider returned.

The map and the globe draw rolled-up places, not one mark per flow. They use the GeoIP annotation stored with the flow. With the shipped GeoIP stub, both still show the world and leave the traffic layer empty. Private and otherwise non-global addresses stay off both views.

Private and otherwise non-global addresses appear in the flow table and carry a local classification. They do not receive GeoIP, ASN, or reputation annotations.

A flow with an empty annotation means the provider is still a stub, the provider was not asked (the address is not global), or the provider returned no data. The flow itself is still stored.

## Enrichment providers

GeoIP, ASN, and reputation are separate providers on one interface. The build includes a stub for each. A stub records "not configured" and does not contact an external service.

To turn an annotation on, implement that provider's client and enable it in the collector configuration. The collector then looks up global addresses through the client, caches the answer in memory, and stores the annotation with later flows. Each provider has its own cache lifetime, because a geographic assignment changes rarely and a reputation score changes often.

Lookups run beside the UDP reader. A slow or failed provider does not stop collection. The stored flow keeps a per-provider outcome so the UI can show "not configured", "no data", or "error" instead of a blank that looks like a successful empty answer.

Enabling a real provider sends looked-up IP addresses to that provider. Enable one only if that destination is acceptable for this traffic.

## What you will see during problems

The UI includes exporter health: last packet time, decode errors, and flows dropped because a template was missing. Use those counters before changing export configuration on the device.

Collection trouble is usually one of these:

- the exporter is sending to the wrong address or port
- a firewall is dropping the UDP
- the device is sending a format other than NetFlow v5, NetFlow v9, or IPFIX
- templates have not arrived since the collector started
- the database disk is full, so the collector counts write failures and sheds load instead of blocking the socket

The collector logs these conditions and exposes counters for them. It keeps reading the socket while a downstream stage is unhealthy.

## Stop and restart

Stopping the process closes the socket and flushes the current SQLite write batch. Starting it again opens the same database. In-memory enrichment cache entries and in-memory template tables start empty. Exporters refill templates on their next template refresh. Cached enrichment refills as flows arrive.

The SQLite file is the durable copy. Back that file up while the collector is stopped, or with the SQLite backup API, so a copy is consistent.
