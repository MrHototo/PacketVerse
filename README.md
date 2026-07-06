# PacketVerse

**PacketVerse** turns a PCAP/PCAPNG capture into an interactive 3D map of your
network traffic — with plain-English explanations alongside the technical
detail. It's built to be useful for students learning networking for the
first time, and detailed enough for engineers and analysts doing real
troubleshooting or investigation.

Everything runs **100% client-side, in your browser**. No backend, no
upload, no build step, no API keys required. Open `index.html` (or the
hosted GitHub Pages link) and drop in a capture.

## Live demo

Enable GitHub Pages for this repo (`Settings → Pages → Source: GitHub
Actions`, using the included workflow) and it will be available at:

```
https://<your-username>.github.io/packetverse/
```

No capture handy? Click **"Try demo capture"** in the app to explore a small
synthetic capture with DNS, TLS, ARP, and TCP traffic.

## Features

* **Drag-and-drop PCAP/PCAPNG upload** — parsed entirely in the browser via a
  small, dependency-free binary parser (`js/pcap/pcapParser.js`).
* **Full-bleed, Google-Maps-style 3D map** — the 3D graph *is* the app
  surface (not a small panel); a search/filter bar, legend, dashboard, and
  inspector float on top as collapsible glass panels, and +/- buttons give
  Maps-style zoom control alongside scroll/drag orbiting.
* **Wireshark-style display filters, evaluated per-packet** — type structured
  queries like `tls && tcp.port==853`, `dns.qry.name==example.com`,
  `tcp.flags.syn==1`, `http.request.method==GET`, or `ip.addr ~ /^10\./` for
  regex matching, with a built-in syntax cheatsheet (the `?` button). Matching
  is protocol-scoped (`tcp.port` never accidentally matches a UDP packet) and,
  like Wireshark's display filter, a non-empty filter **hides** everything
  that doesn't match — in the 3D scene, the packet list, and the dashboard —
  rather than just dimming it. Plain text with no operators falls back to a
  substring search. One-click protocol chips remain available too.
* **Wireshark-style packet list** — a sortable No./Time/Source/Destination/
  Protocol/Length/Info table that always reflects the current filter and time
  range; click any row to open that exact packet in the Inspector and jump
  the 3D scene to its conversation.
* **Click-to-follow traffic** — click any host or connection to highlight it
  and everything it talks to; unrelated traffic dims out. Click empty space
  or "Clear selection" to reset. A "Fit to filtered" button (or Enter in the
  filter box) reframes the camera on only what currently matches.
* **Drill-down inspector with Wireshark-style layer breakdown** — click a
  host to see its conversations, click a conversation to see its packets,
  click a packet for a full Frame / Ethernet II / Internet Protocol /
  TCP-UDP-ICMP / application-layer breakdown (named and labeled the way
  Wireshark presents them) plus hex/ASCII view and a plain-English
  explanation — with a breadcrumb trail to jump back up. Every drill-down
  list narrows to match the active filter/time range automatically.
* **Follow Stream** — from any TCP/UDP conversation, reconstruct and view its
  application-layer payload bytes in chronological order, color-coded by
  direction (client → server / server → client), similar to Wireshark's
  Follow TCP Stream. This is a simplified, non-reassembling view (no
  out-of-order reordering/deduplication) — see Roadmap.
* **Clickable dashboard** — top talkers and protocol bars aren't just
  read-only stats; clicking one instantly filters the graph, packet list,
  and inspector to match, no typing required.
* **Automatic subnet clustering** — captures with many hosts collapse same
  `/24` subnets into a single expandable node (Maps-style "zoom out to see
  less, zoom/click in to see more"); small captures show full detail
  automatically. "Expand all subnets" / "Collapse subnets" buttons included.
* **Timeline scrubber** — drag to select a time range; the 3D scene and
  dashboard update instantly to match. Collapsible if you want more map space.
* **Analytics dashboard** — packet/byte counts, protocol distribution, and
  top talkers, updating live with your filters.
* **Built-in heuristic security checks** — port scan, broadcast storm,
  ARP-spoofing, and failed-connection detection, each with a confidence
  score, severity, explanation, and suggested next step; click a finding to
  jump the 3D view to the affected host.
* **Dark mode by default**, with a light mode toggle. Collapsible left/right
  panels so the map can take the full screen when you want it to.
* **Zero dependencies to install** — Three.js is loaded via a CDN import
  map; there is no `npm install` or bundler step required to run the app.

## Getting started

### Option 1 — Just open it
Clone the repo and open `index.html` directly in a modern browser (Chrome,
Edge, or Firefox). That's it.

### Option 2 — Local dev server (recommended for local file loading in some browsers)
```bash
git clone https://github.com/<your-username>/packetverse.git
cd packetverse
npm run serve
# then visit http://localhost:5173
```

### Option 3 — GitHub Pages (recommended for sharing)
1. Push this repo to your own GitHub account.
2. Go to **Settings → Pages → Source**, select **GitHub Actions**.
3. Push to `main` — the included workflow (`.github/workflows/deploy.yml`)
   builds nothing (there's nothing to build) and publishes the static files
   automatically.
4. Share the resulting `https://<username>.github.io/<repo>/` URL with
   anyone — they need only a browser.

## How it works

```
Upload/drop file
      │
pcapParser.js        → decodes PCAP or PCAPNG binary structure into raw frames
      │
protocolDecoder.js    → decodes Ethernet/ARP/IPv4/IPv6/TCP/UDP/ICMP/DNS/TLS/HTTP
      │
graphModel.js          → aggregates frames into Hosts and Flows (conversations)
      │
      ├─ scene3d.js         → 3D force-directed graph (Three.js)
      ├─ timeline.js          → traffic-volume timeline + range selection
      ├─ filterExpression.js    → Wireshark-style filter parser, evaluated per-packet
      ├─ filters.js               → filter bar UI (search box + protocol chips)
      ├─ packetList.js              → Wireshark-style packet table
      ├─ dashboard.js                 → live stats panel
      ├─ inspector.js                  → drill-down detail + Follow Stream + plain-English explainer
      └─ securityEngine.js              → heuristic anomaly detection
```

Filtering flows one way through the app: the filter bar compiles an
expression into a predicate evaluated against every packet in the current
time range; the resulting matched packet set is used to derive which flows
(and, through them, which hosts) are "active," and that single active set
drives the 3D scene's visibility, the packet list's contents, the
dashboard's stats, and the inspector's drill-down lists — so one filter
narrows down everything at once.

Because parsing happens in the browser and results are aggregated into
hosts/flows before rendering, the app stays responsive on moderately large
captures without needing a server or native binary.

## Supported protocols (current scope)

Ethernet (+ 802.1Q VLAN tags), ARP, IPv4, IPv6 (basic), TCP (flags, handshake
detection), UDP, ICMP/ICMPv6, DNS (query/response, common record types,
SVCB/HTTPS type numbers recognized), mDNS, DHCP/NTP/SSDP (port-identified),
and TLS ClientHello parsing including SNI (server name) extraction. HTTP/1.x
requests/responses are heuristically detected on unencrypted connections.

This is intentionally a **lightweight, educational-first** decoder — it does
not aim to replace a full protocol-analysis suite like Wireshark for deep
binary protocols (e.g., decrypted TLS payloads, full HTTP/2/HTTP/3/QUIC frame
decoding). See **Roadmap** below for how this can grow.

## Roadmap / good first contributions

* Web Worker-based parsing for very large captures (keep the main thread
  fully free during parse).
* Additional decoders: full HTTP/2 (HPACK) and QUIC framing, DHCP option
  parsing, IPv6 extension headers.
* Pluggable decoder architecture so new protocols can be added without
  touching `protocolDecoder.js` core.
* Optional AI assistant mode: swap `js/ui/explainer.js`'s rule-based output
  for an LLM-backed explanation via a user-supplied API key (kept optional
  to preserve the zero-cost, fully offline default).
* Export findings/report as PDF or HTML.
* Side-by-side comparison of two captures.
* True TCP stream reassembly for Follow Stream (currently a simplified,
  chronological, non-reordering view of per-packet application payload).
* Byte-level hex/ASCII ↔ decoded-field synchronized highlighting.

Issues and pull requests are welcome.

## Privacy

Capture files are **never uploaded anywhere**. Parsing, visualization, and
the built-in heuristic security checks all run locally in your browser
tab. Closing the tab discards everything.

## License

MIT — see [LICENSE](LICENSE). Free to use, modify, and redistribute,
including commercially, with attribution retained in the license file.
