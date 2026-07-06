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
* **Interactive 3D graph** — hosts as glowing nodes with IP/hostname labels,
  conversations as thick, animated, protocol-colored connections (Three.js +
  `OrbitControls` + bloom post-processing for a "living network" look).
* **Click-to-follow traffic** — click any host or connection to highlight it
  and everything it talks to; unrelated traffic dims out. Click empty space
  or the "Clear selection" button to reset. A "Labels" toggle and a protocol
  color legend (left sidebar) help keep dense captures readable.
* **Timeline scrubber** — drag to select a time range; the 3D scene and
  dashboard update instantly to match.
* **Filtering & search** — free-text search plus one-click protocol chips
  (TCP, UDP, DNS, TLS, ARP, HTTP, and more).
* **Packet inspector** — click any node/connection, or drill into a packet,
  for an OSI-layer breakdown, hex/ASCII view, and a plain-English
  explanation of what that traffic means.
* **Analytics dashboard** — packet/byte counts, protocol distribution, and
  top talkers, updating live with your filters.
* **Built-in heuristic security checks** — port scan, broadcast storm,
  ARP-spoofing, and failed-connection detection, each with a confidence
  score, severity, explanation, and suggested next step.
* **Dark mode by default**, with a light mode toggle.
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
      ├─ filters.js             → search/filter predicate shared by all views
      ├─ dashboard.js             → live stats panel
      ├─ inspector.js              → per-object detail + plain-English explainer
      └─ securityEngine.js          → heuristic anomaly detection
```

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
* CIDR-aware subnet clustering / expand-collapse in the 3D scene for very
  large host counts.

Issues and pull requests are welcome.

## Privacy

Capture files are **never uploaded anywhere**. Parsing, visualization, and
the built-in heuristic security checks all run locally in your browser
tab. Closing the tab discards everything.

## License

MIT — see [LICENSE](LICENSE). Free to use, modify, and redistribute,
including commercially, with attribution retained in the license file.
