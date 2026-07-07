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
* **Full-bleed, Google-Maps-style map, in 3D or 2D** — the graph *is* the app
  surface (not a small panel); a search/filter bar, legend, dashboard, and
  inspector float on top as collapsible glass panels, and +/- buttons give
  Maps-style zoom control alongside scroll/drag orbiting. A top-right toggle
  switches instantly between the 3D force-directed scene and a **2D radial
  layout** (hub-and-rings by traffic/hop-distance, not just a flattened copy
  of the 3D view — see `js/viz/layout2d.js`) — your preference is remembered
  between visits via `localStorage`. Every filter, selection, and focus state
  is shared between both modes, so switching never loses your place.
* **Physically converging layout, not perpetual motion** — the 3D force
  simulation uses an alpha-decay schedule (the same mechanism used by
  d3-force): it runs hot right after a graph change and then genuinely
  **freezes** once settled, so nodes stop moving entirely and stay stationary
  until the *data* changes (a filter, a focus, an expand/collapse) — orbiting,
  panning, or zooming the camera never reheats it.
* **A genuine Wireshark display-filter grammar** — not a hardcoded list of
  example filters. A real tokenizer + recursive-descent parser implements
  `and`/`or`/`xor`/`not` (and `&&`/`||`/`!`) with correct precedence and
  parentheses; the full comparison set (`==`/`eq`, `!=`/`ne`, `>`/`gt`,
  `<`/`lt`, `>=`/`ge`, `<=`/`le`) plus `any`/`all` quantifiers for repeating
  fields; `contains`; `matches`/`~` regex (case-insensitive by default,
  `(?-i)` for case-sensitive); `in {a, b, c..d}` membership with numeric/IP
  ranges; CIDR matching (`ip.addr == 10.0.0.0/24`); hex/octal/binary/char
  literals; MAC/byte-sequence literals; the slice operator
  (`eth.src[0:3] == 00:11:22`); bitwise AND (`tcp.flags & 0x02`); and
  functions (`upper()`, `lower()`, `len()`, `vals()`, `dec()`, `hex()`,
  `ip_rfc1918()`, and more). Every operator is fully generic and type-driven
  against a declarative field registry (`js/pcap/fieldRegistry.js`) covering
  70+ protocol-scoped fields — adding a new field automatically gets every
  operator for free, rather than special-casing filters one at a time. See
  [`docs/FILTER_SYNTAX.md`](docs/FILTER_SYNTAX.md) for the full reference,
  including the explicit (documented, not silent) exclusions: macros, field
  references, arithmetic operators, and the layer/raw operators. Filtering is
  a true **rebuild**, not a dim/hide overlay: the 3D scene, packet list,
  dashboard, and every statistics tab are recomputed from exactly the
  matching subset. Plain text with no operators falls back to a substring
  search, and any unrecognized-but-plausible field gracefully degrades to a
  protocol-presence test instead of always failing.
* **Wireshark-style packet list** — a sortable No./Time/Source/Destination/
  Protocol/Length/Info table that always reflects the current filter and time
  range; click any row to open that exact packet in the Inspector and jump
  the 3D scene to its conversation.
* **Click to select, double-click to isolate** — a single click on a host or
  connection selects it (centers/zooms the camera on it and shows its detail
  in the Inspector) *without* narrowing what else is visible, so browsing
  never feels like it's suddenly cutting the graph out from under you.
  **Double-click** is the deliberate "investigate this" action: the scene
  rebuilds to show only that node's directly-related traffic
  (graph-database-style traversal, not a giant static map with parts dimmed).
  A breadcrumb bar tracks your drill-down path (click any crumb to jump
  back), an **"+ Expand context"** button reveals one more hop of neighbors
  at a time, and **"Exit focus — show all"** returns to the full (filtered)
  graph. Clicking empty space clears the current selection. Focus and the
  display filter compose together — focusing while a filter is active stays
  within that filter's matches.
* **Drill-down inspector with Wireshark-style layer breakdown** — click a
  host to see its conversations, click a conversation to see its packets,
  click a packet for a full Frame / Ethernet II / Internet Protocol /
  TCP-UDP-ICMP / application-layer breakdown (named and labeled the way
  Wireshark presents them) plus hex/ASCII view and a plain-English
  explanation — with a breadcrumb trail to jump back up. Every drill-down
  list narrows to match the active filter/time range automatically.
* **Follow Stream, fully wired into the visualization** — selecting "Follow
  this stream" doesn't just open a reassembly view in the Inspector, it also
  isolates the 3D/2D scene, the packet list, and every other panel down to
  *exactly* that one conversation (hiding all unrelated hosts/flows/packets),
  fits the camera to it, and adds a dedicated breadcrumb — "Expand context"
  from there reveals the conversation's wider neighborhood one hop at a time,
  and "Exit stream" restores whatever filter/focus was active before you
  followed it. Segments are ordered by TCP sequence number per direction and
  de-duplicated (retransmissions removed) rather than shown in raw arrival
  order, then color-coded by direction (client → server / server → client).
  UDP streams fall back to arrival order (no sequence numbers exist to sort by).
* **Deep, Wireshark-parity packet inspection** — every packet exposes Expert
  Info (retransmissions, duplicate ACKs, zero windows, DNS errors — each with
  a severity), TCP stream index + relative sequence/ack numbers, full DNS
  answer records (name/type/TTL/rdata, CNAME chains), TLS cipher suites, ALPN,
  extensions, and **parsed X.509 certificates** (subject/issuer CN, validity
  dates, expiry/self-signed flags) from the handshake, and complete HTTP
  request/response headers — not just a summary line.
* **Conversations, Endpoints, and Name Resolution tables** — Wireshark's
  Statistics-menu equivalents, as tabs alongside the Overview dashboard; Name
  Resolution shows IP → hostname mappings the app learned from DNS answers,
  TLS SNI, and HTTP Host headers seen anywhere in the capture.
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
* **Packet Explanation & Context panel** — replaces a flat "security
  findings" list with a live, plain-English breakdown of *whatever you have
  selected*: what the packet/conversation/host is, who's talking to whom
  (with resolved hostnames and inferred client/server roles), how the
  protocol normally behaves and what's notable here, where it sits in the
  surrounding conversation, and analyst guidance on what to check next.
  The built-in heuristic engine (port scan, broadcast storm, ARP-spoofing,
  failed-connection detection — each with a confidence score and severity)
  still runs in the background, but its results now surface *in context* as
  "Related heuristic notes" on the specific packets/hosts they actually
  apply to, instead of a disconnected list repeated everywhere.
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
      ├─ scene3d.js         → 3D force-directed graph (Three.js), alpha-decay convergence
      ├─ scene2d.js         → 2D radial/ring layout renderer (Canvas2D), same API as scene3d.js
      ├─ layout2d.js        → deterministic hub-and-rings layout algorithm for the 2D view
      ├─ egoNetwork.js      → BFS ego-network computation powering focus/isolate/expand
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
