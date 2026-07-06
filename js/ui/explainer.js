/**
 * explainer.js
 * Rule-based, deterministic "plain English" narration engine. No external
 * AI/API call is required — this keeps the app free to run and fully
 * client-side, while still delivering the "explain what's happening in
 * plain language" experience the project is built around.
 *
 * A future contribution could swap `explainPacket`/`explainFlow` for an
 * LLM-backed version (see README "Roadmap") without touching the rest of
 * the app, since both already return the same { plain, technical } shape.
 */

export function explainPacket(packetEntry) {
  const { frame } = packetEntry;
  const l = frame.layers;

  if (l.l7?.type === 'DNS' || l.l7?.type === 'mDNS') {
    const d = l.l7;
    if (!d.isResponse) {
      return {
        plain: `This device is asking a DNS server to translate the name "${d.name || 'unknown'}" into an IP address (a "${d.queryType || 'A'}" record lookup).`,
        technical: `DNS query, id present, qdcount=${d.qdCount}, type=${d.queryType}`,
      };
    }
    return {
      plain: `A DNS server is answering an earlier name lookup${d.name ? ` for "${d.name}"` : ''}.`,
      technical: `DNS response, rcode=${d.rcode}, ancount=${d.anCount}`,
    };
  }

  if (l.l7?.type === 'TLS') {
    const t = l.l7;
    if (t.handshakeType === 'ClientHello') {
      return {
        plain: `This device is starting a secure (encrypted) connection${t.serverName ? ` to "${t.serverName}"` : ''}. Think of this as the "hello, let's talk securely" step before any data is exchanged.`,
        technical: `TLS ClientHello, negotiated record version ${t.version}, SNI=${t.serverName || 'n/a'}`,
      };
    }
    return {
      plain: 'This is part of a secure connection being set up between two devices.',
      technical: `TLS handshake message (${t.handshakeType})`,
    };
  }

  if (l.l7?.type === 'HTTP') {
    if (l.l7.method === 'RESPONSE') {
      return {
        plain: 'A web server is sending back a page or file that was requested.',
        technical: 'HTTP response',
      };
    }
    return {
      plain: `This device is requesting a web resource using an HTTP "${l.l7.method}" request — similar to typing a URL into a browser or an app fetching data.`,
      technical: `HTTP ${l.l7.method}`,
    };
  }

  if (l.l3?.type === 'ARP') {
    return {
      plain: `This device is broadcasting a request on the local network asking "who owns IP address ${l.l3.targetIp}?" — it's how devices find each other's hardware address before talking directly.`,
      technical: `ARP ${l.l3.op}`,
    };
  }

  if (l.l4?.type === 'TCP') {
    const f = l.l4.flags;
    if (f.SYN && !f.ACK) {
      return {
        plain: 'This device is opening a new connection — the first handshake step, like knocking on a door before entering.',
        technical: `TCP SYN, port ${l.l4.dstPort}`,
      };
    }
    if (f.SYN && f.ACK) {
      return {
        plain: 'The other side is accepting the connection request — the second handshake step.',
        technical: 'TCP SYN-ACK',
      };
    }
    if (f.FIN) {
      return {
        plain: 'One side is gracefully closing this connection — it has no more data to send.',
        technical: 'TCP FIN',
      };
    }
    if (f.RST) {
      return {
        plain: 'This connection was abruptly rejected or terminated — often because nothing was listening, or an error occurred.',
        technical: 'TCP RST',
      };
    }
    return {
      plain: `Data is being exchanged over an already-open connection between port ${l.l4.srcPort} and port ${l.l4.dstPort}.`,
      technical: `TCP data segment, flags=${Object.entries(f).filter(([, v]) => v).map(([k]) => k).join('/') || 'none'}`,
    };
  }

  if (l.l4?.type === 'UDP') {
    return {
      plain: 'A short, connectionless message is being sent — commonly used for things like DNS, streaming, or gaming where speed matters more than guaranteed delivery.',
      technical: `UDP ${l.l4.srcPort} -> ${l.l4.dstPort}`,
    };
  }

  if (l.l4?.type === 'ICMP' || l.l4?.type === 'ICMPv6') {
    return {
      plain: 'This is a network diagnostic/control message — for example a "ping" or a notice that a destination could not be reached.',
      technical: `${l.l4.type} type ${l.l4.icmpType}, code ${l.l4.icmpCode}`,
    };
  }

  return {
    plain: 'This packet does not match a recognized common protocol in this lightweight decoder.',
    technical: frame.summary,
  };
}

export function explainFlow(flow) {
  const durationSec = Math.max(0, flow.lastSeen - flow.firstSeen);
  const parts = [];
  parts.push(
    `${flow.hostA} and ${flow.hostB} exchanged ${flow.packets} packets (${flow.bytes} bytes) over ${flow.protocol}${flow.appProtocol ? ` (${flow.appProtocol})` : ''}.`
  );
  if (durationSec > 0) {
    parts.push(`This conversation lasted about ${durationSec.toFixed(2)} seconds.`);
  }
  if (flow.flagsSeen.has('RST')) {
    parts.push('It included a reset, which can indicate a rejected or interrupted connection.');
  }
  if (flow.tags.has('Broadcast')) {
    parts.push('This traffic was broadcast to every device on the local network.');
  }
  return { plain: parts.join(' '), technical: `key=${flow.key}` };
}
