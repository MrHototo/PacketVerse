/**
 * securityEngine.js
 * Small set of deterministic, explainable heuristics for common anomaly
 * patterns. Intentionally conservative (favors fewer false positives over
 * exhaustive coverage) to keep this lightweight and trustworthy — every
 * finding includes *why* it was flagged so a beginner can learn from it.
 */
export function runSecurityChecks({ hosts, flows, packets, timeRange }) {
  const findings = [];
  findings.push(...detectPortScans(flows));
  findings.push(...detectBroadcastStorm(packets, timeRange));
  findings.push(...detectArpAnomalies(packets));
  findings.push(...detectExcessiveResets(flows));
  return findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
}

function severityRank(sev) {
  return { high: 3, medium: 2, low: 1 }[sev] || 0;
}

function detectPortScans(flows) {
  const byPair = new Map(); // "srcHost->dstHost" -> Set(ports)
  for (const flow of flows.values()) {
    if (flow.protocol !== 'TCP') continue;
    const key = `${flow.hostA}->${flow.hostB}`;
    if (!byPair.has(key)) byPair.set(key, new Set());
    byPair.get(key).add(flow.portB);
  }
  const findings = [];
  for (const [pair, ports] of byPair) {
    if (ports.size >= 15) {
      const [src, dst] = pair.split('->');
      findings.push({
        type: 'Port Scan',
        severity: ports.size >= 50 ? 'high' : 'medium',
        confidence: Math.min(0.95, 0.5 + ports.size / 100),
        affected: [src, dst],
        explanation: `${src} attempted connections to ${ports.size} different ports on ${dst} in a short window. This pattern commonly indicates port scanning/reconnaissance rather than normal application traffic.`,
        nextSteps: `Check whether ${src} is an authorized scanner (e.g., a vulnerability scanner) or an unexpected/unauthenticated device. If unexpected, isolate the host and review its recent activity.`,
      });
    }
  }
  return findings;
}

function detectBroadcastStorm(packets, timeRange) {
  const span = Math.max(1, timeRange.end - timeRange.start);
  const broadcastCount = packets.filter((p) => p.frame.tags.includes('Broadcast')).length;
  const rate = broadcastCount / span;
  if (rate > 50) {
    return [
      {
        type: 'Broadcast Storm',
        severity: rate > 200 ? 'high' : 'medium',
        confidence: 0.7,
        affected: [],
        explanation: `The capture contains an unusually high rate of broadcast traffic (~${rate.toFixed(0)} broadcast packets/sec). Excessive broadcasts can degrade network performance for every device on the segment.`,
        nextSteps: 'Identify the source(s) of the broadcast traffic and check for switching loops, misconfigured services, or a failing NIC.',
      },
    ];
  }
  return [];
}

function detectArpAnomalies(packets) {
  const ipToMacs = new Map();
  for (const p of packets) {
    const arp = p.frame.layers.l3;
    if (arp?.type !== 'ARP' || arp.op !== 'REPLY') continue;
    if (!ipToMacs.has(arp.senderIp)) ipToMacs.set(arp.senderIp, new Set());
    ipToMacs.get(arp.senderIp).add(arp.senderMac);
  }
  const findings = [];
  for (const [ip, macs] of ipToMacs) {
    if (macs.size > 1) {
      findings.push({
        type: 'Possible ARP Spoofing',
        severity: 'high',
        confidence: 0.6,
        affected: [ip, ...macs],
        explanation: `IP address ${ip} was seen claimed by ${macs.size} different MAC addresses (${[...macs].join(', ')}). This can be normal after a device swap or DHCP change, but is also a classic sign of ARP spoofing / man-in-the-middle activity.`,
        nextSteps: `Verify which device should legitimately own ${ip}. If unexpected, treat this as a potential MITM attack and investigate both MAC addresses.`,
      });
    }
  }
  return findings;
}

function detectExcessiveResets(flows) {
  const findings = [];
  for (const flow of flows.values()) {
    if (flow.protocol === 'TCP' && flow.flagsSeen.has('RST') && flow.packets <= 3) {
      findings.push({
        type: 'Failed Connection',
        severity: 'low',
        confidence: 0.5,
        affected: [flow.hostA, flow.hostB],
        explanation: `The connection attempt from ${flow.hostA} to ${flow.hostB}:${flow.portB} was quickly reset. This usually means nothing was listening on that port, or the destination actively refused the connection.`,
        nextSteps: 'If this was expected traffic, confirm the target service is running and reachable. Repeated resets to many hosts may indicate scanning rather than a single misconfiguration.',
      });
    }
  }
  return findings.slice(0, 20); // cap noise for readability
}
