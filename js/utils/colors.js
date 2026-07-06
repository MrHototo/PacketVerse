/** Centralized, colorblind-conscious protocol color palette. */
export const PROTOCOL_COLORS = {
  TCP: 0x4d9de0,
  UDP: 0xe9b44c,
  DNS: 0x4caf50,
  mDNS: 0x66bb6a,
  TLS: 0x9b59b6,
  HTTP: 0x3fb8af,
  ICMP: 0xe15554,
  ICMPv6: 0xe1a15c,
  ARP: 0x9e9e9e,
  DHCP: 0xff8a65,
  NTP: 0x80cbc4,
  SSDP: 0xba68c8,
  OTHER: 0x607d8b,
};

export function colorForProtocol(protocol) {
  return PROTOCOL_COLORS[protocol] ?? PROTOCOL_COLORS.OTHER;
}

export function hexToCss(hex) {
  return `#${hex.toString(16).padStart(6, '0')}`;
}

export const ROLE_COLORS = {
  client: 0x4d9de0,
  server: 0x9b59b6,
  gateway: 0xe9b44c,
  broadcast: 0x9e9e9e,
  unknown: 0x8892a0,
};
