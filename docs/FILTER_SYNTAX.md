# PacketVerse Filter Syntax

PacketVerse's filter bar implements a genuine subset of Wireshark's own
display filter grammar (`man wireshark-filter`) — the same tokenizer/parser
architecture, not a list of specially-handled example filters. Any field
registered in `js/pcap/fieldRegistry.js` automatically supports every
operator below with no per-field code.

## Existence tests
`tcp`, `dns`, `tls`, `arp` — bare protocol name.
`tls.handshake`, `dns.cname`, `ip.src` — bare dotted field name tests presence.

## Comparison operators
`==`/`eq`, `!=`/`ne`, `>`/`gt`, `<`/`lt`, `>=`/`ge`, `<=`/`le`.
Any/all quantifiers for fields that can repeat in one packet:
`any tcp.port == 443`, `tcp.port all_eq 443` (`any_eq`/`any_ne`/`all_eq`/`all_ne` also work).

## Search operators
`contains` — substring/subsequence match (strings or byte arrays).
`matches` / `~` — PCRE-style regex, case-insensitive by default; prefix the
pattern with `(?-i)` for case-sensitive. `field ~ /pattern/` is also accepted
as a shorthand for `field matches "pattern"`.

## Membership
`tcp.port in {80, 443, 8080}`
`tcp.port in {443, 4430..4434}` — ranges
`ip.addr in {10.0.0.1 .. 10.0.0.9}` — IP ranges

## CIDR
`ip.addr == 10.0.0.0/24`, `ipv6.addr == 2001:db8::/32`

## Literals
Decimal, `0x` hex, `0b` binary, legacy leading-zero octal (`012`), character
constants (`'\x0a'`); double-quoted strings with escapes (`\n`, `\t`, `\xNN`,
`\NNN`, `\"`) and raw strings (`r"..."`); MAC/byte sequences (`aa:bb:cc`,
`aa-bb-cc`); IPv4/IPv6 addresses.

## Logical composition
`not`/`!`, `and`/`&&`, `xor`, `or`/`||`, precedence highest→lowest:
`not > and > xor > or`. Parentheses group explicitly.

## Bitwise AND
`tcp.flags & 0x02` — true if the SYN bit is set (bare use tests non-zero).

## Slice operator
`eth.src[0:3] == 00:11:22` (start:length), `field[i-j]` (inclusive range),
`field[i]` (single byte), `field[:j]`, `field[i:]`, negative offsets from the
end (`field[-4:]`), and comma-combined slices `field[1,3-5,9:]`.

## Functions
`upper()`, `lower()`, `len()`, `count()`, `string()`, `vals()`, `dec()`,
`hex()`, `float()`, `abs()`, `max()`, `min()`, `ip_multicast()`,
`ip_rfc1918()`, `ip_linklocal()`, `ip_ula()`.

## Fallback behavior
Any dotted field not explicitly modeled degrades gracefully: if its protocol
prefix is recognized, it's treated as a presence test for that protocol
rather than permanently failing. If the whole expression fails to parse, the
filter box falls back to a plain case-insensitive substring search so basic
typing never "breaks."

## Explicitly not supported yet
Macros (`$name`), field references (`${frame.time_relative}`), arithmetic
operators (`+ - * /`) between fields, the layer operator (`ip.addr#2`), and
the raw/`@` operator. These are rejected with a clear error rather than
silently mis-evaluated.
