# Enforcing DNS Egress Control on a Segmented Home Network

*A practical exercise in auditing firewall intent vs. implementation, closing IPv6 blind spots, and building self-healing DNS policy on MikroTik RouterOS.*

> All addresses, prefixes, and identifiers in this post are sanitized examples
> (RFC 1918 / RFC 3849 documentation ranges). The architecture and lessons are real.

## Why DNS is worth controlling

DNS is the quietest chokepoint on a network. Every device asks it where to go before
doing almost anything else, which makes it three things at once: a **policy enforcement
point** (ad and malware domain filtering, local split-horizon zones), a **telemetry
source** (who is resolving what), and — if you leave it open — a **bypass and
exfiltration channel**. Malware families tunnel data out over DNS queries precisely
because port 53 is so rarely restricted outbound. IoT gear routinely ships with
hardcoded public resolvers (8.8.8.8 is baked into a shocking amount of firmware),
silently ignoring whatever your DHCP server hands out.

If your filtering resolver can be bypassed, it isn't a security control. It's a suggestion.

## The starting point: rules that had never matched a packet

The trigger for this project was an audit of existing port-53 firewall rules on a
MikroTik router. The findings were humbling in a way that generalizes:

**Every DNS drop rule on the router had zero hits.** Not "few" — zero, months after
creation. The byte and packet counters told the story instantly. The rules *looked*
right in the WinBox table view, but the matchers encoded the wrong intent:

- WAN-inbound drops used `src-address-list=dns` — a list containing **internal**
  resolver IPs. Internet traffic never arrives sourced from your own RFC 1918
  addresses (nothing legitimate does, anyway), so the rules could never match.
  The author almost certainly meant `dst-address-list`.
- Egress-blocking rules sat in the **output** chain, which only sees traffic the
  router itself originates. Blocking *clients* from bypassing the resolver is a
  **forward**-chain job. The rules were no-ops by construction.
- Meanwhile, the rules that *were* active (accepts for the resolvers' upstream
  queries) were redundant, because the forward chain's default policy accepted
  everything anyway — there was no drop behind them to make them meaningful.

**Lesson one: counters are ground truth.** A rule with zero hits after months is
either protecting against something that never happens, or it is broken. Audit for
*effect*, not for *presence*. `print stats` beats eyeballing the rule list every time.

**Lesson two: know your chains.** input = to the router, output = from the router,
forward = through the router. A correct-looking rule in the wrong chain fails silently,
and silence looks exactly like success.

## The design goal

The target policy, stated plainly:

1. Every device behind the firewall may only use the internal resolvers.
2. The DMZ has its own resolver; DMZ hosts use it and nothing else.
3. Every other VLAN uses the internal resolver VLAN's authoritative resolver.
4. Non-DMZ clients may **fall back** to the DMZ resolver — but *only* while the
   primary is actually down, not as a permanent second choice.
5. The resolvers themselves keep unrestricted access to their public upstreams.
6. The router keeps its own public resolvers for system tasks.

## Architecture: two tiers of resolvers, and why the distinction matters

Each resolver zone runs a two-tier stack:

- An **authoritative/filtering resolver** (Pi-hole-style) — this is what clients
  must talk to. It serves local DNS zones and applies blocklist filtering.
- **Unbound forwarder instances** behind it — these perform recursive/upstream
  resolution *on behalf of the filtering resolver only*.

This distinction produced the subtlest bug of the whole project. An early version of
the policy put the unbound forwarders in the client-reachable allow-list and the DHCP
server lists, since they are, after all, "DNS servers." That quietly re-opened the
exact hole the policy existed to close: a client that queried unbound directly would
**skip local-zone resolution and skip every blocklist** — full filter bypass, entirely
inside the "allowed" infrastructure.

**Lesson three: model roles, not just services.** Two boxes can speak identical
protocols and have completely different trust roles. The firewall's allow-list must
encode *who may be queried by whom*, not *what runs DNS*. The fix was a dedicated
`dns-auth` address list containing only the client-facing authoritative resolvers,
distinct from the broader exemption list used for the resolvers' own upstream egress.

## Enforcement: drops with surgical exemptions

RouterOS's forward chain here is default-accept, so the policy is expressed as
targeted drop rules (sanitized addressing; full rule set in the appendix):

- **DMZ clients** (`172.16.10.0/24`): drop UDP/TCP 53 (and TCP 853) to anything
  except the DMZ authoritative resolver.
- **All other internal clients** (`10.0.0.0/16`): drop 53/853 to anything not in
  `dns-auth` — the two authoritative resolvers, and nothing else.
- **Fallback gate**: an additional, *toggleable* drop blocks non-DMZ clients from
  the DMZ resolver. While the primary resolver is healthy, this rule is enabled and
  fallback is closed. (More below.)
- **Source exemptions**: every drop carries `src-address-list=!dns` so the resolver
  infrastructure — including the unbound tier and the entire resolver VLAN — retains
  unrestricted upstream DNS/DoT egress. The resolvers can't do their job if the
  policy strangles them.
- **Router protection**: raw-table prerouting rules drop WAN-inbound dst-53
  unconditionally (cheap, pre-conntrack), and the router's DNS service refuses
  remote requests — no open-resolver exposure.

Blocking TCP 853 alongside 53 closes the trivial DNS-over-TLS bypass. DNS-over-HTTPS
is the honest caveat: it rides port 443 and cannot be blocked by port. That fight
happens at the filtering resolver (blocking known DoH endpoints) and endpoint policy,
not the packet filter.

## The part everyone forgets: IPv6

The first version of any DNS lockdown is usually IPv4-only. This network had global
IPv6 on **every** VLAN via prefix delegation, with router advertisements handing out
resolver addresses. An IPv4-only policy would have been theater: any dual-stack client
could resolve via `2001:4860:4860::8888` and never touch a v4 rule.

The v6 policy mirrors v4 exactly — same allow-lists (`dns-auth6`, `dns-dmz6`), same
source exemptions, same toggleable fallback gate — and the RA (neighbor discovery)
DNS advertisements were realigned so every VLAN advertises its *assigned* resolver
first, with the fallback second, matching what DHCPv4 hands out.

**Lesson four: IPv6 parity is not optional.** Every egress control you write for v4
either exists for v6 or doesn't exist at all.

## Self-healing fallback: firewall rules driven by a health check

The requirement "fallback only while the primary is down" cannot be expressed in
static rules or resolver-list ordering — clients treat their DNS server list however
they like, and Windows in particular will happily latch onto a secondary forever.
Availability logic needs to live somewhere that can *measure* availability.

The solution is a scheduled RouterOS script that performs an actual DNS resolution
against the primary authoritative resolver every 30 seconds — not a ping. A resolver
can answer ICMP with its DNS service wedged; querying the service tests the thing
that matters. (First attempt used `mikrotik.com` as the probe name, which the
blocklists on the resolver itself happened to block — instructive failure. The probe
must be a name the resolver will actually answer.)

```routeros
# dns-fallback-check — runs every 30s from the scheduler
:local up false
:do {
    :resolve "example.com" server=10.0.53.2
    :set up true
} on-error={}
:if ($up) do={
    /ip   firewall filter enable  [find comment~"DNS fallback block"]
    /ipv6 firewall filter enable  [find comment~"DNS fallback block"]
    /ip   firewall nat enable  [find comment~"LAN DNS redirect primary"]
    /ipv6 firewall nat enable  [find comment~"LAN DNS redirect primary"]
    /ip   firewall nat disable [find comment~"LAN DNS redirect fallback"]
    /ipv6 firewall nat disable [find comment~"LAN DNS redirect fallback"]
} else={
    /ip   firewall filter disable [find comment~"DNS fallback block"]
    /ipv6 firewall filter disable [find comment~"DNS fallback block"]
    /ip   firewall nat disable [find comment~"LAN DNS redirect primary"]
    /ipv6 firewall nat disable [find comment~"LAN DNS redirect primary"]
    /ip   firewall nat enable  [find comment~"LAN DNS redirect fallback"]
    /ipv6 firewall nat enable  [find comment~"LAN DNS redirect fallback"]
}
```

Primary healthy → fallback gate closed → clients can only use their assigned
resolver. Primary down → gate opens within 30 seconds → clients fail over to the
DMZ resolver. Primary recovers → gate closes and forcibly herds clients back within
their retry timeout. The firewall becomes a small piece of self-healing automation
instead of a static wall.

## The incident: enforcement reveals what clients actually do

Minutes after the policy went live, every device in the DMZ lost DNS resolution
entirely. The resolver was healthy — the router could resolve through it on demand —
but the drop counters were climbing fast, with the IPv6 rule catching **three times**
the traffic of its v4 twin. Thirty seconds of packet logging on the drop rules
answered everything: DMZ hosts were querying the *router's own upstream resolvers*
over IPv6.

The chain of causation was entirely self-inflicted, and worth spelling out. The DMZ
VLAN's router advertisements had `advertise-dns=yes` with no explicit server list —
a configuration that advertises the **router's upstream resolvers** via RDNSS. So
for months, DMZ hosts had been silently learning public resolver addresses and using
them directly. The old DHCP scope compounding it listed the *other* zone's resolver
first. When enforcement landed, every resolver those hosts had ever learned was a
blocked destination, and nothing they had cached pointed at the one server they were
now allowed to use.

**Lesson five: clients do what they cached, not what you meant.** The pre-enforcement
network *looked* like it used the internal resolvers, because nothing measured
otherwise. The drop rules were the first instrument ever pointed at actual client
behavior, and the first thing they found was that the mental model was wrong. Expect
this: turning on egress enforcement is as much a discovery exercise as a control.

### The fix: transparent redirect, not wider allow rules

The tempting fix — loosening the drops until things work — would have re-opened the
bypass. The correct fix makes the policy *self-correcting*: **destination NAT**.
Any port-53 query from a client zone aimed at the wrong place is silently rewritten
to that zone's authoritative resolver. The client thinks its cached (or hardcoded)
server answered; the filtering resolver actually did. Resolution came back instantly,
policy intact, zero per-host reconfiguration — and devices with factory-hardcoded
DNS are covered forever. The same redirect was then extended to the internal VLANs.

Two design details matter. First, the resolver infrastructure is source-exempted
from the redirect, or the forwarders' own upstream recursion would be looped back
into the resolver they serve — instant resolution deadlock. Second, plain-53 gets
redirected but DoT (853) stays drop-only: you cannot transparently proxy a TLS
session without breaking its certificate validation, and a redirect that hands
clients certificate errors is worse than a clean refusal.

With redirects in place, the layered behavior becomes: **NAT fixes the traffic,
filter drops whatever NAT didn't catch, and the health check retargets both when
the primary fails.** The failover script now swaps the redirect target to the
fallback resolver during an outage, so even hardcoded devices fail over and fail
back without knowing any of it happened.

### The hairpin problem: when client and resolver share a subnet

The redirect worked immediately for internal VLANs — and silently did nothing for
the DMZ, where it mattered most. The reason is a classic NAT trap. When a DMZ client
queries `8.8.8.8` and the router rewrites the destination to the DMZ resolver, both
endpoints are on the *same subnet*. The resolver's reply goes straight back to the
client over layer 2 — it never re-crosses the router, so it never gets un-NATed. The
client, waiting on an answer from `8.8.8.8`, receives one from a neighbor it never
asked, and discards it. Queries flow, replies flow, resolution still fails, and not
a single firewall counter shows a drop.

The fix is **hairpin NAT**: masquerade the redirected flows on their way back into
the subnet, so the resolver replies to the router and the router restores both
addresses. RouterOS adds a wrinkle — the NAT table doesn't support the
`connection-nat-state` matcher, so you can't say "masquerade only the flows I
redirected" directly. The workaround is to mark those connections in **mangle**
(which does support the matcher) and masquerade by connection-mark. That precision
matters: masquerading *all* client-to-resolver traffic would erase per-client
identity on the filtering resolver's query logs. With the mark, only the redirected
flows lose it — and queries showing up as "from the router" become a free signal
that some device is misbehaving.

Two conntrack lessons surfaced while proving this worked:

- **NAT verdicts are cached per connection.** A flow that existed before the rule
  keeps its old (no-NAT) verdict for as long as it stays alive — and a client
  retrying from a fixed source port refreshes the entry forever. New rules don't
  apply until the stale entries are flushed.
- **IPv6 conntrack lives in its own table** (`/ipv6 firewall connection`). Flushing
  `/ip firewall connection` touches only v4 — easy to "flush everything" and wonder
  why v6 behavior didn't change.

Proof of health, end to end, is a conntrack entry with `SACsd` flags — seen-reply,
assured, srcnat, dstnat — and matched query/reply counts. One misbehaving DMZ device
showed 588 queries out, 587 answers back, to a public resolver it had cached weeks
earlier and that its packets never actually reached.

## The final twist: two bugs masking each other

With transport provably healthy, one DMZ device still failed every DNS-dependent
operation. The firewall logs stayed silent. The resolver's own dashboard broke the
case: **over half of all queries in the last hour had returned Server Failure.**
The network was delivering queries perfectly to a resolver that couldn't answer them.

The root cause was configuration archaeology. The resolver's upstream forwarders
were defined by *hostname*, and the A/AAAA records for those hostnames had at some
point been repointed at the local reverse proxy — a box that runs no DNS at all.
Every upstream query dead-ended. A resolver whose forwarders are hostnames has a
chicken-and-egg dependency: it must resolve a name to learn where to resolve names.

The uncomfortable part: this misconfiguration was **old**, and nothing had noticed —
because the broken hairpin had been routing DMZ client traffic *around* the resolver,
so the dead forwarder path was never exercised. Fixing the routing bug is what
surfaced the resolver bug. The new symptom wasn't a new fault; it was an old fault
finally being reached.

**Lesson six: forwarders are IPs. Non-negotiable.** A resolver should never need
DNS to bootstrap its own upstream path.

**Lesson seven: two bugs can mask each other.** When a fix appears to "cause" a new
failure, consider that it may have exposed one that predates it. And zero drops
never meant healthy — a transport that delivers queries flawlessly to a dead
upstream produces exactly the same user experience as a firewall eating packets.

## Making the easy path the compliant path

Enforcement without alignment produces a network full of mysterious timeouts. The
supporting layers were brought into agreement with the firewall:

- **DHCPv4** hands each VLAN its assigned authoritative resolver first, fallback
  second. The DMZ scope lists only its own resolver. The resolver VLAN's scope
  points at the public upstreams, since those hosts *are* the resolution path.
- **RA/ND (v6)** advertises the same assignment in the same order.
- The unbound forwarders appear in **no** client-facing list anywhere.

Defense in depth here means the layers *agree*: clients are told the right thing
(DHCP/RA), and the network enforces it anyway (firewall), and the enforcement adapts
to reality (health check).

## Change management: safe mode

Every change was applied inside RouterOS **safe mode**, which automatically rolls
back the entire change set if the management session drops — the config-management
equivalent of a dead man's switch. Firewalling the very network you're managing
through is exactly the scenario it exists for: a bad rule that cuts your session
also *undoes itself* within minutes. Changes were committed only after verifying
rule placement, counters, and a live run of the health-check script.

## Residual risks, stated honestly

No control is complete, and pretending otherwise is its own vulnerability:

- **DoH (port 443)** remains possible for determined clients; mitigation lives at
  the resolver blocklists and endpoint management, not the packet filter.
- **Hardcoded v6 addresses** in allow-lists and RAs sit inside a delegated prefix;
  if the ISP re-delegates, they need updating (a scripted job for another day).
- **Client stickiness**: failback is bounded by the 30s check interval plus client
  retry behavior; existing DHCP leases carry old resolver lists until renewal.
- **Spoofing**: source-list exemptions trust source addresses; RFC 1918 ingress
  filtering on WAN and per-VLAN isolation keep that assumption reasonable.

## Takeaways

1. **Audit by effect, not appearance.** Zero-hit counters are a finding, not noise.
2. **Chains and directions encode intent.** input/forward/output and src/dst
   confusion produce rules that fail silently.
3. **Role-model your infrastructure.** "Runs DNS" and "may be queried by clients"
   are different properties; the forwarder-bypass bug lived in that gap.
4. **IPv6 parity or nothing.** A v4-only egress policy on a dual-stack network is
   a false sense of security.
5. **Availability logic belongs in automation.** Health-checked, self-toggling
   rules express "only when down" — static configs can't.
6. **Align the layers.** DHCP, RA, and firewall telling the same story turns
   enforcement from friction into invisibility.
7. **Enforcement is discovery.** The first thing new drop rules catch is the gap
   between what you configured and what clients actually cached. Log before you
   loosen — the traffic tells you the real fix.
8. **Redirect beats relax.** When legitimate devices break against a correct
   policy, transparent DNAT to the compliant destination restores service without
   surrendering the control.
9. **Same-subnet NAT needs a hairpin.** Redirecting a client to a destination on
   its own subnet breaks silently unless the return path is forced back through
   the router — and stale conntrack verdicts (v4 *and* v6, separate tables) will
   hide the fix until flushed.
10. **Forwarders are IPs.** A resolver must never depend on DNS to find its own
    upstreams; hostname forwarders are a bootstrap deadlock waiting for a record
    change.
11. **Two bugs can mask each other.** Fixing one fault can surface another that
    predates it. Zero firewall drops with failing clients points at answer
    contents and upstream health, not the packet filter.
12. **Use the safety nets.** Safe mode turns risky remote firewall work into a
    recoverable experiment.

---

## Appendix: sanitized rule set

Example addressing used throughout:

| Zone | Subnet | Authoritative resolver | Unbound forwarders |
|---|---|---|---|
| Internal VLANs | `10.0.0.0/16` (per-VLAN /24s) | `10.0.53.2` | `10.0.53.3`, `10.0.53.4` |
| Resolver VLAN | `10.0.53.0/28` | — | — |
| DMZ | `172.16.10.0/24` | `172.16.10.2` | `172.16.10.3`, `172.16.10.4` |
| IPv6 (documentation) | `2001:db8::/48` per-VLAN /64s | `2001:db8:53::2` | `2001:db8:10::2` (DMZ) |

### Address lists

```routeros
/ip firewall address-list
add list=dns-auth address=10.0.53.2      comment="authoritative resolvers clients may use"
add list=dns-auth address=172.16.10.2    comment="authoritative resolvers clients may use"
add list=dns-dmz  address=172.16.10.2
add list=dns      address=10.0.53.2      # full resolver infra: src exemptions
add list=dns      address=10.0.53.3
add list=dns      address=10.0.53.4
add list=dns      address=172.16.10.2
add list=dns      address=172.16.10.3
add list=dns      address=172.16.10.4
add list=dns      address=10.0.53.0/28   comment="resolver VLAN may reach public resolvers"
```

### Filter rules (forward chain, before the WAN catch-all drop)

```routeros
/ip firewall filter
# resolvers' upstream egress (kept from original config)
add chain=forward action=accept protocol=udp src-address-list=dns dst-port=53
add chain=forward action=accept protocol=tcp src-address-list=dns dst-port=53,853

# DMZ clients: assigned resolver only, no fallback
add chain=forward action=drop protocol=udp dst-port=53     src-address=172.16.10.0/24 \
    src-address-list=!dns dst-address-list=!dns-dmz \
    comment="DNS policy: DMZ clients may only use DMZ resolvers"
add chain=forward action=drop protocol=tcp dst-port=53,853 src-address=172.16.10.0/24 \
    src-address-list=!dns dst-address-list=!dns-dmz \
    comment="DNS policy: DMZ clients may only use DMZ resolvers (tcp/DoT)"

# everyone else: authoritative resolvers only
add chain=forward action=drop protocol=udp dst-port=53     src-address=10.0.0.0/16 \
    src-address-list=!dns dst-address-list=!dns-auth \
    comment="DNS policy: internal clients -> local resolvers only"
add chain=forward action=drop protocol=tcp dst-port=53,853 src-address=10.0.0.0/16 \
    src-address-list=!dns dst-address-list=!dns-auth \
    comment="DNS policy: internal clients -> local resolvers only (tcp/DoT)"

# toggleable fallback gate (managed by dns-fallback-check)
add chain=forward action=drop protocol=udp dst-port=53     src-address=10.0.0.0/16 \
    src-address-list=!dns dst-address-list=dns-dmz comment="DNS fallback block v4 udp"
add chain=forward action=drop protocol=tcp dst-port=53,853 src-address=10.0.0.0/16 \
    src-address-list=!dns dst-address-list=dns-dmz comment="DNS fallback block v4 tcp"
```

### Raw table (router/edge hygiene)

```routeros
/ip firewall raw
add chain=prerouting action=drop protocol=udp in-interface-list=WAN dst-port=53
add chain=prerouting action=drop protocol=tcp in-interface-list=WAN dst-port=53
```

### IPv6 mirror (structure identical; interface-list scoped)

```routeros
/ipv6 firewall filter
add chain=forward action=drop protocol=udp dst-port=53     in-interface-list=DMZ \
    src-address-list=!dns6 dst-address-list=!dns-dmz6 comment="DNS policy v6: DMZ clients -> DMZ resolver only"
add chain=forward action=drop protocol=tcp dst-port=53,853 in-interface-list=DMZ \
    src-address-list=!dns6 dst-address-list=!dns-dmz6 comment="DNS policy v6: DMZ clients -> DMZ resolver only (tcp/DoT)"
add chain=forward action=drop protocol=udp dst-port=53     in-interface-list=!DMZ \
    src-address-list=!dns6 dst-address-list=!dns-auth6 comment="DNS policy v6: internal clients -> local resolvers only"
add chain=forward action=drop protocol=tcp dst-port=53,853 in-interface-list=!DMZ \
    src-address-list=!dns6 dst-address-list=!dns-auth6 comment="DNS policy v6: internal clients -> local resolvers only (tcp/DoT)"
add chain=forward action=drop protocol=udp dst-port=53     in-interface-list=!DMZ \
    src-address-list=!dns6 dst-address-list=dns-dmz6 comment="DNS fallback block v6 udp"
add chain=forward action=drop protocol=tcp dst-port=53,853 in-interface-list=!DMZ \
    src-address-list=!dns6 dst-address-list=dns-dmz6 comment="DNS fallback block v6 tcp"
```

### Health check + scheduler

```routeros
/system script add name=dns-fallback-check source=":local up false; :do {:resolve \"example.com\" server=10.0.53.2; :set up true} on-error={}; :if (\$up) do={/ip firewall filter enable [find comment~\"DNS fallback block\"]; /ipv6 firewall filter enable [find comment~\"DNS fallback block\"]} else={/ip firewall filter disable [find comment~\"DNS fallback block\"]; /ipv6 firewall filter disable [find comment~\"DNS fallback block\"]}"
/system scheduler add name=dns-fallback-check interval=30s on-event=dns-fallback-check
```

### Transparent redirects (dstnat; v6 mirror is structurally identical)

```routeros
/ip firewall nat
# DMZ zone: any misdirected query is answered by the DMZ resolver
add chain=dstnat action=dst-nat to-addresses=172.16.10.2 protocol=udp dst-port=53 \
    src-address=172.16.10.0/24 src-address-list=!dns dst-address=!172.16.10.2 \
    comment="DMZ DNS redirect (udp)"
add chain=dstnat action=dst-nat to-addresses=172.16.10.2 protocol=tcp dst-port=53 \
    src-address=172.16.10.0/24 src-address-list=!dns dst-address=!172.16.10.2 \
    comment="DMZ DNS redirect (tcp)"

# internal zone: normally redirected to the primary...
add chain=dstnat action=dst-nat to-addresses=10.0.53.2 protocol=udp dst-port=53 \
    src-address=10.0.0.0/16 src-address-list=!dns dst-address=!10.0.53.2 \
    comment="LAN DNS redirect primary (udp)"
add chain=dstnat action=dst-nat to-addresses=10.0.53.2 protocol=tcp dst-port=53 \
    src-address=10.0.0.0/16 src-address-list=!dns dst-address=!10.0.53.2 \
    comment="LAN DNS redirect primary (tcp)"
# ...with a disabled twin aimed at the fallback, toggled by the health check
add chain=dstnat action=dst-nat to-addresses=172.16.10.2 protocol=udp dst-port=53 \
    src-address=10.0.0.0/16 src-address-list=!dns dst-address=!172.16.10.2 \
    disabled=yes comment="LAN DNS redirect fallback (udp)"
add chain=dstnat action=dst-nat to-addresses=172.16.10.2 protocol=tcp dst-port=53 \
    src-address=10.0.0.0/16 src-address-list=!dns dst-address=!172.16.10.2 \
    disabled=yes comment="LAN DNS redirect fallback (tcp)"
```

Note: DoT (853) is intentionally *not* redirected — TLS cannot be transparently
re-targeted without certificate failures — so it remains drop-only in the filter.

### Hairpin NAT for same-subnet redirects (DMZ; v6 mirror identical)

```routeros
# mark redirected flows in mangle (NAT table lacks the connection-nat-state matcher)
/ip firewall mangle
add chain=forward action=mark-connection new-connection-mark=dmz-dns-hairpin \
    passthrough=no connection-state=new connection-nat-state=dstnat \
    protocol=udp dst-port=53 dst-address=172.16.10.2 in-interface=vlan-dmz \
    comment="mark redirected DMZ DNS (udp)"
add chain=forward action=mark-connection new-connection-mark=dmz-dns-hairpin \
    passthrough=no connection-state=new connection-nat-state=dstnat \
    protocol=tcp dst-port=53 dst-address=172.16.10.2 in-interface=vlan-dmz \
    comment="mark redirected DMZ DNS (tcp)"

# masquerade only the marked flows so replies return via the router
/ip firewall nat
add chain=srcnat action=masquerade connection-mark=dmz-dns-hairpin \
    out-interface=vlan-dmz comment="DMZ DNS redirect hairpin"
```

After adding these, flush stale port-53 conntrack entries in **both** tables —
`/ip firewall connection` and `/ipv6 firewall connection` — or pre-existing flows
keep their cached no-NAT verdicts indefinitely.

### DHCP alignment

```routeros
/ip dhcp-server network
set [find address=172.16.10.0/24] dns-server=172.16.10.2            # DMZ: own resolver only
set [find address=10.0.53.0/28]   dns-server=<public upstreams>      # resolver VLAN: needs to get out
# all other scopes:
#   dns-server=10.0.53.2,172.16.10.2                                 # primary first, fallback second
```

*Written up from a live hardening session on RouterOS 7.*
