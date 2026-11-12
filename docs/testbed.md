# Windows test bed (replaces netns + netem)

The team has no Linux/VM, so the Section 6 test bed is rebuilt in pure Python
(risk R1 in the Submission 1 report: "user-space impairment proxy").

| Linux plan                      | Windows replacement                     |
|---------------------------------|-----------------------------------------|
| ns-client / ns-server + veth    | two terminals on 127.0.0.1              |
| `tc netem` delay/loss/dup/...   | `testbed/impair_proxy.py`               |
| `ping` through netem            | `testbed/probe.py` (UDP probe)          |
| UDP echo peer                   | `testbed/echo_server.py`                |
| tcpdump / Wireshark on veth     | Wireshark + Npcap "Adapter for loopback traffic capture" |

Topology: `client -> proxy (5006) -> server (5005)`; replies come back the
same way. Each direction is impaired independently, so `--delay 50` gives
RTT ~ 100 ms and `--loss p` gives round-trip loss 1-(1-p)^2.

## Feasibility checks (run each in its own PowerShell window)

1. Clean path
   `python testbed\echo_server.py --port 5005`
   `python testbed\impair_proxy.py --listen 127.0.0.1:5006 --target 127.0.0.1:5005`
   `python testbed\probe.py --port 5006 --count 100`  -> expect 0 lost.
2. Delay: add `--delay 50` to the proxy -> expect RTT avg ~ 100 ms.
3. Loss: `--loss 10`, probe `--count 1000 --interval 0.002` -> expect ~19 % lost.
4. Wireshark: capture on the loopback adapter, filter `udp.port == 5005 || udp.port == 5006`;
   100 datagrams visible, first 4 payload bytes = sequence number.

## Known limitations
* Windows timer resolution is ~1-15 ms, so delays below ~15 ms are approximate.
* The proxy is Python: it will not sustain very high packet rates, so measure
  a no-delay run first and only trust results below that ceiling.
* Corruption is injected by the proxy, so the CRC check really is exercised.
* Loopback has no real bandwidth limit; use `--rate-mbps` to emulate one.
