# CR-18 / Module 3 / N3a — Basic ARP Poisoning

CADMUS Cyber Range scenario. Layer-two man-in-the-middle on a single LAN segment: a host periodically reaches for an unowned address, the trainee answers its ARP requests with a lie, and reads the flag off the captured connection.

## Topology

A single `192.168.25.0/24` segment behind one router (gateway), with the standard `100.100.100.0/24` WAN. The decoy address `192.168.25.99` is unassigned.

| Node   | Image                  | IP             | Role |
| ------ | ---------------------- | -------------- | ---- |
| router | debian-12-x86_64       | 192.168.25.1   | LAN gateway, present so the platform can reach the LAN through its standard mgmt path. Not involved in the attack. |
| vm1    | ubuntu-noble-x86_64    | 192.168.25.10  | Periodically opens TCP to `192.168.25.99:4444` and writes the flag. |
| vma    | kali-2026.1-x86_64     | 192.168.25.20  | Trainee workstation. |

## Provisioning

`provisioning/playbook.yml` runs three plays:
- **vm1**: deploys the local `arp-flag-broadcaster` role, which installs a `nc`-based emitter behind a systemd timer firing every 10 s.
- **vma**: provisions the trainee user `user` / `Password123` via `user-access`.
- **all hosts**: enables sandbox-side command logging via `sandbox-logging`.

The flag value comes from the `flag` APG variable defined in `variables.yml`, so each sandbox instance gets a different answer.

## Trainee workflow

1. Console or SSH into **vma** as `user` / `Password123`.
2. `tcpdump` the LAN interface; observe ARP requests for `192.168.25.99` going unanswered, on `tcp/4444`.
3. `arpspoof` to claim `192.168.25.99`, `nc -lvnp 4444` to receive what vm1 sends.
4. Submit the captured string as the flag.

## Tools used

`tcpdump`, `arpspoof` (from `dsniff`), `nc`. `bettercap` or `ettercap` work as alternatives to `arpspoof`.

## MITRE mapping

- `T1557.002` — Adversary-in-the-Middle: ARP Cache Poisoning
- `T1040` — Network Sniffing
- `T1046` — Network Service Discovery
