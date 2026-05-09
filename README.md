# CR-18 / Module 3 / N3a — Basic ARP Poisoning

CADMUS Cyber Range scenario. Layer-two man-in-the-middle on a single LAN segment: a host periodically reaches for an unowned address, the trainee answers its ARP requests with a lie, and reads the flag off the captured connection.

## Topology

A single `192.168.25.0/24` segment behind one router with a `10.10.10.0/24` WAN. The decoy address `192.168.25.99` is unassigned.

| Node   | Image                  | IP             | Role |
| ------ | ---------------------- | -------------- | ---- |
| router | debian-12-x86_64       | 192.168.25.1   | LAN gateway. Not involved in the attack. |
| vm1    | ubuntu-noble-x86_64    | 192.168.25.10  | Periodically opens TCP to `192.168.25.99:4444` and writes the flag. |
| vma    | kali-2026.1-x86_64     | 192.168.25.20  | Trainee workstation. |

## Provisioning

`provisioning/playbook.yml` runs two plays:
- **vm1**: installs `netcat-openbsd`, drops a flag-emitter script + systemd service + 10 s timer that periodically writes the flag to `192.168.25.99:4444`.
- **vma**: provisions the trainee user `user` / `Password123` (sudo enabled) via the `user-access` role.

The flag value comes from the `flag` APG variable in `variables.yml` (`type: password`, length 16, no braces or quotes). The emitter wraps it as `CADMUS{<flag>}` on the wire so the captured string looks like a flag. The trainee submits only the inner value because `training.json` uses `answer_variable_name: flag`, so the platform compares against the raw APG output.

## Trainee workflow

1. Console or SSH into **vma** as `user` / `Password123`.
2. `tcpdump` the LAN interface (`eth1` on Kali) and confirm vm1 is ARP-requesting `192.168.25.99` on `tcp/4444` with no replies.
3. `arpspoof` to push forged ARP replies claiming `192.168.25.99` is at vma's MAC.
4. `ip addr add 192.168.25.99/32 dev eth1` so the kernel will accept packets destined for the spoofed IP.
5. `nc -lvnp 4444` to receive the connection from vm1.
6. The captured line looks like `CADMUS{<value>}`; submit just `<value>`.

## Tools used

`tcpdump`, `arpspoof` (from `dsniff`), `nc`. `bettercap` or `ettercap` work as alternatives to `arpspoof`.

## MITRE mapping

- `T1557.002` Adversary-in-the-Middle / ARP Cache Poisoning
- `T1040` Network Sniffing
- `T1046` Network Service Discovery
