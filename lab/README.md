# 🧪 Lab Kit — Packet Tracer untuk LogAnalyzer_V1

File `.pkt` tidak bisa di-generate di luar Packet Tracer (format binary proprietary),
jadi kit ini berisi **config siap-paste** — rakit topologi ±5 menit.

## Topologi (drag & drop di PT)

```
[PC1]──Fa0/1┐
            ├──[SW1 2960]──Gi0/1══Gi0/1──[SW2 2960]──Fa0/1──[SRV1 Syslog Server]
[PC2]──Fa0/2┘                                                    192.168.1.10
```

| Device | Type di PT | IP |
|---|---|---|
| SW1 | Switch 2960 | 192.168.1.2 (VLAN 10) |
| SW2 | Switch 2960 | 192.168.1.3 (VLAN 10) |
| SRV1 | Server-PT | **192.168.1.10** /24 (static, tab Desktop → IP Configuration) |
| PC1/PC2 | PC (opsional) | DHCP tidak aktif — set static 192.168.1.11/12 /24 |

Kabel: copper straight-through untuk PC→SW dan SW→Server, **copper cross-over** (atau auto-MDIX di PT versi baru) untuk SW1↔SW2.

## Setup steps

1. **SRV1**: Desktop → IP Configuration → static `192.168.1.10 / 255.255.255.0`
2. **SRV1**: Services → **Syslog → On** ✅
3. **SW1**: klik → CLI → `enable` → `configure terminal` → paste isi `01_SW1_config.txt`
4. **SW2**: sama, paste `02_SW2_config.txt`
5. Verify: di SW1 → `ping 192.168.1.10` harus reply
6. Test syslog jalan: `send log 6 test` di SW1 → pesan muncul di panel Syslog SRV1

## Jalankan skenario

Lihat `03_scenarios.txt` — 5 skenario: port flapping, login failure,
STP change, duplex mismatch, device down. Setiap skenario menghasilkan
log Cisco asli → copy dari panel Syslog → paste ke LogAnalyzer UI.

## Simpan

File → Save As → `LogAnalyzer_Lab.pkt` — sekali rakit, dipakai terus.
