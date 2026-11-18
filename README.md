# TP-Link TL-SG108E v4: comprehensive guarded MCP

**Target:** TL-SG108E hardware 6.0, firmware `1.0.0 Build 20230218`, management address `<switch-ip>`, connected to UniFi gateway on switch **port 1**. This project wraps the `tplink-tool` Python SDK. It has been checked with offline tests; **no live switch writes have been executed**.

## Purpose

All supported, documented software-management operations are exposed through a **general-purpose** preview/apply interface. Nothing is tied to VLAN 30 or to a particular switch port except the protected gateway-uplink rules.

### Existing reads (retained)

`switch_identity`, `switch_ports`, `switch_vlans`, `switch_port_counters`, `switch_health_snapshot`, `switch_extended_config`, `switch_vlan_port_matrix`, `switch_config_backup`, `switch_config_drift`, `switch_preview_port_change`.

### v4 tools (new)

- `switch_capabilities()` — enumerate supported operations, risk category and example argument objects.
- `switch_preview_change(operation, parameters)` — validate, inspect, return before/after diff and a short-lived `change_id`. **Read-only.**
- `switch_apply_change(change_id, confirm=true, disruption_acknowledged=true|false)` — execute only the exact, current, previously reviewed preview. Requires explicit user approval of **that specific preview**; a generic request for write access is not sufficient.

Supported operations cover system description, LEDs, ports and flow control, packet counter reset, mirroring, LAG groups, IGMP snooping and report suppression, loop prevention, VLAN creation/update/deletion, port access/hybrid profiles and PVID, QoS mode/priority, bandwidth rate limits, storm control, MTU VLAN, port-based VLANs, 802.1Q mode, management IP/DHCP, reboot, backup restore, factory reset, password rotation, and save-config. Use `switch_capabilities()` to see the exact operation names and example `parameters` for each.

**Not working / unsupported:** firmware upload is not implemented in the underlying SDK; TDR cable diagnostics are broken on this switch's 2023 firmware and are intentionally not presented as reliable. The hardware has no PoE and no Omada adoption support.

## Safety

- Binds ONLY to `127.0.0.1:8765/mcp`; reuses the existing authenticated OpenAI tunnel.
- Exact switch MAC/hardware/firmware verified before write; no raw HTTP, shell or arbitrary SDK method tool.
- Gateway port 1: must stay on VLAN 1 untagged, PVID 1, administratively enabled with auto negotiation. Tags for other VLANs may be added by explicit preview.
- Every write: fresh preview (expires in 10 minutes), single-use token, live state recheck, local private binary backup, audit record; read-back checks for non-disruptive actions.
- High-risk operations require `disruption_acknowledged=true` **in addition to** explicit user approval.
- Critical operations (management IP/DHCP, switching VLAN modes, factory reset, reboot, config restore, password rotation, and gateway-uplink rate limiting) additionally need a local 10-minute unlock on the Pi. The unlock is single-use after a successful authorization.
- Switch auto-saves every write immediately. **Backups are not an automatic rollback**. If a VLAN change disconnects management, hands-on recovery may be required. If an operation fails mid-sequence, treat it as partially applied.
- Passwords and binary configuration backups remain private under `~/.config/tplink-mcp/` with restrictive permissions; never paste them into ChatGPT.
- Potential firmware behavior and read-back differences mean writes require careful initial testing on noncritical ports. Mode changes, IP changes and reset/restore are not remotely verified end-to-end.

## Install

1. Copy this repo to the host that runs the MCP (e.g. `git clone` or `scp`), then SSH in.
2. Tell the server which switch to manage. Values are kept outside the repo, in
   `~/.config/tplink-mcp/` (or the `TPLINK_SWITCH_HOST` / `TPLINK_SWITCH_MAC` environment variables):

   ```sh
   mkdir -p ~/.config/tplink-mcp && chmod 700 ~/.config/tplink-mcp
   echo '<switch-ip>'  > ~/.config/tplink-mcp/host
   echo '<switch-mac>' > ~/.config/tplink-mcp/mac   # e.g. AA:BB:CC:DD:EE:FF; writes are refused without it
   ```
3. Install:

   ```sh
   bash install_v4.sh
   systemctl --user is-active tplink-mcp.service
   systemctl --user is-active openai-tplink-tunnel.service
   ```
4. Refresh the **existing** TP-Link custom MCP in ChatGPT; do **not** create a new tunnel. Then ask `Call switch_capabilities on my TP-Link MCP.`

The installer only checks Python syntax, reads switch identity, backs up the old **server code**, replaces it and restarts the MCP. It does not modify switch configuration.

## Example of general VLAN workflow

To add tagged VLAN 30 to the gateway uplink while keeping VLAN 1/PVID1:

1. Ask for the live VLAN membership via `switch_vlans()`.
2. Use `switch_preview_change(operation="set_8021q_vlan", parameters={"vlan_id":30,"tagged_ports":[1,2,3,4,5],"untagged_ports":[]})`. **Full VLAN membership must be provided**; omitting a member removes it.
3. Review the exact before/after and connectivity implications. Only after explicit user approval call `switch_apply_change(change_id=..., confirm=true, disruption_acknowledged=true)`.
4. Re-read switch VLANs and validate connectivity of both management interface and affected devices. No smart-home hubs should be moved at the same time.

For another VLAN, supply its ID and actual live membership. The same generic tool handles it.

## Critical recovery/maintenance

Use your Pi SSH terminal to grant one-time temporary permission:

```sh
~/tplink-env/bin/python ~/.local/share/tplink-mcp/server.py --unlock-critical
```

Type the exact safety phrase shown. Then preview and explicitly approve your change in ChatGPT. Lock again immediately if you do not proceed:

```sh
~/tplink-env/bin/python ~/.local/share/tplink-mcp/server.py --lock-critical
```

For `rotate_password`, **stage the new password privately** first:

```sh
~/tplink-env/bin/python ~/.local/share/tplink-mcp/server.py --stage-password
```

Then local unlock + preview/apply. The new password will not be transmitted in MCP arguments or returned over the tunnel. Switch management IP changes may require manually updating the Pi's saved host address if the switch becomes unreachable.

## Diagnostics / testing

The included `test_v4.py` runs offline without `mcp` or `tplink-tool` installed, using mocks. It cannot prove the real hardware accepts each write. The installer's `--self-test` is **read-only**.

```sh
python3 ~/tplink-mcp-v4/test_v4.py
```

The previous MCP source is saved as `server.py.pre-v4-TIMESTAMP`. If the service fails to start, the installer restores it automatically. It does not roll back switch hardware settings.
