#!/usr/bin/env python3
"""TP-Link TL-SG108E v4 MCP: comprehensive guarded management for TL-SG108E.

Writes require a live preview, a short-lived token, explicit confirmation,
a private local backup, identity checks, and read-back verification.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import enum
import json
import os
import pathlib
import shutil
import sys
import tempfile
import threading
from contextlib import contextmanager
from typing import Any, Iterator

from mcp.server.fastmcp import FastMCP
from tplink_tool import make_switch

# Site-specific values live outside the repo: env vars, or files in ~/.config/tplink-mcp/.
HOST = os.environ.get('TPLINK_SWITCH_HOST', '192.168.0.1')  # TL-SG108E factory default
HOST_FILE = pathlib.Path.home() / '.config' / 'tplink-mcp' / 'host'
_MAC_FILE = pathlib.Path.home() / '.config' / 'tplink-mcp' / 'mac'
# Writes are refused unless the live switch MAC matches this pin; empty means never match.
EXPECTED_MAC = (os.environ.get('TPLINK_SWITCH_MAC') or (_MAC_FILE.read_text().strip() if _MAC_FILE.is_file() else '')).upper()
ROOT = pathlib.Path.home() / '.config' / 'tplink-mcp'
PASSWORD_PATH = ROOT / 'password'
BACKUP_DIR = ROOT / 'backups'
BASELINE_PATH = ROOT / 'baseline-v2.json'
PORT = 8765
LOCK = threading.RLock()

mcp = FastMCP('TP-Link TL-SG108E (guarded v4)', host='127.0.0.1',
              port=PORT, stateless_http=True, json_response=True)


def _host() -> str:
    return HOST_FILE.read_text().strip() if HOST_FILE.is_file() else HOST


def _password() -> str:
    password = PASSWORD_PATH.read_text(encoding='utf-8').rstrip('\r\n')
    if not password:
        raise RuntimeError('Switch password is empty')
    return password


@contextmanager
def switch() -> Iterator:
    # Avoid overlapping management sessions when tools execute concurrently.
    with LOCK:
        with make_switch(_host(), password=_password()) as sw:
            ident = sw.get_system_info()
            if ident.mac.upper() != EXPECTED_MAC:
                raise RuntimeError('Switch identity mismatch; refusing to operate')
            yield sw


def _jsonable(value: Any) -> Any:
    if isinstance(value, enum.Enum):
        return value.name
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: _jsonable(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _bits(mask: int, count: int = 8) -> list[int]:
    return [x + 1 for x in range(count) if mask & (1 << x)]


def _speed(s: Any) -> str:
    return 'down' if s is None else getattr(s, 'name', str(s))


def _identity(sw: Any) -> dict:
    x = sw.get_system_info()
    return dict(description=x.description, mac=x.mac, ip=x.ip,
                netmask=x.netmask, gateway=x.gateway, firmware=x.firmware,
                hardware=x.hardware)


def _ports(sw: Any) -> list[dict]:
    return [dict(port=p.port, admin_enabled=p.enabled,
                 configured_speed=_speed(p.speed_cfg),
                 negotiated_speed=_speed(p.speed_act),
                 flow_control_configured=p.fc_cfg, flow_control_active=p.fc_act,
                 link_up=p.speed_act is not None,
                 trunk_id=getattr(p, 'trunk_id', 0))
            for p in sw.get_port_settings()]


def _vlans(sw: Any) -> dict:
    active, entries = sw.get_dot1q_vlans()
    pvids = sw.get_pvids()
    return dict(dot1q_enabled=active,
                vlans=[dict(id=v.vid, name=v.name,
                            tagged_ports=_bits(v.tagged_members),
                            untagged_ports=_bits(v.untagged_members))
                       for v in entries],
                port_pvids={str(i): vid for i, vid in enumerate(pvids, 1)})


def _counters(sw: Any) -> list[dict]:
    return [dict(port=p.port, tx_packets=p.tx_pkts, rx_packets=p.rx_pkts)
            for p in sw.get_port_statistics()]


def _try_read(sw: Any, operation: str) -> dict:
    try:
        return {'available': True, 'data': _jsonable(getattr(sw, operation)())}
    except Exception as e:
        # Avoid exposing raw switch HTTP login responses, cookies, or secrets.
        return {'available': False, 'error_type': type(e).__name__}


def _extra(sw: Any) -> dict:
    return {
        'ip_settings': _try_read(sw, 'get_ip_settings'),
        'led': _try_read(sw, 'get_led'),
        'port_mirror': _try_read(sw, 'get_port_mirror'),
        'link_aggregation': _try_read(sw, 'get_port_trunk'),
        'igmp_snooping': _try_read(sw, 'get_igmp_snooping'),
        'loop_prevention': _try_read(sw, 'get_loop_prevention'),
        'mtu_vlan': _try_read(sw, 'get_mtu_vlan'),
        'port_based_vlans': _try_read(sw, 'get_port_vlan'),
        'qos': _try_read(sw, 'get_qos_settings'),
        'bandwidth_control': _try_read(sw, 'get_bandwidth_control'),
        'storm_control': _try_read(sw, 'get_storm_control'),
    }


def _inventory(sw: Any) -> dict:
    # Excludes volatile counters, so normal network traffic doesn't cause drift.
    return {'identity': _identity(sw), 'ports': _ports(sw),
            'vlans': _vlans(sw), 'extended': _extra(sw)}


def _canonical_inventory(sw: Any) -> dict:
    # Operational link state should not count as configuration drift.
    inv = _inventory(sw)
    for p in inv['ports']:
        p.pop('negotiated_speed', None)
        p.pop('link_up', None)
        p.pop('flow_control_active', None)
    return inv


def _save_private(path: pathlib.Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    fd, tmp = tempfile.mkstemp(prefix='.tmp-', dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _backup(sw: Any) -> dict:
    data = sw.backup_config()
    if not isinstance(data, bytes) or not 0 < len(data) < 5_000_000:
        raise RuntimeError('Unexpected backup response; no file saved')
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    path = BACKUP_DIR / ('switch-' + stamp + '-' + os.urandom(3).hex() + '.bin')
    _save_private(path, data)
    return {'saved_locally': True, 'filename': path.name, 'bytes': len(data),
            'contains_sensitive_data': True,
            'note': 'Backup never returned over MCP; stored on the Raspberry Pi.'}


def _get_baseline() -> dict | None:
    if not BASELINE_PATH.is_file():
        return None
    data = json.loads(BASELINE_PATH.read_text(encoding='utf-8'))
    if data.get('identity_mac') != EXPECTED_MAC:
        raise RuntimeError('Baseline belongs to another switch')
    return data


def _changes(before: Any, after: Any, prefix: str = '') -> list[dict]:
    if before == after:
        return []
    if isinstance(before, dict) and isinstance(after, dict):
        changes = []
        for k in sorted(set(before) | set(after)):
            changes += _changes(before.get(k, '<missing>'), after.get(k, '<missing>'),
                                f'{prefix}.{k}' if prefix else k)
        return changes
    # One difference for a list, to avoid unbounded output.
    return [{'field': prefix, 'baseline': before, 'current': after}]


def _matrix(sw: Any) -> dict:
    data = _vlans(sw)
    rows = []
    for port in range(1, 9):
        tagged = [v['id'] for v in data['vlans'] if port in v['tagged_ports']]
        untagged = [v['id'] for v in data['vlans'] if port in v['untagged_ports']]
        pvid = data['port_pvids'][str(port)]
        rows.append(dict(port=port, pvid=pvid, tagged=tagged, untagged=untagged,
                         pvid_in_untagged=pvid in untagged))
    return dict(dot1q_enabled=data['dot1q_enabled'], ports=rows,
                caution='Port mapping and upstream VLAN settings must also be checked; membership alone does not prove end-to-end reachability.')


@mcp.tool()
def switch_identity() -> dict:
    """Read switch model, MAC, management address, firmware and hardware revision."""
    with switch() as sw:
        return _identity(sw)


@mcp.tool()
def switch_ports() -> list[dict]:
    """Read admin state, physical link and negotiated speed on all eight ports."""
    with switch() as sw:
        return _ports(sw)


@mcp.tool()
def switch_vlans() -> dict:
    """Read 802.1Q tagged/untagged memberships and per-port PVIDs."""
    with switch() as sw:
        return _vlans(sw)


@mcp.tool()
def switch_port_counters() -> list[dict]:
    """Read per-port packet counters, not throughput bytes or bandwidth."""
    with switch() as sw:
        return _counters(sw)


@mcp.tool()
def switch_health_snapshot() -> dict:
    """Read current links, VLANs and packet counters; 100 Mbps is not always a fault."""
    with switch() as sw:
        return {'ports': _ports(sw), 'vlans': _vlans(sw), 'counters': _counters(sw),
                'note': 'A 100-Mbps link may be normal for a Fast Ethernet device.'}


@mcp.tool()
def switch_extended_config() -> dict:
    """Read IP, LED, LAG, mirror, IGMP, loop prevention, QoS, storm and rate settings."""
    with switch() as sw:
        return _extra(sw)


@mcp.tool()
def switch_vlan_port_matrix() -> dict:
    """Explain each port's untagged/tagged VLANs and ingress PVID. Never writes."""
    with switch() as sw:
        return _matrix(sw)


@mcp.tool()
def switch_config_backup() -> dict:
    """Save raw binary switch backup privately on Pi; never expose backup contents."""
    with switch() as sw:
        return _backup(sw)


@mcp.tool()
def switch_config_drift() -> dict:
    """Compare current settings to locally approved baseline; excludes live link changes."""
    baseline = _get_baseline()
    if baseline is None:
        return {'baseline_exists': False,
                'instruction': 'On Pi: ~/tplink-env/bin/python ~/.local/share/tplink-mcp/server.py --capture-baseline'}
    with switch() as sw:
        current = _canonical_inventory(sw)
    differences = _changes(baseline['configuration'], current)
    return {'baseline_exists': True, 'baseline_time_utc': baseline['captured_at'],
            'has_drift': bool(differences), 'difference_count': len(differences),
            'differences': differences[:50], 'truncated': len(differences) > 50}


@mcp.tool()
def switch_preview_port_change(port: int, enabled: bool | None = None,
                               speed: str | None = None,
                               flow_control: bool | None = None) -> dict:
    """Preview potential consequences of changing port configuration. No apply tool exists."""
    if not 1 <= port <= 8:
        raise ValueError('Port must be between 1 and 8')
    valid = {'AUTO', 'M10H', 'M10F', 'M100H', 'M100F', 'M1000F'}
    if speed is not None and speed not in valid:
        raise ValueError('Invalid speed selection')
    with switch() as sw:
        ports, matrix = _ports(sw), _matrix(sw)
    current = ports[port - 1]
    membership = matrix['ports'][port - 1]
    risk = ('high' if current['link_up'] or membership['tagged'] else 'unknown')
    return {'requested': {'port': port, 'enabled': enabled, 'speed': speed,
                          'flow_control': flow_control},
            'current': current, 'membership': membership,
            'risk': risk, 'applied': False,
            'warning': 'Uplink/device mapping not verified. No remote write is permitted.'}


def _capture_baseline() -> dict:
    with switch() as sw:
        data = _canonical_inventory(sw)
    payload = {'captured_at': _now(), 'identity_mac': EXPECTED_MAC,
               'configuration': data}
    _save_private(BASELINE_PATH, json.dumps(payload, sort_keys=True, indent=2).encode())
    return {'baseline_saved': True, 'captured_at': payload['captured_at'],
            'location': str(BASELINE_PATH)}


def _local_led_change(turn_on: bool) -> dict:
    if not sys.stdin.isatty():
        raise RuntimeError('Requires a local interactive terminal')
    print('Local-only LED change. This does not change VLANs or link state.')
    print('Type APPLY to confirm or anything else to cancel: ', end='', flush=True)
    if input().strip() != 'APPLY':
        return {'applied': False, 'reason': 'cancelled'}
    with switch() as sw:
        backup = _backup(sw)  # abort if backup fails
        before = sw.get_led()
        if before != turn_on:
            sw.set_led(turn_on)
        after = sw.get_led()
    return {'applied': after == turn_on, 'before': before, 'after': after,
            'backup': backup['filename']}



# ---------------------------------------------------------------------
# General-purpose guarded administration. No arbitrary HTTP or shell APIs.
# ---------------------------------------------------------------------
import copy
import hashlib
import ipaddress
import re
import secrets
import time
from tplink_tool import PortSpeed, QoSMode, StormType

PENDING_PLAN = ROOT / 'pending-write-v4.json'
WRITE_AUDIT = ROOT / 'write-audit-v4.jsonl'
CRITICAL_UNLOCK = ROOT / 'critical-unlock-v4.json'
STAGED_PASSWORD = ROOT / 'new-switch-password'
PLAN_TTL = 600
CRITICAL_TTL = 600
VLAN_UPLINK = 1              # Gateway is on switch port 1.
MANAGEMENT_VLAN = 1          # Management is currently untagged VLAN 1.
APPROVED_FIRMWARE_BUILD = '20230218'

# Every hardware-supported operation except firmware flashing / TDR is here.
# CRITICAL commands are available but require an additional local unlock on the Pi.
SPECS = {
    'set_description': ('low', False, 'Rename the switch'),
    'set_leds': ('low', False, 'Enable or disable front-panel LEDs'),
    'set_ports': ('high', False, 'Set administrative state, speed and flow control'),
    'reset_counters': ('medium', False, 'Clear port packet counters'),
    'set_mirror': ('high', False, 'Configure ingress/egress port mirroring'),
    'set_lag': ('high', False, 'Configure static link aggregation group'),
    'set_igmp': ('medium', False, 'Set IGMP snooping and report suppression'),
    'set_loop_prevention': ('high', False, 'Enable or disable loop prevention'),
    'set_8021q_vlan': ('high', False, 'Create or fully update an 802.1Q VLAN'),
    'delete_8021q_vlan': ('high', False, 'Delete an unused 802.1Q VLAN'),
    'set_port_profile': ('high', False, 'Set one port PVID, untagged VLAN and tagged VLANs'),
    'set_pvid': ('high', False, 'Change ingress PVID on one or more access ports'),
    'set_qos_mode': ('medium', False, 'Switch QoS mode'),
    'set_qos_priority': ('medium', False, 'Set port QoS priority'),
    'set_bandwidth': ('high', False, 'Set port ingress and egress rate limits'),
    'set_storm': ('high', False, 'Set per-port broadcast/multicast/unknown-unicast storm control'),
    'set_mtu_vlan': ('critical', True, 'Enable/disable MTU VLAN mode (changes isolation)'),
    'set_port_vlan_mode': ('critical', True, 'Enable/disable mutually exclusive port-based VLAN mode'),
    'set_port_vlan': ('critical', True, 'Create/update port-based VLAN'),
    'delete_port_vlan': ('critical', True, 'Delete port-based VLAN'),
    'set_8021q_mode': ('critical', True, 'Enable/disable 802.1Q VLAN mode'),
    'set_ip': ('critical', True, 'Change switch management IP, gateway or DHCP'),
    'reboot': ('critical', True, 'Restart switch; connectivity interrupts'),
    'restore_backup': ('critical', True, 'Restore private config backup; switch reboots'),
    'factory_reset': ('critical', True, 'Erase switch configuration and reset'),
    'rotate_password': ('critical', True, 'Change switch password from locally staged secret'),
    'save_config': ('low', False, 'Persist configuration (no-op on this switch)'),
}


def _sha(data: object) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _p(port: int) -> int:
    if type(port) is not int or not 1 <= port <= 8:
        raise ValueError('Port must be 1 through 8')
    return port


def _ps(ports: object, allow_empty: bool = False) -> list[int]:
    if type(ports) is not list or (not ports and not allow_empty):
        raise ValueError('ports must be a list of unique port numbers')
    for port in ports:
        _p(port)
    if len(set(ports)) != len(ports):
        raise ValueError('duplicate port numbers')
    return sorted(ports)


def _vid(v: int) -> int:
    if type(v) is not int or not 1 <= v <= 4094:
        raise ValueError('VLAN ID must be 1-4094')
    return v


def _bool(x: object, name: str) -> bool:
    if type(x) is not bool:
        raise ValueError(f'{name} must be true/false')
    return x


def _integer(x: object, name: str, lo: int, hi: int) -> int:
    if type(x) is not int or not lo <= x <= hi:
        raise ValueError(f'{name} must be between {lo} and {hi}')
    return x


def _keys(args: dict, required: set[str], optional: set[str] = frozenset()) -> None:
    if not isinstance(args, dict) or not required <= set(args) or set(args) - required - optional:
        raise ValueError(f'Provide fields {sorted(required)}; optional {sorted(optional)}; no other fields')


def _vlans_map(v: dict) -> dict[int, dict]:
    return {x['id']: x for x in v['vlans']}


def _check_identity(sw: Any) -> None:
    i = _identity(sw)
    if i['hardware'] != 'TL-SG108E 6.0' or APPROVED_FIRMWARE_BUILD not in i['firmware']:
        raise RuntimeError('Firmware/hardware no longer matches write-tested TL-SG108E V6.0')
    if i['mac'].upper() != EXPECTED_MAC or i['ip'] != _host():
        raise RuntimeError('Switch identity or IP mismatch')


def _protected(sw: Any, op: str) -> dict:
    _check_identity(sw)
    v = _vlans(sw)
    p = _ports(sw)
    vlan1 = _vlans_map(v).get(MANAGEMENT_VLAN)
    if not p[0]['admin_enabled'] or p[0]['configured_speed'] != 'AUTO':
        raise RuntimeError('Gateway uplink is not enabled/auto; administrative writes halted')
    if not v['dot1q_enabled']:
        recovery={'set_8021q_mode','set_port_vlan_mode','set_mtu_vlan',
                  'restore_backup','factory_reset','set_ip','reboot'}
        if op not in recovery:
            raise RuntimeError('802.1Q mode is disabled; only critical recovery operations are allowed')
        return {'dot1q_enabled':False, 'switch_mac':EXPECTED_MAC,
                'port1_enabled':True, 'port1_speed':'AUTO'}
    if v['port_pvids']['1'] != MANAGEMENT_VLAN or not vlan1 or VLAN_UPLINK not in vlan1['untagged_ports']:
        raise RuntimeError('Unexpected management VLAN/PVID; administrative writes halted')
    return {'dot1q_enabled':True, 'vlan1_untagged_uplink': True, 'port1_pvid': 1,
            'port1_enabled': True, 'port1_speed': 'AUTO', 'switch_mac': EXPECTED_MAC}


def _state(sw: Any, op: str) -> Any:
    # Read only the relevant configuration fields; exclude volatile link and packet counters.
    if op in ('set_8021q_vlan','delete_8021q_vlan','set_port_profile','set_pvid','set_8021q_mode'):
        return _vlans(sw)
    if op == 'set_ports':
        return [{k:p[k] for k in ('port','admin_enabled','configured_speed','flow_control_configured')}
                for p in _ports(sw)]
    methods = {
        'set_description':lambda: _identity(sw)['description'],
        'set_leds':sw.get_led,
        'set_mirror':sw.get_port_mirror,
        'set_lag':sw.get_port_trunk,
        'set_igmp':sw.get_igmp_snooping,
        'set_loop_prevention':sw.get_loop_prevention,
        'set_mtu_vlan':sw.get_mtu_vlan,
        'set_port_vlan_mode':sw.get_port_vlan,
        'set_port_vlan':sw.get_port_vlan,
        'delete_port_vlan':sw.get_port_vlan,
        'set_qos_mode':sw.get_qos_settings,
        'set_qos_priority':sw.get_qos_settings,
        'set_bandwidth':sw.get_bandwidth_control,
        'set_storm':sw.get_storm_control,
        'set_ip':sw.get_ip_settings,
        'reset_counters':lambda: 'nonconfiguration_counter_reset',
        'reboot':lambda: 'device_reboot',
        'restore_backup':lambda: 'restore_private_backup',
        'factory_reset':lambda: 'factory_reset',
        'rotate_password':lambda: 'credential_rotation',
        'save_config':lambda: 'save_config',
    }
    return _jsonable(methods[op]())


def _normalized_vlans(v: dict) -> dict:
    x = copy.deepcopy(v)
    x['vlans'].sort(key=lambda z:z['id'])
    for z in x['vlans']:
        z['tagged_ports'].sort()
        z['untagged_ports'].sort()
    return x


def _check_vlan_output(before: dict, after: dict, op: str) -> None:
    # Preflight post-state against invariants. Operations that change VLAN mode
    # are only allowed with a local critical unlock.
    if op in ('set_8021q_mode','set_mtu_vlan','set_port_vlan_mode','set_port_vlan','delete_port_vlan'):
        return
    v1 = _vlans_map(after).get(1)
    if not v1 or 1 not in v1['untagged_ports'] or after['port_pvids']['1'] != 1:
        raise ValueError('Attempt would sever switch management on port 1')
    for port in range(1,9):
        ids = [v['id'] for v in after['vlans'] if port in v['untagged_ports']]
        tagids = [v['id'] for v in after['vlans'] if port in v['tagged_ports']]
        if len(ids) > 1 or set(ids)&set(tagids):
            raise ValueError('Conflicting VLAN membership on a port')
        # Preserve existing ingress reachability; validate new profile PVID.
        if op in ('set_port_profile','set_pvid') and after['port_pvids'][str(port)] not in ids:
            raise ValueError(f'Port {port}: PVID must be its untagged VLAN')
    for port in range(1, 9):
        pvid=after['port_pvids'][str(port)]
        untagged={z['id'] for z in after['vlans'] if port in z['untagged_ports']}
        if pvid not in untagged:
            raise ValueError(f'Port {port}: ingress PVID {pvid} is not untagged; use set_port_profile')
    if op == 'delete_8021q_vlan' and not after['dot1q_enabled']:
        raise ValueError('802.1Q disabled unexpectedly')


def _plan(op: str, args: dict, before: Any, protect: dict) -> dict:
    if op not in SPECS:
        raise ValueError('Unknown operation; use switch_capabilities')
    desired = copy.deepcopy(before)
    notes = []
    risk, critical, _ = SPECS[op]

    if op == 'set_description':
        _keys(args, {'description'})
        value = args['description']
        if type(value) is not str or not value or len(value.encode()) > 32:
            raise ValueError('description must be 1-32 UTF-8 bytes')
        desired = value
    elif op == 'set_leds':
        _keys(args, {'enabled'}); desired = _bool(args['enabled'],'enabled')
    elif op == 'set_ports':
        _keys(args, {'ports'}, {'enabled','speed','flow_control'})
        ports = _ps(args['ports'])
        if 1 in ports and (args.get('enabled') is False or args.get('speed') not in (None, 'AUTO')):
            raise ValueError('Cannot disable or force speed of port 1 gateway uplink')
        if not any(k in args for k in ('enabled','speed','flow_control')):
            raise ValueError('Provide a port setting')
        if 'speed' in args and args['speed'] not in PortSpeed.__members__:
            raise ValueError('speed must be PortSpeed enum name, e.g. AUTO or M1000F')
        for f in ('enabled','flow_control'):
            if f in args: _bool(args[f], f)
        for item in desired:
            if item['port'] in ports:
                for src, dst in [('enabled','admin_enabled'),('speed','configured_speed'),('flow_control','flow_control_configured')]:
                    if src in args: item[dst]=args[src]
        notes.append('Port operation may interrupt attached devices')
    elif op == 'set_8021q_vlan':
        _keys(args, {'vlan_id','tagged_ports','untagged_ports'}, {'name'})
        vid = _vid(args['vlan_id']); tagged=_ps(args['tagged_ports'],True); untagged=_ps(args['untagged_ports'],True)
        if set(tagged)&set(untagged): raise ValueError('Tagged and untagged ports overlap')
        if vid == 1:
            raise ValueError('VLAN1 is protected; use port profile to move non-uplink access ports')
        name=args.get('name')
        if name is not None and (type(name) is not str or len(name.encode())>32): raise ValueError('name max 32 bytes')
        current=_vlans_map(desired).get(vid)
        if not current:
            current={'id':vid,'name':name or '', 'tagged_ports':[],'untagged_ports':[]}
            desired['vlans'].append(current)
        elif name is None:
            name=current['name']
        current.update(name=name or '',tagged_ports=tagged,untagged_ports=untagged)
        # Never silently change another VLAN entry as a side effect.
        for port in untagged:
            existing_access = [z['id'] for z in desired['vlans']
                               if z['id'] != vid and port in z['untagged_ports']]
            if existing_access or desired['port_pvids'][str(port)] != vid:
                raise ValueError('Use set_port_profile to migrate untagged VLAN/PVID together')
        notes.append('Changes VLAN membership only; gateway port profile is managed separately')
    elif op == 'delete_8021q_vlan':
        _keys(args, {'vlan_id'}); vid=_vid(args['vlan_id'])
        if vid==1: raise ValueError('Cannot delete management VLAN')
        vlan=_vlans_map(desired).get(vid)
        if not vlan: raise ValueError('VLAN not found')
        if vid in desired['port_pvids'].values(): raise ValueError('Cannot delete VLAN used as a PVID')
        if 1 in vlan['tagged_ports']:
            raise ValueError('Removing a VLAN from protected uplink requires local recovery, not exposed here')
        desired['vlans']=[v for v in desired['vlans'] if v['id']!=vid]
    elif op == 'set_port_profile':
        _keys(args,{'port','untagged_vlan','tagged_vlans'})
        port=_p(args['port']); access=_vid(args['untagged_vlan']); tags=args['tagged_vlans']
        if port == 1: raise ValueError('Cannot reconfigure protected uplink profile')
        if type(tags) is not list: raise ValueError('tagged_vlans must be a list')
        tags=sorted(set(tags)) if len(tags)==len(set(tags)) else (_ for _ in ()).throw(ValueError('duplicate VLAN ID'))
        for v in tags: _vid(v)
        if access in tags:raise ValueError('Access VLAN also tagged')
        available=set(_vlans_map(desired))
        if access not in available or not set(tags)<=available:raise ValueError('Desired VLAN missing; create it first')
        if access != 1 and 1 not in _vlans_map(desired)[access]['tagged_ports']:
            raise ValueError('VLAN is not carried on gateway uplink port 1')
        for vlan in desired['vlans']:
            v=vlan['id']
            vlan['tagged_ports']=sorted((set(vlan['tagged_ports'])-{port})|({port} if v in tags else set()))
            vlan['untagged_ports']=sorted((set(vlan['untagged_ports'])-{port})|({port} if v==access else set()))
        desired['port_pvids'][str(port)]=access
        notes.append('Attached device may lose DHCP connectivity; verify upstream VLAN and recovery first')
    elif op == 'set_pvid':
        _keys(args,{'ports','vlan_id'})
        ports=_ps(args['ports']); vid=_vid(args['vlan_id'])
        if 1 in ports: raise ValueError('Gateway uplink PVID1 must remain 1')
        if vid not in _vlans_map(desired): raise ValueError('VLAN does not exist')
        for port in ports:
            if port not in _vlans_map(desired)[vid]['untagged_ports']:
                raise ValueError('PVID change only allowed if target VLAN is already untagged on port')
            desired['port_pvids'][str(port)]=vid
    elif op == 'set_mirror':
        _keys(args,{'enabled','dest_port','ingress_ports','egress_ports'})
        enabled=_bool(args['enabled'],'enabled'); dest=_p(args['dest_port'])
        ing=_ps(args['ingress_ports'],True); eg=_ps(args['egress_ports'],True)
        if enabled and (dest in set(ing+eg) or not (ing or eg)):
            raise ValueError('Mirror destination cannot also be a source; specify sources')
        if enabled and dest==1:raise ValueError('Gateway uplink cannot be mirror destination')
        desired={'enabled':enabled,'dest_port':dest,'mode':0 if ing and eg else 1 if ing else 2 if eg else 0,
                 'ingress_ports':ing,'egress_ports':eg}
    elif op == 'set_lag':
        _keys(args,{'group_id','ports'})
        group=_integer(args['group_id'],'group_id',1,2); ports=_ps(args['ports'],True)
        if 1 in ports:raise ValueError('Gateway uplink port 1 cannot be aggregated remotely')
        if ports and len(ports)<2:raise ValueError('LAG requires >=2 ports or empty list to delete')
        desired['groups'][str(group)] = ports
        if not ports: desired['groups'].pop(str(group),None)
    elif op == 'set_igmp':
        _keys(args,{'enabled','report_suppression'})
        desired['enabled']=_bool(args['enabled'],'enabled')
        desired['report_suppression']=_bool(args['report_suppression'],'report_suppression')
        desired.pop('group_count',None)  # group count is volatile, ignore during verification
    elif op == 'set_loop_prevention':
        _keys(args, {'enabled'});desired=_bool(args['enabled'],'enabled')
    elif op == 'set_qos_mode':
        _keys(args,{'mode'});mode=args['mode']
        if mode not in QoSMode.__members__:raise ValueError('mode: PORT_BASED, DOT1P, DSCP')
        desired[0]=mode
    elif op == 'set_qos_priority':
        _keys(args,{'ports','priority'}); ports=_ps(args['ports']); prio=_integer(args['priority'],'priority',1,4)
        for item in desired[1]:
            if item['port'] in ports: item['priority']=prio
    elif op == 'set_bandwidth':
        _keys(args,{'ports','ingress_kbps','egress_kbps'})
        ports=_ps(args['ports']); ing=_integer(args['ingress_kbps'],'ingress_kbps',0,1000000)
        eg=_integer(args['egress_kbps'],'egress_kbps',0,1000000)
        for item in desired:
            if item['port'] in ports:item.update(ingress_rate=ing,egress_rate=eg)
        if 1 in ports and (ing or eg):
            risk='critical';critical=True
            notes.append('Rate limiting the gateway uplink requires temporary local authorization')
    elif op == 'set_storm':
        _keys(args,{'ports','rate_index','storm_types'})
        ports=_ps(args['ports']); ri=_integer(args['rate_index'],'rate_index',0,12)
        types=args['storm_types']
        if type(types) is not list or len(set(types))!=len(types) or not set(types)<={'broadcast','multicast','unknown_unicast'}:
            raise ValueError('storm_types must contain broadcast/multicast/unknown_unicast')
        if bool(ri) != bool(types):raise ValueError('rate_index 0 and empty storm_types must be used together')
        bit={'broadcast':4,'multicast':2,'unknown_unicast':1}
        mask=sum(bit[t] for t in types)
        for item in desired:
            if item['port'] in ports:item.update(enabled=bool(ri),rate_index=ri,storm_types=mask)
        if 1 in ports and ri:
            risk='critical';critical=True
            notes.append('Rate limiting the gateway uplink requires temporary local authorization')
    elif op == 'reset_counters':
        _keys(args,set(),{'port'});
        if 'port' in args and args['port'] is not None: _p(args['port'])
    elif op == 'set_mtu_vlan':
        _keys(args,{'enabled'}, {'uplink_port'})
        enabled=_bool(args['enabled'],'enabled'); uplink=_p(args.get('uplink_port',1))
        if enabled and uplink!=1:raise ValueError('MTU VLAN gateway uplink must remain port 1')
        desired.update(enabled=enabled,uplink_port=uplink)
    elif op == 'set_port_vlan_mode':
        _keys(args,{'enabled'}); desired[0]=_bool(args['enabled'],'enabled')
    elif op == 'set_port_vlan':
        _keys(args,{'vlan_id','member_ports'});vid=_vid(args['vlan_id']);members=_ps(args['member_ports'])
        if 1 not in members:raise ValueError('Port-based VLAN must include protected gateway uplink')
        if not desired[0]:raise ValueError('Port-based VLAN mode not enabled; switching modes requires critical unlock')
        entries=desired[1]
        current=next((v for v in entries if v['vid']==vid),None)
        if current:current['members']=sum(1<<(p-1) for p in members)
        else:entries.append({'vid':vid,'members':sum(1<<(p-1) for p in members)})
    elif op == 'delete_port_vlan':
        _keys(args,{'vlan_id'});vid=_vid(args['vlan_id'])
        if vid==1:raise ValueError('Cannot delete default port VLAN')
        desired[1]=[v for v in desired[1] if v['vid']!=vid]
    elif op == 'set_8021q_mode':
        _keys(args,{'enabled'}); desired['dot1q_enabled']=_bool(args['enabled'],'enabled')
    elif op == 'set_ip':
        _keys(args, {'dhcp'}, {'ip','netmask','gateway'})
        _bool(args['dhcp'],'dhcp')
        for k in ('ip','netmask','gateway'):
            if k in args:
                if not isinstance(args[k],str):raise ValueError('IP field must be a string')
                ipaddress.IPv4Address(args[k])
                desired[k]=args[k]
        desired['dhcp']=args['dhcp']
        if args['dhcp']: notes.append('New DHCP address may be unknown; remote MCP might lose access')
        else: notes.append('Management address change can disconnect MCP; Pi host configuration will need update')
    elif op == 'rotate_password':
        _keys(args,set())
        if not STAGED_PASSWORD.is_file():raise ValueError('Stage new password locally on the Pi first')
        desired='new_password_staged_privately'
    elif op == 'restore_backup':
        _keys(args,{'filename'})
        filename=args['filename']
        if type(filename) is not str or not re.fullmatch(r'switch-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{6}\.bin',filename):
            raise ValueError('Only private backups generated by this MCP may be restored')
        if not (BACKUP_DIR/filename).is_file():raise ValueError('Backup not found')
        desired={'backup_file':filename,'operation':'restore'}
    elif op in ('reboot','factory_reset','save_config'):
        _keys(args,set())
    else:
        raise ValueError('Unsupported operation')

    if op in ('set_8021q_vlan','delete_8021q_vlan','set_port_profile','set_pvid'):
        _check_vlan_output(before,desired,op)
        before=_normalized_vlans(before);desired=_normalized_vlans(desired)
    if op == 'set_igmp':
        before={k:before[k] for k in ('enabled','report_suppression')}
    if op in ('reset_counters','reboot','factory_reset','restore_backup','rotate_password','save_config'):
        changed=True
    else: changed=(before!=desired)
    return {'changed':changed, 'before':before,'after':desired,'risk':risk,
            'critical':critical,'notes':notes}


def _preview(op: str, args: dict) -> dict:
    with switch() as sw:
        protect=_protected(sw,op)
        before=_state(sw,op)
        plan=_plan(op,args,before,protect)
        if op=='set_bandwidth' and args['ingress_kbps']:
            storm={p.port:p for p in sw.get_storm_control()}
            if any(storm[p].enabled for p in args['ports']):
                raise ValueError('Ingress bandwidth control conflicts with storm control on the same port')
        if op=='set_storm' and args['rate_index']:
            bandwidth={p.port:p for p in sw.get_bandwidth_control()}
            if any(bandwidth[p].ingress_rate for p in args['ports']):
                raise ValueError('Storm control conflicts with ingress bandwidth control on the same port')
        if not plan['changed']:
            return {'operation':op,'change_needed':False,'applied':False,'current':before}
        token=secrets.token_urlsafe(32)
        record={'operation':op,'parameters':args,'fingerprint':_sha(before),
                'protected':_sha(protect),'expires_at':int(time.time())+PLAN_TTL,
                'token_hash':hashlib.sha256(token.encode()).hexdigest()}
        _save_private(PENDING_PLAN,json.dumps(record,sort_keys=True).encode())
        return {'operation':op,'change_needed':True,'applied':False,'risk':plan['risk'],
                'critical':plan['critical'],'before':plan['before'],'after':plan['after'],
                'notes':plan['notes'],'change_id':token,'expires_in_seconds':PLAN_TTL,
                'warning':'Review disruption risk and physical recovery route before applying.'}


def _audit(payload: dict) -> None:
    ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
    with open(WRITE_AUDIT,'a',encoding='utf-8') as f:
        os.chmod(WRITE_AUDIT,0o600)
        f.write(json.dumps({'utc':_now(),**payload},sort_keys=True)+'\n')
        f.flush(); os.fsync(f.fileno())


def _critical_authorized() -> bool:
    if not CRITICAL_UNLOCK.exists():return False
    try:
        return json.loads(CRITICAL_UNLOCK.read_text())['expires'] > int(time.time())
    except (ValueError,KeyError):return False


def _perform(sw: Any, op: str, a: dict, planned: dict) -> None:
    if op == 'set_description':sw.set_device_description(a['description'])
    elif op == 'set_leds':sw.set_led(a['enabled'])
    elif op == 'set_ports':
        kw={key:a[key] for key in ('enabled','flow_control') if key in a}
        if 'speed' in a:kw['speed']=PortSpeed[a['speed']]
        sw.set_ports(a['ports'],**kw)
    elif op == 'reset_counters':sw.reset_port_statistics(a.get('port'))
    elif op == 'set_mirror':sw.set_port_mirror(**a)
    elif op == 'set_lag':sw.set_port_trunk(a['group_id'],a['ports'])
    elif op == 'set_igmp':sw.set_igmp_snooping(a['enabled'],report_suppression=a['report_suppression'])
    elif op == 'set_loop_prevention':sw.set_loop_prevention(a['enabled'])
    elif op == 'set_8021q_vlan':
        target=_vlans_map(planned['after'])[a['vlan_id']]
        sw.add_dot1q_vlan(a['vlan_id'],name=target['name'],
                          tagged_ports=target['tagged_ports'],untagged_ports=target['untagged_ports'])
    elif op == 'delete_8021q_vlan':sw.delete_dot1q_vlan(a['vlan_id'])
    elif op == 'set_port_profile':
        after=planned['after'];before=planned['before'];port=a['port']
        target=_vlans_map(after);old=_vlans_map(before)
        # Destination VLAN first, PVID second, removal of obsolete membership last.
        dst=a['untagged_vlan']
        v=target[dst]
        if v!=old[dst]: sw.add_dot1q_vlan(dst,name=v['name'],tagged_ports=v['tagged_ports'],untagged_ports=v['untagged_ports'])
        if before['port_pvids'][str(port)]!=dst:sw.set_pvid([port],dst)
        for vid,z in target.items():
            if vid!=dst and z!=old[vid]:
                sw.add_dot1q_vlan(vid,name=z['name'],tagged_ports=z['tagged_ports'],untagged_ports=z['untagged_ports'])
    elif op == 'set_pvid':sw.set_pvid(a['ports'],a['vlan_id'])
    elif op == 'set_qos_mode':sw.set_qos_mode(QoSMode[a['mode']])
    elif op == 'set_qos_priority':sw.set_port_priority(a['ports'],a['priority'])
    elif op == 'set_bandwidth':sw.set_bandwidth_control(a['ports'],ingress_kbps=a['ingress_kbps'],egress_kbps=a['egress_kbps'])
    elif op == 'set_storm':
        names={'broadcast':StormType.BROADCAST,'multicast':StormType.MULTICAST,'unknown_unicast':StormType.UNKNOWN_UNICAST}
        sw.set_storm_control(a['ports'],rate_index=a['rate_index'],storm_types=[names[x] for x in a['storm_types']])
    elif op == 'set_mtu_vlan':sw.set_mtu_vlan(a['enabled'],uplink_port=a.get('uplink_port',1))
    elif op == 'set_port_vlan_mode':sw.set_port_vlan_enabled(a['enabled'])
    elif op == 'set_port_vlan':sw.add_port_vlan(a['vlan_id'],a['member_ports'])
    elif op == 'delete_port_vlan':sw.delete_port_vlan(a['vlan_id'])
    elif op == 'set_8021q_mode':sw.set_dot1q_enabled(a['enabled'])
    elif op == 'set_ip':
        sw.set_ip_settings(**a)
        if not a['dhcp'] and 'ip' in a:
            _save_private(HOST_FILE,a['ip'].encode())
    elif op == 'rotate_password':
        new=STAGED_PASSWORD.read_text().rstrip('\r\n')
        if len(new)<12:raise ValueError('Locally staged password too short')
        sw.change_password(_password(),new)
        _save_private(PASSWORD_PATH,new.encode())
        STAGED_PASSWORD.unlink(missing_ok=True)
    elif op == 'restore_backup':sw.restore_config((BACKUP_DIR/a['filename']).read_bytes())
    elif op == 'reboot':sw.reboot()
    elif op == 'factory_reset':sw.factory_reset()
    elif op == 'save_config':sw.save_config()
    else:raise ValueError('Unsupported write operation')


def _verification_target(op: str, before: Any, after: Any) -> Any:
    return after


def _apply(change_id: str, confirm: bool, disruption_acknowledged: bool = False) -> dict:
    if confirm is not True:raise ValueError('Explicit confirm=true required after showing this preview to the user')
    if not isinstance(change_id,str) or len(change_id)<30:raise ValueError('Preview change_id required')
    with LOCK:
        if not PENDING_PLAN.exists():raise RuntimeError('No preview pending')
        record=json.loads(PENDING_PLAN.read_text())
        if not secrets.compare_digest(hashlib.sha256(change_id.encode()).hexdigest(),record['token_hash']):
            raise RuntimeError('Preview token mismatch')
        if int(time.time())>=record['expires_at']:
            PENDING_PLAN.unlink(missing_ok=True)
            raise RuntimeError('Preview expired; generate a new one')
        op=record['operation'];args=record['parameters']
        with switch() as sw:
            protected=_protected(sw,op)
            before=_state(sw,op)
            if _sha(before)!=record['fingerprint'] or _sha(protected)!=record['protected']:
                PENDING_PLAN.unlink(missing_ok=True)
                raise RuntimeError('Switch settings changed since preview, no write performed')
            planned=_plan(op,args,before,protected)
            if op=='set_bandwidth' and args['ingress_kbps']:
                storm={p.port:p for p in sw.get_storm_control()}
                if any(storm[p].enabled for p in args['ports']):raise RuntimeError('Storm control now enabled; preview again')
            if op=='set_storm' and args['rate_index']:
                bandwidth={p.port:p for p in sw.get_bandwidth_control()}
                if any(bandwidth[p].ingress_rate for p in args['ports']):raise RuntimeError('Ingress rate limit now enabled; preview again')
            if planned['risk'] in ('high','critical') and disruption_acknowledged is not True:
                raise ValueError('Disruption acknowledgement required after verifying recovery path')
            if planned['critical'] and not _critical_authorized():
                raise RuntimeError('Critical operation needs local 10-minute authorization on Raspberry Pi')
            if not planned['changed']:
                PENDING_PLAN.unlink(missing_ok=True)
                return {'applied':False,'already_correct':True}
            backup=_backup(sw)  # Fails closed before sending any write.
            PENDING_PLAN.unlink(missing_ok=True)  # Single-use token before writes.
            if planned['critical']: CRITICAL_UNLOCK.unlink(missing_ok=True)
            try:
                _perform(sw,op,args,planned)
                # These operations intentionally disconnect/reboot/change credentials.
                disconnected=op in ('set_ip','rotate_password','restore_backup','reboot','factory_reset',
                                    'set_mtu_vlan','set_port_vlan_mode','set_8021q_mode')
                if not disconnected:
                    actual=_state(sw,op)
                    expected=_verification_target(op,planned['before'],planned['after'])
                    if op=='set_igmp':actual={k:actual[k] for k in ('enabled','report_suppression')}
                    if op in ('set_8021q_vlan','delete_8021q_vlan','set_port_profile','set_pvid'):
                        actual=_normalized_vlans(actual)
                    if op=='set_mirror' and not args['enabled']:
                        # Firmware may clear destination when mirroring is disabled.
                        actual={'enabled':actual['enabled']}
                        expected={'enabled':expected['enabled']}
                    if op in ('reset_counters','save_config'): pass
                    elif op=='set_lag' and str(args['group_id']) in actual['groups']:
                        # JSON rendering may stringify integer dict keys.
                        if actual['groups'][str(args['group_id'])]!=expected['groups'].get(str(args['group_id'])):
                            raise RuntimeError('LAG read-back mismatch')
                    elif actual!=expected:
                        raise RuntimeError('Read-back differs from planned state')
                    _protected(sw,op)
                _audit({'operation':op,'args':args,'success':True,'verified':not disconnected,
                        'backup':backup['filename']})
                return {'applied':True,'verified':not disconnected, 'operation':op,
                        'backup':backup['filename'],
                        'note':('Disruptive operation requires local connectivity verification' if disconnected
                                else 'Configuration read-back matches proposed changes')}
            except Exception as e:
                _audit({'operation':op,'args':args,'success':False,'backup':backup['filename'],
                        'error_type':type(e).__name__})
                raise RuntimeError('Write/read-back failed; switch may be PARTIALLY configured. '
                                   'Use local management and saved backup to recover.') from e


EXAMPLES = {
    'set_description': {'description':'Home Switch'},
    'set_leds': {'enabled':False},
    'set_ports': {'ports':[2], 'enabled':True, 'speed':'AUTO', 'flow_control':False},
    'reset_counters': {'port':2},
    'set_mirror': {'enabled':True, 'dest_port':8, 'ingress_ports':[2], 'egress_ports':[2]},
    'set_lag': {'group_id':1, 'ports':[6,7]},
    'set_igmp': {'enabled':True, 'report_suppression':False},
    'set_loop_prevention': {'enabled':True},
    'set_8021q_vlan': {'vlan_id':30, 'tagged_ports':[1,2,3,4,5], 'untagged_ports':[]},
    'delete_8021q_vlan': {'vlan_id':99},
    'set_port_profile': {'port':2, 'untagged_vlan':30, 'tagged_vlans':[]},
    'set_pvid': {'ports':[2], 'vlan_id':30},
    'set_qos_mode': {'mode':'DSCP'},
    'set_qos_priority': {'ports':[2], 'priority':3},
    'set_bandwidth': {'ports':[2], 'ingress_kbps':0, 'egress_kbps':0},
    'set_storm': {'ports':[2], 'rate_index':5, 'storm_types':['broadcast','multicast']},
    'set_mtu_vlan': {'enabled':False, 'uplink_port':1},
    'set_port_vlan_mode': {'enabled':False},
    'set_port_vlan': {'vlan_id':2, 'member_ports':[1,2]},
    'delete_port_vlan': {'vlan_id':2},
    'set_8021q_mode': {'enabled':True},
    'set_ip': {'dhcp':False, 'ip':'192.168.0.2','netmask':'255.255.255.0', 'gateway':'192.168.0.1'},
    'reboot': {},
    'restore_backup': {'filename':'switch-YYYYMMDDTHHMMSSZ-xxxxxx.bin'},
    'factory_reset': {},
    'rotate_password': {},
    'save_config': {},
}


@mcp.tool()
def switch_capabilities() -> dict:
    """List every supported managed-switch operation and which require local unlock."""
    return {'hardware':'TL-SG108E V6.0, firmware 20230218',
            'operations':[{'operation':name,'risk':v[0], 'local_unlock_required':v[1],
                           'description':v[2], 'example_parameters':EXAMPLES[name]} for name,v in SPECS.items()],
            'read_tools':'All existing v2 read tools remain available',
            'unavailable':{'firmware_upload':'Not supported by tplink-tool SDK',
                           'cable_diagnostics':'Known non-functional on this firmware'},
            'protections':'Port 1 untagged VLAN1, PVID1 and enabled auto speed remain protected'}


@mcp.tool()
def switch_preview_change(operation: str, parameters: dict) -> dict:
    """READ-ONLY: preview ANY supported operation in switch_capabilities.

    Supply operation name and validated parameters object. Returns a one-time
    10-minute change_id, before/after, risk and local-unlock requirement.
    Always show the preview and obtain the user's explicit approval before apply.
    """
    return _preview(operation,parameters)


@mcp.tool()
def switch_apply_change(change_id: str, confirm: bool = False,
                        disruption_acknowledged: bool = False) -> dict:
    """WRITE: apply exactly the short-lived preview approved by the user.

    Switch identity + configuration are rechecked, private backup created, token
    consumed, and non-disruptive writes verified. Critical changes additionally
    need temporary LOCAL authorization. No raw HTTP or arbitrary command tool.
    """
    return _apply(change_id,confirm,disruption_acknowledged)


def _unlock_local() -> dict:
    if not sys.stdin.isatty():raise RuntimeError('Unlock requires local interactive terminal')
    print('WARNING: unlock permits management-IP change, password rotation, restore,')
    print('reboot, factory reset, and network mode changes for TEN MINUTES.')
    print(f'Type: UNLOCK TL-SG108E {EXPECTED_MAC}')
    typed=input('Exact confirmation: ').strip()
    if not EXPECTED_MAC or typed != f'UNLOCK TL-SG108E {EXPECTED_MAC}':
        raise RuntimeError('Not authorized')
    _save_private(CRITICAL_UNLOCK,json.dumps({'expires':int(time.time())+CRITICAL_TTL}).encode())
    return {'critical_unlocked':True,'expires_in_seconds':CRITICAL_TTL}


def _stage_password_local() -> dict:
    if not sys.stdin.isatty():raise RuntimeError('Must use local terminal')
    import getpass
    a=getpass.getpass('New password: ')
    b=getpass.getpass('Confirm: ')
    if a!=b or len(a)<12 or '\n' in a or '\r' in a:
        raise RuntimeError('Passwords differ or below minimum length')
    _save_private(STAGED_PASSWORD,a.encode())
    return {'password_staged_locally':True,'path':str(STAGED_PASSWORD)}


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    modes=parser.add_mutually_exclusive_group()
    modes.add_argument('--self-test',action='store_true')
    modes.add_argument('--backup',action='store_true')
    modes.add_argument('--capture-baseline',action='store_true')
    modes.add_argument('--unlock-critical',action='store_true')
    modes.add_argument('--lock-critical',action='store_true')
    modes.add_argument('--stage-password',action='store_true')
    modes.add_argument('--set-led',choices=['on','off'])
    args=parser.parse_args()
    if args.self_test:
        with switch() as sw:
            out={'identity':_identity(sw),'port_count':len(_ports(sw)),
                 'vlan_ids':[v['id'] for v in _vlans(sw)['vlans']]}
    elif args.backup:
        with switch() as sw:out=_backup(sw)
    elif args.capture_baseline:out=_capture_baseline()
    elif args.unlock_critical:out=_unlock_local()
    elif args.lock_critical:
        CRITICAL_UNLOCK.unlink(missing_ok=True);out={'critical_unlocked':False}
    elif args.stage_password:out=_stage_password_local()
    elif args.set_led:out=_local_led_change(args.set_led=='on')
    else:
        mcp.run(transport='streamable-http');return
    print(json.dumps(out,indent=2))


if __name__=='__main__':main()
