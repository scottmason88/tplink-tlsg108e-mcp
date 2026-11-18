"""Offline unit tests; no switch, network or write actions."""
import importlib.util
import json
import pathlib
import sys
import types
import unittest
from enum import IntEnum

class FakeFastMCP:
    def __init__(self, *a, **k):pass
    def tool(self):return lambda fn:fn

for mod in ('mcp','mcp.server','mcp.server.fastmcp'):
    sys.modules[mod]=types.ModuleType(mod)
sys.modules['mcp.server.fastmcp'].FastMCP=FakeFastMCP
sdk=types.ModuleType('tplink_tool')
class PortSpeed(IntEnum):
    AUTO=1;M10H=2;M10F=3;M100H=4;M100F=5;M1000F=6
class QoSMode(IntEnum):
    PORT_BASED=0;DOT1P=1;DSCP=2
class StormType(IntEnum):
    UNKNOWN_UNICAST=1;MULTICAST=2;BROADCAST=4
sdk.PortSpeed=PortSpeed;sdk.QoSMode=QoSMode;sdk.StormType=StormType
sdk.make_switch=lambda *a,**k:None
sys.modules['tplink_tool']=sdk
spec=importlib.util.spec_from_file_location('switchv4',pathlib.Path(__file__).with_name('server.py'))
s=importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)

V={'dot1q_enabled':True,'vlans':[
    {'id':1,'name':'Default','tagged_ports':[],'untagged_ports':list(range(1,9))},
    {'id':30,'name':'','tagged_ports':[2,3,4,5],'untagged_ports':[]},
    {'id':40,'name':'','tagged_ports':[2,3,4,5],'untagged_ports':[]}],
    'port_pvids':{str(x):1 for x in range(1,9)}}
PROTECT={'port1_pvid':1,'vlan1_untagged_uplink':True}

class Plans(unittest.TestCase):
    def p(self,op,args,v=None):return s._plan(op,args,json.loads(json.dumps(v if v is not None else V)),PROTECT)
    def test_all_operations_declared(self):
        self.assertEqual(set(s.SPECS),set(s.EXAMPLES))
        self.assertGreaterEqual(len(s.SPECS),25)
    def test_generic_uplink(self):
        r=self.p('set_8021q_vlan',{'vlan_id':30,'tagged_ports':[1,2,3,4,5],'untagged_ports':[]})
        self.assertTrue(r['changed']); self.assertIn(1,s._vlans_map(r['after'])[30]['tagged_ports'])
        self.assertEqual(r['after']['port_pvids']['1'],1)
    def test_arbitrary_vlan(self):
        r=self.p('set_8021q_vlan',{'vlan_id':53,'name':'Lab','tagged_ports':[1,6],'untagged_ports':[]})
        self.assertEqual(s._vlans_map(r['after'])[53]['name'],'Lab')
    def test_block_management_vlan(self):
        with self.assertRaises(ValueError):
            self.p('set_8021q_vlan',{'vlan_id':1,'tagged_ports':[],'untagged_ports':[]})
    def test_block_management_port_profile(self):
        with self.assertRaises(ValueError):
            self.p('set_port_profile',{'port':1,'untagged_vlan':30,'tagged_vlans':[]})
    def test_cannot_migrate_before_uplink(self):
        with self.assertRaises(ValueError):
            self.p('set_port_profile',{'port':2,'untagged_vlan':30,'tagged_vlans':[]})
    def test_migrate_after_uplink(self):
        v=json.loads(json.dumps(V));s._vlans_map(v)[30]['tagged_ports'].append(1)
        r=self.p('set_port_profile',{'port':2,'untagged_vlan':30,'tagged_vlans':[]},v)
        self.assertIn(2,s._vlans_map(r['after'])[30]['untagged_ports'])
        self.assertNotIn(2,s._vlans_map(r['after'])[1]['untagged_ports'])
        self.assertEqual(r['after']['port_pvids']['2'],30)
    def test_delete_default_rejected(self):
        with self.assertRaises(ValueError):self.p('delete_8021q_vlan',{'vlan_id':1})
    def test_reject_vlan_overlap(self):
        with self.assertRaises(ValueError):
            self.p('set_8021q_vlan',{'vlan_id':30,'tagged_ports':[2], 'untagged_ports':[2]})
    def test_reject_unsafe_untagged(self):
        with self.assertRaises(ValueError):
            self.p('set_8021q_vlan',{'vlan_id':30,'tagged_ports':[], 'untagged_ports':[2]})
    def test_port_speed(self):
        current=[{'port':i,'admin_enabled':True,'configured_speed':'AUTO','flow_control_configured':False} for i in range(1,9)]
        r=self.p('set_ports',{'ports':[2,3],'speed':'M1000F'},current)
        self.assertEqual(r['after'][1]['configured_speed'],'M1000F')
        self.assertEqual(r['after'][3]['configured_speed'],'AUTO')
    def test_protect_uplink_speed(self):
        current=[{'port':i,'admin_enabled':True,'configured_speed':'AUTO','flow_control_configured':False} for i in range(1,9)]
        with self.assertRaises(ValueError):self.p('set_ports',{'ports':[1],'enabled':False},current)
    def test_qos_priority(self):
        before=['DSCP',[{'port':i,'priority':1} for i in range(1,9)]]
        self.assertEqual(self.p('set_qos_priority',{'ports':[2],'priority':4},before)['after'][1][1]['priority'],4)
    def test_storm(self):
        before=[{'port':i,'enabled':False,'rate_index':0,'storm_types':0} for i in range(1,9)]
        r=self.p('set_storm',{'ports':[3],'rate_index':5,'storm_types':['broadcast','multicast']},before)
        self.assertEqual(r['after'][2]['storm_types'],6)
    def test_bad_destructive_parameters(self):
        with self.assertRaises(ValueError):self.p('factory_reset',{'secret':'inject'})
    def test_critical_restore_requires_local_file(self):
        with self.assertRaises(ValueError):self.p('restore_backup',{'filename':'../../etc/shadow'},'restore_private_backup')
    def test_loop(self):
        self.assertTrue(self.p('set_loop_prevention',{'enabled':True},False)['changed'])
    def test_mirror(self):
        before={'enabled':False,'dest_port':0,'mode':0,'ingress_ports':[],'egress_ports':[]}
        r=self.p('set_mirror',{'enabled':True,'dest_port':8,'ingress_ports':[2],'egress_ports':[2]},before)
        self.assertEqual(r['after']['dest_port'],8)
    def test_lag(self):
        before={'max_groups':2,'port_count':8,'groups':{}}
        r=self.p('set_lag',{'group_id':1,'ports':[6,7]},before)
        self.assertEqual(r['after']['groups']['1'],[6,7])

if __name__=='__main__':unittest.main(verbosity=2)
