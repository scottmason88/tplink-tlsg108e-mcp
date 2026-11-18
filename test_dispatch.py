"""Offline dispatch checks; no hardware I/O or live credentials."""
import pathlib
import sys
import unittest
sys.path.insert(0,str(pathlib.Path(__file__).parent))
from test_v4 import s, V, PROTECT

class StubSwitch:
    def __init__(self):self.calls=[]
    def __getattr__(self,name):
        def call(*args,**kwargs):
            self.calls.append((name,args,kwargs))
        return call

class Dispatch(unittest.TestCase):
    def test_generic_vlan_set(self):
        stub=StubSwitch()
        parms={'vlan_id':30,'tagged_ports':[1,2,3,4,5],'untagged_ports':[]}
        plan=s._plan('set_8021q_vlan',parms,V,PROTECT)
        s._perform(stub,'set_8021q_vlan',parms,plan)
        self.assertEqual(stub.calls[0][0],'add_dot1q_vlan')
        self.assertEqual(stub.calls[0][2]['tagged_ports'],[1,2,3,4,5])
    def test_port_profile_order(self):
        old=s.copy.deepcopy(V)
        s._vlans_map(old)[30]['tagged_ports'].append(1)
        a={'port':2,'untagged_vlan':30,'tagged_vlans':[]}
        plan=s._plan('set_port_profile',a,old,PROTECT)
        stub=StubSwitch()
        s._perform(stub,'set_port_profile',a,plan)
        names=[q[0] for q in stub.calls]
        self.assertEqual(names,['add_dot1q_vlan','set_pvid','add_dot1q_vlan','add_dot1q_vlan'])
    def test_qos_dispatch(self):
        stub=StubSwitch()
        s._perform(stub,'set_qos_mode',{'mode':'DSCP'},None)
        self.assertEqual(stub.calls[0][0],'set_qos_mode')
    def test_storm_enum_dispatch(self):
        stub=StubSwitch()
        s._perform(stub,'set_storm',{'ports':[2],'rate_index':5,'storm_types':['multicast','broadcast']},None)
        self.assertEqual(stub.calls[0][0],'set_storm_control')
        self.assertEqual([x.name for x in stub.calls[0][2]['storm_types']],['MULTICAST','BROADCAST'])
    def test_port_settings_dispatch(self):
        stub=StubSwitch()
        s._perform(stub,'set_ports',{'ports':[3],'speed':'AUTO','flow_control':True},None)
        self.assertEqual(stub.calls[0][0],'set_ports')
        self.assertEqual(stub.calls[0][2]['speed'].name,'AUTO')
    def test_reboot_method(self):
        stub=StubSwitch();s._perform(stub,'reboot',{},None)
        self.assertEqual(stub.calls,[('reboot',(),{})])
    def test_no_arbitrary_method(self):
        with self.assertRaises(ValueError):
            s._plan('run_shell',{'command':'rm -rf /'},None,PROTECT)

if __name__=='__main__':unittest.main(verbosity=2)
