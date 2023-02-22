#!/usr/bin/python2
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import TCLink, Intf
from mininet.node import RemoteController, OVSSwitch
from p4_topology.p4_mininet import P4Host, P4RuntimeSwitch, P4Controller

import os
os.chdir(os.path.dirname(os.path.realpath(__file__)))

p4_ctrl_info = {1:"10.77.77.1",2:"10.77.77.2",3:"10.77.77.3",4:"10.77.77.4"}
of_ctrl_info = {1:"127.0.0.1"}
num_of_p4_switch = 4
num_of_of_switch = 2
num_of_host_switch = 2

def main():
	
	net = Mininet(controller = None, link = TCLink)

	# Hosts
	hosts = []
	for i in range(num_of_host_switch):
		hosts.append(net.addHost("pc%d"%(i+1), cls=P4Host, ip = "10.33.33.%d/24"%(i+11)))
	
	# OpenFlow controllers
	of_ctrls = {}
	for did, control_ip in of_ctrl_info.items():
		of_ctrls.setdefault(did, RemoteController('ofc%d'%did, ip=control_ip, port=6633))
	
	# OpenFlow switches
	of_switches = []
	for i in range(num_of_of_switch):
		of_switches.append(net.addSwitch("ofs%d"%(i+1), cls = OVSSwitch))
	
	# P4 controller
	p4_ctrls = {}
	for did, control_ip in p4_ctrl_info.items():
		p4_ctrls.setdefault(did,P4Controller(did, control_ip))

	# P4 switches
	p4_switches = []
	for i in range(num_of_p4_switch):
		p4_switches.append(net.addSwitch("p4s%d"%(i+1), cls = P4RuntimeSwitch, grpc_port = 50050, grpc_addr = "10.77.77.%d"%(i+11), inband_control=True, device_id = i+1, json_path="./p4_script/build/switch.json", cpu_port=255))
	
	
	# Topology

	## Hosts' connection
	net.addLink(hosts[0], of_switches[0], bw=10)
	net.addLink(hosts[1], of_switches[1], bw=10)
	
	## Switches' connection
	net.addLink(of_switches[0], p4_switches[0], bw=1)
	net.addLink(of_switches[1], p4_switches[2], bw=1)
	
	net.addLink(p4_switches[0], p4_switches[1], bw=1)
	net.addLink(p4_switches[1], p4_switches[2], bw=1)
	net.addLink(p4_switches[2], p4_switches[3], bw=1)
	net.addLink(p4_switches[3], p4_switches[0], bw=1)
	net.addLink(p4_switches[0], p4_switches[2], bw=1)
	## In-band controller
	for did in p4_ctrls:
		Intf(p4_ctrls[did].start(), p4_switches[did-1])
	
	
	net.start()
	CLI(net)
	net.stop()
	
	for did in p4_ctrls:
		p4_ctrls[did].stop()

if __name__ == "__main__":
	setLogLevel( "info" )
	main()
