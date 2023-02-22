# Copyright 2017-present Barefoot Networks, Inc.
# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os
import tempfile
import psutil
from time import sleep

from subprocess import call, PIPE
from pyroute2 import NetNS, NSPopen, IPRoute

from mininet.log import debug, error, info
from mininet.moduledeps import pathCheck
from mininet.node import Host, Switch
from .netstat import check_listening_on_port

SWITCH_START_TIMEOUT = 10 # seconds
os.getcwd()

def check_listening_on_port(port):
    for c in psutil.net_connections(kind='inet'):
        if c.status == 'LISTEN' and c.laddr[1] == port:
            return True
    return False

class P4Controller():
    def __init__(self, did, ip):
        self.name = 'p4c%d'%did
        self.ip_config = IPRoute()
        self.netns = NetNS(self.name)
        self.control_ip = ip
        self.domain_id = did
    
    def start(self):
        self.ip_config.link('add', ifname='switch-port-%d'%self.domain_id, kind='veth', peer='ctrl-port-%d'%self.domain_id)
        
        # Controller side
        idx = self.ip_config.link_lookup(ifname='ctrl-port-%d'%self.domain_id)[0]
        self.ip_config.link('set', index=idx, net_ns_fd='%s'%self.name)
        NSPopen('%s'%self.name, ['ip', 'link', 'set', 'lo', 'up' ], stdout=PIPE)
        NSPopen('%s'%self.name, ['ip', 'link', 'set', 'ctrl-port-%d'%self.domain_id, 'up' ], stdout=PIPE)
        NSPopen('%s'%self.name, ['ip', 'addr', 'add', '%s/24'%self.control_ip, 'dev', 'ctrl-port-%d'%self.domain_id], stdout=PIPE)
        NSPopen('%s'%self.name, ["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"], stdout=PIPE)
        NSPopen('%s'%self.name, ["sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1"], stdout=PIPE)
        NSPopen('%s'%self.name, ["sysctl", "-w", "net.ipv6.conf.lo.disable_ipv6=1"], stdout=PIPE)

        # Switch side
        self.ip_config.link('set', ifname='switch-port-%d'%self.domain_id, state='up')
        
        # Ethtool configure
        for off in ["rx", "tx", "sg"]:
            call(['ethtool', '--offload', 'switch-port-%d'%self.domain_id, off, 'off' ], stdout=PIPE)
            NSPopen('%s'%self.name, ['ethtool', '--offload', 'ctrl-port-%d'%self.domain_id, off, 'off' ], stdout=PIPE)

        return 'switch-port-%d'%self.domain_id
    
    def stop(self):
        self.netns.remove()

class P4Host(Host):
    def config(self, **params):
        r = super(Host, self).config(**params)
        self.defaultIntf().rename("eth0")
        for off in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload eth0 %s off" % off
            self.cmd(cmd)
        # disable IPv6
        self.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")
        return r

    def describe(self):
        print("**********")
        print(self.name)
        print("default interface: %s\t%s\t%s" %( self.defaultIntf().name, self.defaultIntf().IP(), self.defaultIntf().MAC() ))
        print("**********")

class P4RuntimeSwitch(Switch):
    "BMv2 switch with gRPC support"
    next_grpc_port = 50051
    next_thrift_port = 9090
    device_id = 0

    def __init__(self, name, json_path = None,
                 grpc_addr = None,
                 grpc_port = None,
                 thrift_port = None,
                 pcap_dump = False,
                 log_console = False,
                 verbose = False,
                 device_id = None,
                 enable_debugger = False,
                 log_file = None,
                 cpu_port = None, 
                 inband_control = False, # Inband control
                 nanomsg=None,
                 **kwargs):
        info("P4Runtime switch %s set up ... \n"% name)
        Switch.__init__(self, name, **kwargs)
        
        self.sw_path = "simple_switch_grpc"
        self.ip_config = None
        self.netns = None
        
        self.inband_control = inband_control
        if json_path is not None:
            if not os.path.isfile(json_path):
                error("Invalid JSON file: {}\n".format(json_path))
                exit(1)
            self.json_path = json_path
        else:
            self.json_path = None

        if grpc_port is not None:
            self.grpc_port = grpc_port
        if grpc_addr is not None:
            self.grpc_addr = grpc_addr
            if (self.inband_control == True):
                self.ip_config = IPRoute()
                self.netns = NetNS('%s'%self.name)
                self.ip_config.link('add', ifname='%s-i'%self.name, kind='veth', peer='%s-g'%self.name)
                idx = self.ip_config.link_lookup(ifname='%s-i'%self.name)[0]
                self.ip_config.link('set', index=idx, net_ns_fd='%s'%self.name)
                idx = self.ip_config.link_lookup(ifname='%s-g'%self.name)[0]
                self.ip_config.link('set', index=idx, net_ns_fd='%s'%self.name)
                NSPopen('%s'%self.name, ['ip', 'link', 'set', 'lo', 'up' ], stdout=PIPE)
                NSPopen('%s'%self.name, ['ip', 'link', 'set', '%s-i'%self.name, 'up' ], stdout=PIPE)
                NSPopen('%s'%self.name, ['ip', 'link', 'set', '%s-g'%self.name, 'up' ], stdout=PIPE)
                for off in ["rx", "tx", "sg"]:
                    NSPopen('%s'%self.name, ['ethtool', '--offload', '%s-i'%self.name, off, 'off' ], stdout=PIPE)
                    NSPopen('%s'%self.name, ['ethtool', '--offload', '%s-g'%self.name, off, 'off' ], stdout=PIPE)
                NSPopen('%s'%self.name, ['ip', 'addr', 'add', '%s/24'%grpc_addr, 'dev', '%s-g'%self.name ], stdout=PIPE)
            else:
                self.grpc_addr = "0.0.0.0"
        else:
            if (self.inband_control == False):
                self.grpc_port = P4RuntimeSwitch.next_grpc_port
                P4RuntimeSwitch.next_grpc_port += 1
            else:
                error("P4Runtime Switch %s configuration error. "% (self.name))
                exit(1)

        if thrift_port is not None:
            self.thrift_port = thrift_port
        else:
            self.thrift_port = P4RuntimeSwitch.next_thrift_port
            P4RuntimeSwitch.next_thrift_port += 1
        
        if cpu_port is not None:
            self.cpu_port = cpu_port
        
        if check_listening_on_port(self.grpc_port):
            error('%s cannot bind port %d because it is bound by another process\n' % (self.name, self.grpc_port))
            exit(1)

        self.verbose = verbose
        logfile = "/tmp/p4s.{}.log".format(self.name)
        self.output = open(logfile, 'w')
        self.pcap_dump = pcap_dump
        self.enable_debugger = enable_debugger
        self.log_console = log_console
        if log_file is not None:
            self.log_file = log_file
        else:
            self.log_file = "/tmp/p4s.{}.log".format(self.name)
        if device_id is not None:
            self.device_id = device_id
            P4RuntimeSwitch.device_id = max(P4RuntimeSwitch.device_id, device_id)
        else:
            self.device_id = P4RuntimeSwitch.device_id
            P4RuntimeSwitch.device_id += 1
        
        if (nanomsg == True):
            self.nanomsg = "ipc:///tmp/bm-{}-log.ipc".format(self.device_id)
        else:
            self.nanomsg = None

    @classmethod
    def setup(cls):
        pass

    def check_switch_started(self, pid):
        for _ in range(SWITCH_START_TIMEOUT * 2):
            if not os.path.exists(os.path.join("/proc", str(pid))):
                return False
            if check_listening_on_port(self.grpc_port):
                return True
            sleep(0.5)

    def start(self, controllers):
        if self.inband_control == True:
            self.inband_p4_runtime_switch_start (controllers)
        else:
            self.out_of_band_p4_runtime_switch_start (controllers)
    
    def inband_p4_runtime_switch_start(self, controllers):
        info("Starting P4 switch {}.\n".format(self.name))
        args = [self.sw_path]

        for port, intf in list(self.intfs.items()):
            if not intf.IP():
                args += ["-i", "%d@%s"%(port,intf.name)]
                idx = self.ip_config.link_lookup(ifname=intf.name)[0]
                self.ip_config.link('set', index=idx, net_ns_fd='%s'%self.name)
                NSPopen('%s'%self.name, ['ip', 'link', 'set', intf.name, 'up' ], stdout=PIPE)

        args += ["-i", "254@%s-i"%self.name]

        args += ['--device-id', "%d"%self.device_id]
        P4RuntimeSwitch.device_id += 1

        if self.pcap_dump:
            args += ["--pcap", self.pcap_dump]
        
        if self.nanomsg:
            args += ['--nanolog', self.nanomsg]
        
        if self.json_path:
            args.append(self.json_path)
        else:
            args.append("--no-p4")
        
        if self.enable_debugger:
            args.append("--debugger")
        
        if self.log_console:
            args.append("--log-console")
        
        if self.thrift_port:
            args += ['--thrift-port','%d'%self.thrift_port]
        
        if self.grpc_port:
            args += ["--", "--grpc-server-addr", "%s:%d"%(self.grpc_addr, self.grpc_port)]
        
        if self.cpu_port:
            args += ['--cpu-port', '%d'%self.cpu_port]
        
        cmd = ' '.join(args)
        info(cmd + "\n")
        
        pid = None
        NSPopen('%s'%self.name, args, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        
        for _ in range(SWITCH_START_TIMEOUT*2):
            nsp = NSPopen('%s'%self.name, ['pidof', self.sw_path], stdin=PIPE, stdout=PIPE, stderr=PIPE)
            pid = nsp.communicate()[0]
            if (pid != b''):
                info("P4 switch {} has been started.\n".format(self.name))
                break
            sleep(0.5)

        if pid == b'':
            error("P4 switch {} did not start correctly.\n".format(self.name))
            exit(1)
        
    def out_of_band_p4_runtime_switch_start(self, controllers):
        info("Starting P4 switch {}.\n".format(self.name))
        args = [self.sw_path]
        for port, intf in list(self.intfs.items()):
            if not intf.IP():
                args.extend(['-i', str(port) + "@" + intf.name])
        
        if self.pcap_dump:
            args.append("--pcap %s" % self.pcap_dump)
        if self.nanomsg:
            args.extend(['--nanolog', self.nanomsg])
        args.extend(['--device-id', str(self.device_id)])
        P4RuntimeSwitch.device_id += 1
        
        if self.json_path:
            args.append(self.json_path)
        else:
            args.append("--no-p4")
        if self.enable_debugger:
            args.append("--debugger")
        if self.log_console:
            args.append("--log-console")
        if self.thrift_port:
            args.append('--thrift-port ' + str(self.thrift_port))
        if self.grpc_port:
            args.append("-- --grpc-server-addr 0.0.0.0:" + str(self.grpc_port))
        if self.cpu_port:
            args.append('--cpu-port ' + str(self.cpu_port))
        
        cmd = ' '.join(args)
        info(cmd + "\n")

        pid = None
        with tempfile.NamedTemporaryFile() as f:
            self.cmd(cmd + ' >' + self.log_file + ' 2>&1 & echo $! >> ' + f.name)
            pid = int(f.read())
        debug("P4 switch {} PID is {}.\n".format(self.name, pid))
        if not self.check_switch_started(pid):
            error("P4 switch {} did not start correctly.\n".format(self.name))
            exit(1)
        
        info("P4 switch {} has been started.\n".format(self.name))

    def stop(self):
        "Terminate P4 switch."
        if (self.inband_control == True):
            # Delete linux namespace
            NSPopen('%s'%self.name, ["killall", self.sw_path], stdin=PIPE, stdout=PIPE, stderr=PIPE)
            self.netns.remove()
        else:
            self.output.flush()
            self.cmd('kill %' + self.sw_path)
            self.cmd('wait')
        self.deleteIntfs()
        

    def attach(self, intf):
        "Connect a data port"
        assert(0)

    def detach(self, intf):
        "Disconnect a data port"
        assert(0)