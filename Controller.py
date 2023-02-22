#!/usr/bin/env python2
import grpc, os, sys
from time import sleep
from threading import Thread 
# GRPC client
import p4_runtime.bmv2
import p4_runtime.helper
from p4_runtime.error_utils import printGrpcError

class P4_Controller:
    def __init__ (self, p4info_file, json_file):
        self.switches = {}
        self.p4info_file = p4info_file
        self.json_file = json_file

    def _write_arp_forwarding_rules(self, p4info, source, destination, port):
        table_entries = []
        entity_action_type = 1 # Insert 
        entity_message_type = 2 # Table entry
        table_entries.append((entity_action_type, entity_message_type, p4info.buildTableEntry(
            table_name="MyIngress.arp_forwarding",
            match_fields={ "hdr.arp.srcProtoAddr": source, "hdr.arp.dstProtoAddr": destination}, 
            action_name="MyIngress.set_output",
            action_params={"port": port} )))
        return table_entries
    
    def _write_ipv4_forwarding_rules(self, p4info, source, destination, port):
        table_entries = []
        entity_action_type = 1 # Insert 
        entity_message_type = 2 # Table entry
        table_entries.append((entity_action_type, entity_message_type, p4info.buildTableEntry(
            table_name="MyIngress.ipv4_forwarding",
            match_fields={ "hdr.ipv4.srcAddr": source, "hdr.ipv4.dstAddr": destination}, 
            action_name="MyIngress.set_output",
            action_params={"port": port} )))
        return table_entries

    def main(self):
        print ("Testing start. ")
        try:
            for sw in range(1,2):
                p4info_helper = p4_runtime.helper.P4InfoHelper(self.p4info_file)
                grpc_client = p4_runtime.bmv2.Bmv2SwitchConnection(name = 'p4s-%d'%(sw),address = '10.77.77.%d:%d'%(10+sw, 50050), device_id = sw, low = 0)
                grpc_client.MasterArbitrationUpdate()
                grpc_client.SetConfigureForwardingPipeline(action = "VERIFY_AND_COMMIT", p4info = p4info_helper.p4info, bmv2_json_file_path = self.json_file)
                self.switches.setdefault(sw, {"gRPC": grpc_client, "p4info": p4info_helper})
            print(" >>> Start monitoring ports and flows. ")
            # Default Entries
            while (True):
                pass
            
        except KeyboardInterrupt:
            print (" Shutting down.")
        finally:
            for sw_id in self.switches:
                self.switches[sw_id]['gRPC'].shutdown()

if __name__ == '__main__':
    P4Controller = P4_Controller("./p4_script/build/switch.p4info.txt", "./p4_script/build/switch.json")
    P4Controller.main()


