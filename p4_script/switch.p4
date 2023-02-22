# include <core.p4>
# include <v1model.p4>

# include "include/header.p4"
# include "include/parser.p4"

control MyIngress(inout headers hdr,inout metadata_t metadata,inout standard_metadata_t standard_metadata) { 
    
    // Actions
    action drop () { 
        mark_to_drop(standard_metadata); 
    }
    action set_output (bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    // Tables
    table arp_forwarding {
        key = {
            hdr.arp.srcProtoAddr: exact;
            hdr.arp.dstProtoAddr: exact;
        } 
        actions = {
            drop;
            set_output;
        }
        default_action = drop();
    }
    table ipv4_forwarding {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
        } 
        actions = {
            drop;
            set_output;
        }
        default_action = drop();
    }

    //Apply statement
    apply { 
        if (standard_metadata.ingress_port == 3) {
            standard_metadata.egress_spec = 254;
        } else if (standard_metadata.ingress_port == 254) {
            standard_metadata.egress_spec = 3;
        }
    }
} 


control MyDeparser(packet_out packet, in headers hdr) { 
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
    }
} 

// Empty Control block
control MyVerifyChecksum(inout headers hdr, inout metadata_t metadata) { apply {  } }
control MyEgress(inout headers hdr,inout metadata_t metadata,inout standard_metadata_t standard_metadata) {  apply {  } }
control MyComputeChecksum(inout headers  hdr, inout metadata_t metadata) { apply { } }
V1Switch( MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser() ) main;