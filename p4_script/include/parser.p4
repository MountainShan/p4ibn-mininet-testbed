/* -*- P4_16 -*- */

# include <core.p4>
# include <v1model.p4>

const   bit<16>   ETHERNET_TYPE_ARP     =   16w0x0806;
const   bit<16>   ETHERNET_TYPE_IPV4    =   16w0x0800;

/* Header*/
struct metadata_t { }

struct headers {
    ethernet_t ethernet;
    arp_t arp;
    ipv4_t ipv4;
}

parser MyParser(packet_in packet, out headers hdr, inout metadata_t metadata, inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }
    
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERNET_TYPE_ARP:  parse_arp;
            ETHERNET_TYPE_IPV4: parse_ipv4;
            default:            accept;
        }
    }
    
    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}