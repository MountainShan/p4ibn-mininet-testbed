/* -*- P4_16 -*- */
# include <core.p4>
# include <v1model.p4>

header ethernet_t {
    bit<48>     dstAddr;
    bit<48>     srcAddr;
    bit<16>     etherType;
}

header arp_t {
    bit<16>     hwtype;
    bit<16>     protoType;
    bit<8>      hwAddrLen;
    bit<8>      protoAddrLen;
    bit<16>     opcode;
    bit<48>     srcHwAddr;
    bit<32>     srcProtoAddr;
    bit<48>     dstHwAddr;
    bit<32>     dstProtoAddr;

}

header ipv4_t {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      diffserv;
    bit<16>     totalLen;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     fragOffset;
    bit<8>      dscp;
    bit<8>      protocol;
    bit<16>     hdrChecksum;
    bit<32>     srcAddr;
    bit<32>     dstAddr;
}