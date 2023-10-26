#pragma once

// turn on only one of them
// #define IG_MIRRORING_ENABLED
// #define EG_MIRRORING_ENABLED

enum bit<16> ether_type_t {
    IPV4 = 0x0800,
    ARP  = 0x0806
}

enum bit<8> ipv4_proto_t {
    TCP = 6,
    UDP = 17,
    ICMP = 1
}

enum bit<16> udp_port_t {
    ROCE_V2 = 4791
}


// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
    packet_in pkt,
    out header_t hdr,
    out metadata_t meta,
    out ingress_intrinsic_metadata_t ig_intr_md,
    out ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm,
    out ingress_intrinsic_metadata_from_parser_t ig_intr_md_from_prsr){


	state start {
        pkt.extract(ig_intr_md);
        transition parse_port_metadata;
	}

    state parse_port_metadata {
        meta.port_md = port_metadata_unpack<port_metadata_t>(pkt);
        transition init_metadata;
    }

    state init_metadata { // init bridged_meta (based on slide 23 of BA-1122)
        // hdr.bridged_meta.setValid();
        // hdr.bridged_meta.type = INTERNAL_HDR_TYPE_BRIDGED_META;
        // hdr.bridged_meta.info = 0;
        transition parse_ethernet;
    }
    
	state parse_ethernet {
		pkt.extract(hdr.ethernet);
		transition select(hdr.ethernet.ether_type){
			(bit<16>) ether_type_t.IPV4: parse_ipv4;
			(bit<16>) ether_type_t.ARP: parse_arp;
			default: accept;
		}
	}

	state parse_ipv4 {
		pkt.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol){
			(bit<8>) ipv4_proto_t.TCP: parse_tcp;
			(bit<8>) ipv4_proto_t.UDP: parse_udp;
            (bit<8>) ipv4_proto_t.ICMP: parse_icmp;
		    default: accept;
		}
	}

	state parse_arp {
		pkt.extract(hdr.arp);
		transition accept;
	}

	state parse_tcp {
		pkt.extract(hdr.tcp);
		transition accept;
	}

	state parse_udp {
		pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            (bit<16>) udp_port_t.ROCE_V2: parse_bth; 
            default: accept;
        }
	}

    state parse_bth {
        pkt.extract(hdr.bth);
        transition select(hdr.bth.opcode) {
            0x04 : parse_deth; // RC RDMA SEND-ONLY (4)
            0x06 : parse_reth; // RC RDMA WRITE FIRST (6)
            0x11 : parse_aeth; // RC RDMA ACK (17)
            default: accept;

            // 0x0A : parse_reth; // RC RDMA WRITE-ONLY (10) - RETH (not sure)
            // 0x2A : parse_reth; // UC RDMA Write (42) - RETH (not sure)
            // 0x64 : parse_deth; // UC RDMA SEND-ONLY - DETH (not sure)
        }
    }

    state parse_reth {
        pkt.extract(hdr.reth);
        transition accept;
    }

    state parse_deth {
        pkt.extract(hdr.deth);
        transition accept;
    }

    state parse_aeth {
        pkt.extract(hdr.aeth);
        transition accept;
    }

    state parse_icmp {
        pkt.extract(hdr.icmp);
        transition accept;
    }
}


// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t meta,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    Checksum() ipv4_checksum;
    Mirror() mirror;

    apply {
        hdr.ipv4.hdr_checksum = ipv4_checksum.update({
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.dscp,
            hdr.ipv4.ecn,
            hdr.ipv4.total_len,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.frag_offset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr});

        // different mirror types can define different sets of headers
        if(ig_dprsr_md.mirror_type == IG_MIRROR_TYPE_1) {      
            // which session? what mirroring metadata?
            mirror.emit<ig_mirror1_h>(meta.mirror_session, {meta.ig_mirror1.ingress_mac_timestamp, 
                                                                    meta.ig_mirror1.opcode,
                                                                    meta.ig_mirror1.mirrored,
                                                                    meta.ig_mirror1.last_ack,
                                                                    meta.ig_mirror1.rdma_seqnum});
        }
        pkt.emit(hdr);
    }
}


// ---------------------------------------------------------------------------
// Egress parser
// ---------------------------------------------------------------------------
parser SwitchEgressParser(
    packet_in pkt,
    out header_t hdr,
    out metadata_t meta,
    out egress_intrinsic_metadata_t eg_intr_md,
    out egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr){

    // internal_hdr_h internal_hdr;
    state start {
        pkt.extract(eg_intr_md);
        transition parse_metadata;
    }

    state parse_metadata {
        #ifdef IG_MIRRORING_ENABLED 
        ig_mirror1_h mirror_md = pkt.lookahead<ig_mirror1_h>();
        transition select(mirror_md.mirrored) {
            (bit<8>)IG_MIRROR_TYPE_1 : parse_ig_mirror_md;
            default : parse_ethernet;
        }
        #endif
        
        #ifdef EG_MIRRORING_ENABLED
        eg_mirror1_h mirror_md = pkt.lookahead<eg_mirror1_h>();
        transition select(mirror_md.mirrored) {
            (bit<8>)EG_MIRROR_TYPE_1 : parse_eg_mirror_md;
            default : parse_ethernet;
        }
        #endif

        #ifndef IG_MIRRORING_ENABLED
        #ifndef EG_MIRRORING_ENABLED
        transition parse_ethernet; // if no ig/eg_mirroring
        #endif
        #endif
    }

    /* mirroring */
    state parse_ig_mirror_md {
        pkt.extract(meta.ig_mirror1);
        transition parse_ethernet;
    }

    state parse_eg_mirror_md {
        pkt.extract(meta.eg_mirror1);
        transition parse_ethernet;
    }

    state parse_ethernet {
		pkt.extract(hdr.ethernet);
		transition select(hdr.ethernet.ether_type){
			(bit<16>) ether_type_t.IPV4: parse_ipv4;
			(bit<16>) ether_type_t.ARP: parse_arp;
			default: accept;
		}
	}

	state parse_ipv4 {
		pkt.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol){
			(bit<8>) ipv4_proto_t.TCP: parse_tcp;
			(bit<8>) ipv4_proto_t.UDP: parse_udp;
            (bit<8>) ipv4_proto_t.ICMP: parse_icmp;
		    default: accept;
		}
	}

	state parse_arp {
		pkt.extract(hdr.arp);
		transition accept;
	}

	state parse_tcp {
		pkt.extract(hdr.tcp);
		transition accept;
	}

	state parse_udp {
		pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            (bit<16>) udp_port_t.ROCE_V2: parse_bth; 
            default: accept;
        }
	}

    state parse_bth {
        pkt.extract(hdr.bth);
        transition select(hdr.bth.opcode) {
            0x04 : parse_deth; // RC RDMA SEND-ONLY (4)
            0x06 : parse_reth; // RC RDMA WRITE FIRST (6)
            0x11 : parse_aeth; // RC RDMA ACK (17)
            default: accept;

            // 0x0A : parse_reth; // RC RDMA WRITE-ONLY (10) - RETH (not sure)
            // 0x2A : parse_reth; // UC RDMA Write (42) - RETH (not sure)
            // 0x64 : parse_deth; // UC RDMA SEND-ONLY - DETH (not sure)
        }
    }

    state parse_reth {
        pkt.extract(hdr.reth);
        transition accept;
    }

    state parse_deth {
        pkt.extract(hdr.deth);
        transition accept;
    }

    state parse_aeth {
        pkt.extract(hdr.aeth);
        transition accept;
    }

    state parse_icmp {
        pkt.extract(hdr.icmp);
        transition accept;
    }
    // do more stuff here if needed
}

// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(
    packet_out pkt,
    inout header_t hdr,
    in metadata_t meta,
    in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr){

    Mirror() mirror;
    Checksum() ipv4_checksum;

	apply{
        
        if(eg_intr_md_for_dprsr.mirror_type == EG_MIRROR_TYPE_1){
            mirror.emit<eg_mirror1_h>(meta.mirror_session,
                {   meta.eg_mirror1.egress_global_timestamp,
                    meta.eg_mirror1.mirrored,
                    meta.eg_mirror1.ecn
                });
        } 

        hdr.ipv4.hdr_checksum = ipv4_checksum.update({
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.dscp,
            hdr.ipv4.ecn,
            hdr.ipv4.total_len,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.frag_offset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr});

		pkt.emit(hdr);
	}
}
