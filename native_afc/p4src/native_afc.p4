/* -*- P4_16 -*- */

#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
 **************************************************************************/


/**
 * @brief Basic networking
 */
typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOL_UDP = 0x11;
const ip_protocol_t IP_PROTOCOL_TCP = 0x6;
const int MCAST_GRP_ID = 1;

enum bit<16> ether_type_t {
    IPV4 = 0x0800,
    ARP = 0x0806,
    ETHERTYPE_AFC = 0x2001
}
enum bit<8> ipv4_proto_t {
    TCP = IP_PROTOCOL_TCP,
    UDP = IP_PROTOCOL_UDP
}

const bit<16> UDP_ROCE_V2 = 4791;  // UDP RoCEv2

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header arp_h {
    bit<16> htype;
    bit<16> ptype;
    bit<8> hlen;
    bit<8> plen;
    bit<16> oper;
    mac_addr_t sender_hw_addr;
    ipv4_addr_t sender_ip_addr;
    mac_addr_t target_hw_addr;
    ipv4_addr_t target_ip_addr;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<6> dscp;
    bit<2> ecn;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

/**
 * @brief RoCEv2 headers
 */

header ib_bth_h {
    bit<8> opcode;
    bit<8> flags;  // 1 bit solicited event, 1 bit migreq, 2 bit padcount, 4 bit headerversion
    bit<16> partition_key;
    bit<8> reserved0;
    bit<24> destination_qp;
    bit<1> ack_request;
    bit<7> reserved1;
    bit<24> packet_seqnum;
}


header adv_flow_ctl_h {
    bit<32> adv_flow_ctl;

    /** 32-bit adv_flow_ctl format */
    // bit<1> qfc;
    // bit<2> tm_pipe_id;
    // bit<4> tm_mac_id;
    // bit<3> _pad;
    // bit<7> tm_mac_qid;
    // bit<15> credit; 
}


/***********************  H E A D E R S  ************************/

struct header_t {
    ethernet_h ethernet;
    adv_flow_ctl_h afc_msg;
    ipv4_h ipv4;
    arp_h arp;
    tcp_h tcp;
    udp_h udp;
    ib_bth_h bth;
}

/******  G L O B A L   I N G R E S S   M E T A D A T A  *********/
struct metadata_t {
    bit<32> where_to_afc;
    PortId_t eg_port;
    bit<1> eg_bypass;
}



/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

/***********************  P A R S E R  **************************/
parser SwitchIngressParser(packet_in pkt,
                out header_t hdr,
                out metadata_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md,
                out ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm,
                out ingress_intrinsic_metadata_from_parser_t ig_intr_md_from_prsr){
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);  // macro defined in tofino.p4
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type){
			(bit<16>)ether_type_t.IPV4: parse_ipv4;
			(bit<16>)ether_type_t.ARP: parse_arp;
			(bit<16>)ether_type_t.ETHERTYPE_AFC : parse_afc;
			default: accept;
		}
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            (bit<8>)ipv4_proto_t.TCP : parse_tcp;
            (bit<8>)ipv4_proto_t.UDP : parse_udp;
            default: accept;
        }
    }

    state parse_afc {
		pkt.extract(hdr.afc_msg);
		transition accept;
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
            UDP_ROCE_V2: parse_bth; 
            default: accept;
        }
    }

    state parse_bth {
        pkt.extract(hdr.bth);
        transition accept;
    }
}





/***************** M A T C H - A C T I O N  *********************/

control SwitchIngress(
    /* User */
    inout header_t hdr,
    inout metadata_t meta,
    /* Intrinsic */
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_intr_md_from_prsr,
    inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr,
    inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm) {
        
    action nop(){}
    action drop(bit<3> drop_bits) { ig_intr_md_for_dprsr.drop_ctl = drop_bits; }
    action forward(PortId_t port) { 
		ig_intr_md_for_tm.ucast_egress_port = port;
	}
	table simple_l2_forward {
		key = {
			ig_intr_md.ingress_port: exact;
		}
		actions = {
			forward;
			@defaultonly nop;
		}
		const default_action = nop();
		size = 256;
	}
    
    /** 0: Ingress, 1: Egress */
    Register<bit<32>, bit<1>>(1, 0) afc_where;
    RegisterAction<bit<32>, bit<1>, bit<32>>(afc_where) check_afc_where = {
        void apply(inout bit<32> value, out bit<32> result){
            result = value;
        }
    };
    action do_check_afc_where() {
        meta.where_to_afc = check_afc_where.execute(0);
    }

    Register<bit<32>, bit<1>>(1, 160) afc_forward;
    RegisterAction<bit<32>, bit<1>, bit<32>>(afc_forward) check_afc_forward = {
        void apply(inout bit<32> value, out bit<32> result){
            result = value;
        }
    };
    action do_check_afc_forward() {
        meta.eg_port = (PortId_t)check_afc_forward.execute(0);
    }


    Register<bit<32>, bit<1>>(1, 1) afc_egress_bypass;
    RegisterAction<bit<32>, bit<1>, bit<1>>(afc_egress_bypass) check_afc_egress_bypass = {
        void apply(inout bit<32> value, out bit<1> result){
            result = value[0:0];
        }
    };
    action do_check_afc_egress_bypass() {
        meta.eg_bypass = check_afc_egress_bypass.execute(0);
    }

    Register<bit<32>, bit<1>>(1, 0) afc_record;
    RegisterAction<bit<32>, bit<1>, bit<1>>(afc_record) check_afc_record = {
        void apply(inout bit<32> value, out bit<1> result){
            value = hdr.afc_msg.adv_flow_ctl;
        }
    };
    action do_check_afc_record() {
        check_afc_record.execute(0);
    }


    apply {
        if(hdr.ethernet.ether_type == (bit<16>) ether_type_t.ARP){
			// do the broadcast to all involved ports
			ig_intr_md_for_tm.mcast_grp_a = MCAST_GRP_ID;
			ig_intr_md_for_tm.rid = 0;
		} else {    
            if (ig_intr_md.ingress_port == (PortId_t)160) {
                drop(0x1);
                exit;
            }
            do_check_afc_forward(); // -> meta.eg_port
            do_check_afc_where(); // -> meta.where_to_afc (0: ingress, 1: egress)
            do_check_afc_egress_bypass(); // meta.eg_bypass (1: bypass)

            if (hdr.ethernet.ether_type == (bit<16>)ether_type_t.ETHERTYPE_AFC) {
                forward(meta.eg_port);
                if (meta.where_to_afc == 0) { /* AFC at Ingress */
                    /* pass adv_flow_ctl message */
                    ig_intr_md_for_dprsr.adv_flow_ctl = hdr.afc_msg.adv_flow_ctl;
                    ig_intr_md_for_tm.bypass_egress = meta.eg_bypass; // uncomment to bypass egress processing
                    do_check_afc_record(); // debugging
                }
            } else { 
                /* forward */
                simple_l2_forward.apply();
            }
        }
        // ig_intr_md_for_tm.bypass_egress = 1; // uncomment to bypass egress processing
    }
}

/*********************  D E P A R S E R  ************************/

control SwitchIngressDeparser(packet_out pkt,
                        /* User */
                        inout header_t hdr,
                        in metadata_t meta,
                        /* Intrinsic */
                        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    
    Checksum() ipv4_checksum;

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

        pkt.emit(hdr);
    }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/


    /***********************  P A R S E R  **************************/

parser SwitchEgressParser(packet_in pkt,
    out header_t hdr,
    out metadata_t meta,
    out egress_intrinsic_metadata_t eg_intr_md,
    out egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr){

    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            (bit<16>)ether_type_t.IPV4 : parse_ipv4;
            (bit<16>)ether_type_t.ARP : parse_arp;
			(bit<16>)ether_type_t.ETHERTYPE_AFC : parse_afc;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            (bit<8>)ipv4_proto_t.TCP : parse_tcp;
            (bit<8>)ipv4_proto_t.UDP : parse_udp;
            default: accept;
        }
    }

    state parse_afc {
		pkt.extract(hdr.afc_msg);
		transition accept;
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
            UDP_ROCE_V2: parse_bth; 
            default: accept;
        }
    }

    state parse_bth {
        pkt.extract(hdr.bth);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control SwitchEgress(
    inout header_t hdr,
    inout metadata_t meta,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
    inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {
    
    Register<bit<32>,_>(1, 0) reg_debug_cntr0;
	RegisterAction<bit<32>, _, bit<32>>(reg_debug_cntr0) reg_debug_cntr0_action = {
        void apply(inout bit<32> reg, out bit<32> result) {
			reg = (bit<32>)eg_intr_md.egress_port;
        }
    };

    Register<bit<32>,_>(1, 0) reg_debug_egress_qid;
	RegisterAction<bit<32>, _, bit<32>>(reg_debug_egress_qid) reg_debug_egress_qid_action = {
        void apply(inout bit<32> reg, out bit<32> result) {
			reg = (bit<32>)eg_intr_md.egress_qid;
        }
    };


    apply {
        reg_debug_cntr0_action.execute(0); /* just counting */
        
        reg_debug_egress_qid_action.execute(0); /* get egress_qid (is it 0, or 16, when ingress's qid was 0?) */

        if (hdr.afc_msg.isValid()) {
            eg_intr_md_for_dprsr.adv_flow_ctl = hdr.afc_msg.adv_flow_ctl;
        }

    }
}

    /*********************  D E P A R S E R  ************************/

control SwitchEgressDeparser(packet_out pkt,
    /* User */
    inout header_t                       hdr,
    in    metadata_t                      meta,
    /* Intrinsic */
    in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr){

    Checksum() ipv4_checksum;

	apply{
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


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    SwitchIngressParser(),
    SwitchIngress(),
    SwitchIngressDeparser(),
    SwitchEgressParser(),
    SwitchEgress(),
    SwitchEgressDeparser()
) pipe;

Switch(pipe) main;