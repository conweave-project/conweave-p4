/* -*- P4_16 -*- */
#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "includes/headers.p4"
#include "includes/parser.p4"

const int MCAST_GRP_ID = 1; // for ARP
const bit<9> RECIRC_PORT_PIPE_1 = 196; // recirculation port
const bit<32> OUT_OF_RANGE_24BIT = 32w16777216; // 2^24

const bit<10> MIRROR_SESSION_RDMA_ID_IG = 10w777;
const bit<10> MIRROR_SESSION_RDMA_ID_EG = 10w888;

const int MAX_PORTS = 256;


control SwitchIngress(
    inout header_t hdr,
    inout metadata_t meta,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_intr_md_from_prsr,
    inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr,
    inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm){

	/**
	 * @brief L2 Forwarding
	 */
	action nop(){}
	action drop(){
		ig_intr_md_for_dprsr.drop_ctl = 0b001;
	}

	action miss(bit<3> drop_bits) {
		ig_intr_md_for_dprsr.drop_ctl = drop_bits;
	}

	action forward(PortId_t port){
		ig_intr_md_for_tm.ucast_egress_port = port;
	}

	/* What we mainly use for switching/routing */
	table l2_forward {
		key = {
			meta.port_md.switch_id: exact;
			hdr.ethernet.dst_addr: exact;
		}

		actions = {
			forward;
			@defaultonly miss;
		}

		const default_action = miss(0x1);
	}

    /* Mirroring packets to Sniff Port */
    action mirror_to_collector(bit<10> ing_mir_ses){
        ig_intr_md_for_dprsr.mirror_type = IG_MIRROR_TYPE_1;
        meta.mirror_session = ing_mir_ses;
		meta.ig_mirror1.ingress_mac_timestamp = ig_intr_md.ingress_mac_tstamp;
		meta.ig_mirror1.opcode = hdr.bth.opcode;
		meta.ig_mirror1.mirrored = (bit<8>)IG_MIRROR_TYPE_1;
    }

	action get_seqnum_to_metadata() {
        meta.ig_mirror1.rdma_seqnum = (bit<32>)hdr.bth.packet_seqnum;
    }

	apply {
		if(hdr.ethernet.ether_type == (bit<16>) ether_type_t.ARP){
			// do the broadcast to all involved ports
			ig_intr_md_for_tm.mcast_grp_a = MCAST_GRP_ID;
			ig_intr_md_for_tm.rid = 0;
		} else { // non-arp packet	
			l2_forward.apply();

			if (hdr.bth.isValid()){ // if RDMA
				#ifdef IG_MIRRORING_ENABLED
				mirror_to_collector(MIRROR_SESSION_RDMA_ID_IG); // ig_mirror all RDMA packets
				get_seqnum_to_metadata();
				#endif
			}
		}

		// Allow egress processing for all switches 
		// ig_intr_md_for_tm.bypass_egress = 1w1; 
	}

}  // End of SwitchIngressControl





/*******************
 * Egress Pipeline *
 * *****************/

control SwitchEgress(
    inout header_t hdr,
    inout metadata_t meta,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
    inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport){

	// DCQCN (9)? DCTCP(5)?
    Register<bit<8>,bit<1>>(1, 9) reg_cc_mode; // default: DCQCN (9)
    RegisterAction<bit<8>,bit<1>,bit<8>>(reg_cc_mode) get_reg_cc_mode = {
		void apply(inout bit<8> reg_val, out bit<8> rv){
			rv = reg_val;
		}
	};
	action get_cc_mode() {
		meta.cc_mode = get_reg_cc_mode.execute(0);
	}

	// DCTCP
	Register<bit<32>,bit<1>>(1,1250) reg_ecn_marking_threshold; // default = 1250 (100KB)
	RegisterAction<bit<32>,bit<1>,bit<1>>(reg_ecn_marking_threshold) cmp_ecn_marking_threshold = {
		void apply(inout bit<32> reg_val, out bit<1> rv){
			if((bit<32>)eg_intr_md.deq_qdepth >= reg_val){
				rv = 1;
			}
			else {
				rv = 0;
			}
		}
	};

	action dctcp_check_ecn_marking(){
		meta.exceeded_ecn_marking_threshold = cmp_ecn_marking_threshold.execute(0);
	}

	action mark_ecn_ce_codepoint(){
		hdr.ipv4.ecn = 0b11;
	}

	// DCQCN
	action dcqcn_mark_probability(bit<8> value) {
		meta.dcqcn_prob_output = value;
	}

	table dcqcn_get_ecn_probability {
		key = {
			eg_intr_md.deq_qdepth : range; // 19 bits
		}
		actions = {
			dcqcn_mark_probability;
		}
		const default_action = dcqcn_mark_probability(0); // default: no ecn mark
		size = 1024;
	}

	Random<bit<8>>() random;  // random seed for sampling
	action dcqcn_get_random_number(){
		meta.dcqcn_random_number = random.get();
	}

	action nop(){}

	action dcqcn_check_ecn_marking() {
		meta.exceeded_ecn_marking_threshold = (bit<1>)1;
	}
	
	table dcqcn_compare_probability {
		key = {
			meta.dcqcn_prob_output : exact;
			meta.dcqcn_random_number : exact;
		}
		actions = {
			dcqcn_check_ecn_marking;
			@defaultonly nop;
		}
		const default_action = nop();
		size = 65536;
	}

	// mirroring
	action encode_eg_mirror_md(bit<2> ecn_mark) {
		meta.eg_mirror1.egress_global_timestamp = eg_intr_md_from_prsr.global_tstamp;
		meta.eg_mirror1.mirrored = (bit<8>)EG_MIRROR_TYPE_1; // eg type
		meta.eg_mirror1.ecn = ecn_mark; // ecn mark
		meta.mirror_session = MIRROR_SESSION_RDMA_ID_EG; // session id
		eg_intr_md_for_dprsr.mirror_type = EG_MIRROR_TYPE_1; // for deparser
	}

	action decode_eg_mirror_md() {
		hdr.ethernet.src_addr = meta.eg_mirror1.egress_global_timestamp;
		hdr.ethernet.dst_addr = (bit<48>)hdr.bth.packet_seqnum;
		hdr.ipv4.ecn = meta.eg_mirror1.ecn;
	}

    // for debugging ECN marking
    Register<bit<32>,bit<1>>(1) reg_ecn_marking_cntr;
    RegisterAction<bit<32>,bit<1>,bit<1>>(reg_ecn_marking_cntr) incr_ecn_marking_cntr = {
		void apply(inout bit<32> reg_val, out bit<1> rv){
			reg_val = reg_val |+| 1;
		}
	};

	apply{
		/* IG_MIRRORING : RDMA Monitoring */
		#ifdef IG_MIRRORING_ENABLED
		if (meta.ig_mirror1.mirrored == (bit<8>)IG_MIRROR_TYPE_1) {
			/* Timestamp -> MAC Src Address*/
			hdr.ethernet.src_addr = meta.ig_mirror1.ingress_mac_timestamp; // 48 bits
			/* Sequence Number -> MAC Dst Address */
			hdr.ethernet.dst_addr = (bit<48>)meta.ig_mirror1.rdma_seqnum;
		}
		#endif

		/* ECN */
		if (hdr.ipv4.ecn == 0b01 || hdr.ipv4.ecn == 0b10){
			get_cc_mode();
			if (meta.cc_mode == 5) {
				/* DCTCP (static marking) */
				dctcp_check_ecn_marking(); 
			} else if (meta.cc_mode == 9) {
				/* DCQCN (RED-like marking) */
				dcqcn_get_ecn_probability.apply(); // get probability to ecn-mark
				dcqcn_get_random_number(); // get random number for sampling
				dcqcn_compare_probability.apply();
			}
			if (meta.exceeded_ecn_marking_threshold == 1){
				mark_ecn_ce_codepoint();
				incr_ecn_marking_cntr.execute(0);
			}
		}

		/* EG_MIRRORING : RDMA_Monitoring */
		#ifdef EG_MIRRORING_ENABLED
		if (hdr.bth.isValid()) { 
			if (meta.eg_mirror1.mirrored != (bit<8>)EG_MIRROR_TYPE_1) { // to be mirrored
				encode_eg_mirror_md(hdr.ipv4.ecn);
			} else { // mirrored
				decode_eg_mirror_md();
				// debugging of eg_mirror
				if (hdr.ipv4.ecn == 0b11) {
					incr_ecn_marking_cntr.execute(0);
				}	
			}
		}
		#endif
	} // end of apply block

} // End of SwitchEgress


Pipeline(SwitchIngressParser(),
		 SwitchIngress(),
		 SwitchIngressDeparser(),
		 SwitchEgressParser(),
		 SwitchEgress(),
		 SwitchEgressDeparser()
		 ) pipe;

Switch(pipe) main;
