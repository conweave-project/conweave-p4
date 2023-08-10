#ifndef _PARSER_
#define _PARSER_

#include "macro.p4"

enum bit<16> ether_type_t {
    IPV4 = 0x0800,
    ARP = 0x0806,
    CWCTRL = 0x2001, // conweave's ctrl-loop header
    CWTAIL = 0x2002  // conweave's TAIL header
}

enum bit<8> ipv4_proto_t {
    TCP = 6,
    UDP = 17,
    ICMP = 1
}

enum bit<16> udp_proto_t{
    ROCE_V2 = 4791,
    FAKE_ROCE_V2 = 4792  // XXX
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
    out ingress_intrinsic_metadata_from_parser_t ig_intr_md_from_prsr) {
    state start {
        pkt.extract(ig_intr_md);
        /****************************************************************************
        *    	        M E T A D A T A   I N I T I A L I Z A T I O N
        ****************************************************************************/

        meta.pipeline_index = ig_intr_md.ingress_port [8:7];  // index of pipeline
        meta.mirror_session = 0;
        meta.conweave_on_off = 0;
        meta.conweave_logic = 0;
        meta.switch_id = 0;
        meta.nexthop_id = 0;
        meta.out_port = 0;
        meta.out_queue_id = 0;
        meta.last_hop = 0;

        meta.dummy_32b = 0;
        meta.ts_now = 0;
        meta.ts_tail = 0;
        meta.hashidx = 0;
        meta.digest_on = 0;

        /*-----	C O N W E A V E   -   TxToR   M E T A D A T A -----*/
        meta.ts_base_rtt = 0;
        meta.ts_new_reply_timeout = 0;
        
        meta.sample_port_c1 = 0;
        meta.sample_port_c2 = 0;
        meta.good_port = 0;
        meta.final_port = 0;
        meta.no_good_port = 0;
        meta.stage_to_record_port = 0;
        
        meta.flag_rdma_data = 0;
        meta.flag_matched = 0;
        meta.flag_enforce_no_reroute = 0;
        meta.result_expired = 0;
        meta.result_stability = 0;
        meta.result_reply_timeout = 0;
        meta.result_timely_replied = 0;
        meta.result_phase = 0;
        meta.result_epoch = 0;
        
        meta.result_port_c1_bad = 0;
        meta.result_port_c2_bad = 0;
        meta.result_reply_with_notify = 0;

        /*----- C O N W E A V E   -   RxToR (DstToR)   M E T A D A T A -----*/
        meta.hash_flowkey = 0;

        meta.ts_phase0_tx = 0;
        meta.ts_phase0_rx = 0;
        meta.ts_timegap_rx = 0;
        meta.ts_expected_tail_arrival_rx = 0;

        meta.result_epoch_rx = 0;
        meta.result_phase0_cch_rx = 0;
        meta.result_tail_cch_rx = 0;
        meta.result_out_of_order_rx = 0;
        meta.result_reorder_status = 0;

        meta.hash_qid_sample_c1 = 0;
        meta.hash_qid_sample_c2 = 0;
        meta.hash_qid_sample_c3 = 0;
        meta.idx_q_occup_arr_rx_c1 = 0;
        meta.idx_q_occup_arr_rx_c2 = 0;
        meta.idx_q_occup_arr_rx_c3 = 0;
        meta.result_q_occupancy_c1 = 0;
        meta.result_q_occupancy_c2 = 0;
        meta.result_q_occupancy_c3 = 0;
        meta.result_time_flush_queue_rx = 0;
        meta.possibly_tail_before_timeout = 0;
        meta.flag_mirr_for_ctrl_loop = 0;
        meta.result_tail_send_reply_rx = 0;
        meta.result_q_pkt_cntr_ig = 0;
        meta.flag_finish_reorder_process = 0;
        meta.flag_resume_reorder_queue = 0;
        meta.idx_qdepth_history_rx = 0;

        /**** TEMPORARILY *****/
        meta.cntr_additive = 0;


        /*----- A D V A N C E D   F L O W   C O N T R O L -----*/   
        meta.afc_msg_c1 = 0;
        meta.afc_msg_c2 = 0;
        meta.afc_msg_c3 = 0;

        /*------ D C Q C N -----*/
        meta.mark_ecn_codepoint = 0;
        meta.is_roce_v2 = 0;
        meta.dcqcn_prob_output = 0;
        meta.dcqcn_random_number = 0;

        /*------ M I R R O R I N G ------*/
        meta.ig_mirror1.mirror_option = 0;
        
        /*---- R E A D   H E A D E R ----*/
        meta.pkt_epoch = 0;
        meta.pkt_phase = 0;
        meta.pkt_ask_reply = 0;
        meta.pkt_tail_flag = 0;

        meta.flag_cwctrl_active = 0;
        meta.pkt_cwctrl_timeout = 0;
        meta.pkt_cwctrl_cntr_eg = 0;
        meta.pkt_cwctrl_drop = 0;
        meta.pkt_cwctrl_afc_msg = 0;

        meta.init_cntr_ig.lo = 0;
        meta.init_cntr_ig.hi = CONWEAVE_MAX_TIMESTAMP;

        /*----- D E B U G -----*/
        meta.flag_something_wrong = 0;

        transition select(ig_intr_md.resubmit_flag) {
            (0) : init_metadata;
            (1) : parse_resubmit;
        }
    }

    state parse_resubmit {
        pkt.extract(meta.resubmit_hdr);
        pkt.advance(PORT_METADATA_SIZE - sizeInBits(meta.resubmit_hdr));
        transition parse_ethernet;
    }

    state init_metadata {
        pkt.advance(PORT_METADATA_SIZE);  // macro defined in tofino.p4
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            (bit<16>)ether_type_t.IPV4 : parse_ipv4;
            (bit<16>)ether_type_t.ARP : parse_arp;
            (bit<16>)ether_type_t.CWCTRL : parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);

        /* copy src/dst ip address */
        meta.meta_src_addr = hdr.ipv4.src_addr;
        meta.meta_dst_addr = hdr.ipv4.dst_addr;

        transition select(hdr.ipv4.protocol) {
            (bit<8>)ipv4_proto_t.TCP : parse_tcp;
            (bit<8>)ipv4_proto_t.UDP : parse_udp;
            (bit<8>)ipv4_proto_t.ICMP : parse_icmp;
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
            (bit<16>)udp_proto_t.ROCE_V2 : parse_bth;
            (bit<16>)udp_proto_t.FAKE_ROCE_V2 : parse_bth;  // XXX
            default: accept;
        }
    }

    state parse_bth {
        pkt.extract(hdr.bth);
        meta.is_roce_v2 = 1;  // RDMA packet
        transition select(hdr.bth.conweave_opcode) {
            (bit<2>)1 : parse_conweave;
            (bit<2>)2 : parse_conweave;
            (bit<2>)3 : parse_conweave;
            default: accept;
        }
    }

    state parse_conweave {
        /* pkt metadata */
        meta.pkt_epoch = hdr.bth.conweave_epoch;         /* get pkt's epoch */
        meta.pkt_phase = hdr.bth.conweave_phase;         /* get pkt's phase */
        meta.pkt_ask_reply = hdr.bth.conweave_ask_reply; /* get pkt's ask_reply */
        meta.pkt_tail_flag = hdr.bth.conweave_tail_flag;   /* get tail flag */

        pkt.extract(hdr.cwh);
        transition select(hdr.ethernet.ether_type) {
            (bit<16>)ether_type_t.CWCTRL : parse_cwctrl;
            default: accept;
        }
    }


    state parse_cwctrl {
        pkt.extract(hdr.cwctrl); 
        meta.flag_cwctrl_active = 1;
        meta.pkt_cwctrl_timeout = hdr.cwctrl.timeout;
        meta.pkt_cwctrl_drop = hdr.cwctrl.drop;
        meta.pkt_cwctrl_cntr_eg = hdr.cwctrl.cntr_eg;
        meta.pkt_cwctrl_afc_msg = hdr.cwctrl.afc_msg;
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
    Resubmit() resubmit;

    apply {
        /* CHECKSUM */
        hdr.ipv4.hdr_checksum = ipv4_checksum.update({hdr.ipv4.version,
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

        /* RESUBMIT */
        if (ig_dprsr_md.resubmit_type == RESUB_DPRSR_DIGEST_REPLY) {
            resubmit.emit(meta.resubmit_hdr);
        }

        /* INGRESS MIRRORING FOR REPLY/NOTIFY */
        if (ig_dprsr_md.mirror_type == IG_MIRROR_TYPE_1) {
            mirror.emit<ig_mirror1_h>(meta.mirror_session, {meta.ig_mirror1.mirror_option});
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
    out egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr) {
    state start {
        pkt.extract(eg_intr_md);


        /*---- R E A D   H E A D E R ----*/
        meta.pkt_epoch = 0;
        meta.pkt_phase = 0;
        meta.pkt_ask_reply = 0;
        meta.pkt_tail_flag = 0;

        meta.flag_cwctrl_active = 0;
        meta.pkt_cwctrl_timeout = 0;
        meta.pkt_cwctrl_drop = 0;
        meta.pkt_cwctrl_cntr_eg = 0;
        meta.pkt_cwctrl_afc_msg = 0;


        transition parse_metadata;
    }

    state parse_metadata {
        /* D C Q C N */
        meta.mark_ecn_codepoint = 0;
        meta.is_roce_v2 = 0;
        meta.dcqcn_prob_output = 0;
        meta.dcqcn_random_number = 0;
        
        /*---- M E T A D A T A ----*/
        meta.flag_check_tail_resume = 0;

        ig_mirror1_h mirror_md = pkt.lookahead<ig_mirror1_h>();
        transition select(mirror_md.mirror_option) {
            1 : parse_mirror_reply_notify;
            2 : parse_mirror_reply_notify;
            3 : parse_mirror_reply_notify;
            4 : parse_mirror_reply_notify;
            default: parse_ethernet;
        }
    }

    /* mirroring */
    state parse_mirror_reply_notify {
        pkt.extract(meta.ig_mirror1);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            (bit<16>)ether_type_t.IPV4 : parse_ipv4;
            (bit<16>)ether_type_t.CWCTRL : parse_ipv4;
            (bit<16>)ether_type_t.CWTAIL  : parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            // (bit<8>) ipv4_proto_t.TCP: parse_tcp;
            (bit<8>)ipv4_proto_t.UDP : parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            (bit<16>)udp_proto_t.ROCE_V2 : parse_bth;
            (bit<16>)udp_proto_t.FAKE_ROCE_V2 : parse_bth;  // XXX
            default: accept;
        }
    }

    state parse_bth {
        pkt.extract(hdr.bth);
        meta.is_roce_v2 = 1;  // RDMA packet
        transition select(hdr.bth.conweave_opcode) {
            (bit<2>)1 : parse_conweave;
            (bit<2>)2 : parse_conweave;
            (bit<2>)3 : parse_conweave;
            default: accept;
        }
    }

    state parse_conweave {
        /* pkt metadata */
        meta.pkt_epoch = hdr.bth.conweave_epoch;         /* get pkt's epoch */
        meta.pkt_phase = hdr.bth.conweave_phase;         /* get pkt's phase */
        meta.pkt_ask_reply = hdr.bth.conweave_ask_reply; /* get pkt's ask_reply */
        meta.pkt_tail_flag = hdr.bth.conweave_tail_flag;   /* get tail flag */

        pkt.extract(hdr.cwh);
        transition select(hdr.ethernet.ether_type) {
            (bit<16>)ether_type_t.CWCTRL : parse_cwctrl;
            (bit<16>)ether_type_t.CWTAIL  : parse_cwtail;
            default: accept;
        }
    }


    state parse_cwctrl {
        pkt.extract(hdr.cwctrl); 
        meta.flag_cwctrl_active = 1;
        meta.pkt_cwctrl_timeout = hdr.cwctrl.timeout;
        meta.pkt_cwctrl_drop = hdr.cwctrl.drop;
        meta.pkt_cwctrl_cntr_eg = hdr.cwctrl.cntr_eg;
        meta.pkt_cwctrl_afc_msg = hdr.cwctrl.afc_msg;
        transition accept;
    }

    state parse_cwtail {
        pkt.extract(hdr.tailh);
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
    in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr) {
    apply {
        // do more stuff here if needed
        pkt.emit(hdr);
    }
}

#endif