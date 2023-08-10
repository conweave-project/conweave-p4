#ifndef _HEADERS_
#define _HEADERS_

#include "macro.p4"

/*******************************************************
 ****            C L A S S I C    H E A D E R       ****
 ********************************************************/

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
    bit<6> dscp;        // tos field
    bit<2> ecn;         // tos field
    bit<16> total_len;  // 1024B MTU RDMA -> 1084 (CX6), 1068 (CX5 except WR_FIRST)
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

header icmp_h {
    bit<8> type_;
    bit<8> code;
    bit<16> hdr_checksum;
    bit<16> id;
    bit<16> seq_no;
    bit<64> data_time;
}

/*---- RDMA (12 bytes) ----*/
header ib_bth_h {
    bit<8> opcode;
    bit<8> flags;  /** NOTE: "flags" field is used for REPLY INIT's ECN (0x3) between SrcToR/DstToR. No effect on RDMA. */
    bit<16> partition_key; 

    /*--- RC reserved0 (8 bits) ----*/
    bit<8> out_port;  
    /*---------------------*/

    bit<24> destination_qp;
    bit<1> ack_request; 

    /*--- RC reserved1 (7 bits)----*/
    bit<2> conweave_opcode; /* 0: NOTHING, 1: DATA, 2: REPLY, 3: NOTIFY */
    bit<1> conweave_phase;
    bit<2> conweave_epoch;
    bit<1> conweave_ask_reply;
    bit<1> conweave_tail_flag; /* TAIL */
    /*---------------------*/

    bit<24> packet_seqnum;
}

// ACK
header ib_aeth_h {
    bit<1> reserved;
    bit<2> opcode;      // (0: ACK, 3: NACK)
    bit<5> error_code;  // (PSN SEQ ERROR)
    bit<8> msg_seq_number;
}

/*******************************************************
 ****    A D V A N C E D   F L O W  C O N T R O L   ****
 *******************************************************/
header conweave_ctrl_h {
    @padding bit<5> _pad1;
    bit<1> pre_timeout; /* 1: pre_timeout (must check egress register) */
    bit<1> timeout; /* 1: timeout triggered */
    bit<1> drop; /* 1: must be dropped */
    bit<32> cntr_eg; /* reorder-buffer egress counter */
    bit<32> afc_msg; /* without credit setup (i.e., the least significant 15 bits are empty) */
    bit<16> hashidx; // hashidx for egress pipeline


    /** AFC: Format */
    // bit<1> qfc;
    // bit<2> tm_pipe_id;
    // bit<4> tm_mac_id;
    // bit<3> _pad;
    // bit<7> tm_mac_qid;
    // bit<15> credit;
}

header conweave_tail_h {
    bit<32> afc_msg_resume;
    bit<16> hashidx; // hashidx for egress pipeline
}

/*******************************************************
 ****        C O N W E A V E    H E A D E R      ****
 *******************************************************/
header conweave_h {
    bit<16> ts_tx;
    bit<16> ts_tail;
}

header resubmit_h {
}

header eg_mirror1_h {
}

header ig_mirror1_h {
    bit<8> mirror_option; /* 1: TAIL's REPLY (CLEAR), 2: INIT's REPLY, 3: NOTIFY, 4: Reorder-Ctrl */
}

struct header_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    arp_h arp;
    tcp_h tcp;
    udp_h udp;
    icmp_h icmp;
    ib_bth_h bth;   /* RDMA headers */
    conweave_h cwh; /* ConWeave header */
    conweave_ctrl_h cwctrl; /* ConWeave Ctrl header */
    conweave_tail_h tailh; /* ConWeave TAIL header (if needed) */
}

/*******************************************************
 ****        H E A D E R  &   M E T A D A T A       ****
 ********************************************************/

struct metadata_t {
    /* resubmit or mirroring */
    resubmit_h resubmit_hdr;
    eg_mirror1_h eg_mirror1;
    ig_mirror1_h ig_mirror1;
    MirrorId_t mirror_session;
    
    /* ConWeave */
    bit<1> conweave_on_off; /* switch on/off */
    bit<2> conweave_logic;  /* 1: TxToR, 2: RxToR, 3: WRONG, 0: intra-ToR */
    bit<2> pipeline_index;  /* ig_intr_md.ingress_port[8:7], see parser */

    /* switch's ID for our virtual topology */
    switch_id_t switch_id;
    nexthop_id_t nexthop_id;
    bit<1> last_hop;
    PortId_t out_port; // final 
    QueueId_t out_queue_id; // final
    

    /* dummy and common metadata */
    ipv4_addr_t dummy_32b; /* for sip<->dip swap (REPLY & NOTIFY) */
    ipv4_addr_t meta_src_addr;
    ipv4_addr_t meta_dst_addr;
    timestamp_t ts_now;
    timestamp_t ts_tail;
    hashidx_t hashidx; /* key & table idx */
    bit<1> digest_on;  /* digest flowkey */


    /* packet metadata */
    bit<2> pkt_epoch;     /* <- hdr.bth.conweave_epoch */
    bit<1> pkt_phase;     /* <- hdr.bth.conweave_phase */
    bit<1> pkt_ask_reply; /* <- hdr.bth.conweave_ask_reply */
    bit<1> pkt_tail_flag;  /* <- hdr.bth.conweave_tail_flag */

    bit<1> flag_cwctrl_active; /* hdr.cwctrl.isValid() */
    bit<1> pkt_cwctrl_timeout; /* <- hdr.cwctrl.timeout */
    bit<1> pkt_cwctrl_drop; /* <- hdr.cwctrl.drop */
    bit<32> pkt_cwctrl_cntr_eg; /* <- hdr.cwctrl.cntr_eg */
    bit<32> pkt_cwctrl_afc_msg; /* <- hdr.cwctrl.afc_msg */

    /* pair for initialization */
    pair init_cntr_ig;
    /***********************************************************
     *		 C O N W E A V E   -   T X    M E T A D A T A
     ***********************************************************/
    /* timestamp */
    timestamp_t ts_base_rtt;
    timestamp_t ts_new_reply_timeout;

    /* sampled port info */
    bit<8> sample_port_c1;        // chance 1
    bit<8> sample_port_c2;        // chance 2
    bit<8> good_port;             // good port without ECN marking
    bit<8> final_port;            // final port to send a current packet
    bit<1> no_good_port;          // if good_port is not actually good enough
    bit<2> stage_to_record_port;  // CRC8 or out_port[1:0]

    /* metadata at TX */
    bit<1> flag_rdma_data;
    bit<1> flag_matched;                // 1: found from get_hash_idx table
    bit<1> flag_enforce_no_reroute;     // 1: enforce not to reroute, since TS_MAX - 10ms
    bit<1> result_expired;              // 1: expired
    bit<1> result_stability;            // 1: stable
    bit<1> result_reply_timeout;        // 1: timeout
    bit<1> result_timely_replied;       // 1: timely replied
    bit<1> result_phase;                // phase 1 is possible only when we call "do_get_phase()"
    bit<2> result_epoch;                // current epoch
    bit<1> result_port_c1_bad;          // 1: sample_c1 is bad port
    bit<1> result_port_c2_bad;          // 1: sample_c2 is bad port
    bit<1> result_reply_with_notify;  // 1: INIT's reply with NOTIFY

    /***********************************************************
     *		 C O N W E A V E   -   R X    M E T A D A T A
     ***********************************************************/
    bit<32> hash_flowkey;

    timestamp_t ts_phase0_tx;
    timestamp_t ts_phase0_rx;    
    timestamp_t ts_timegap_rx; /* tail_tx - phase0_tx */
    timestamp_t ts_expected_tail_arrival_rx; /* time to flush queue */

    bit<2> result_epoch_rx; /* 1: new epoch, 2: prev epoch so bypass, 0: process */
    bit<1> result_phase0_cch_rx; /* 1: phase-0 pkt has passed (or is passing) */
    bit<1> result_tail_cch_rx; /* 1: tail has passed (or is passing) */
    bit<1> result_out_of_order_rx; /* 1: out-of-ordered packet */
    bit<2> result_reorder_status; /* 1: reorder is on-going, 2: new register */
    
    QueueId_t hash_qid_sample_c1; // 25G: 4 queues (2 bits), 100G: 8 queues (3 bits)
    QueueId_t hash_qid_sample_c2; // 25G: 4 queues (2 bits), 100G: 8 queues (3 bits)
    QueueId_t hash_qid_sample_c3; // 25G: 4 queues (2 bits), 100G: 8 queues (3 bits)

    conweave_qreg_idx_width_t idx_q_occup_arr_rx_c1; // 12 bits - port(9) + queue(3)
    conweave_qreg_idx_width_t idx_q_occup_arr_rx_c2; // 12 bits - port(9) + queue(3)
    conweave_qreg_idx_width_t idx_q_occup_arr_rx_c3; // 12 bits - port(9) + queue(3)

    bit<1> result_q_occupancy_c1; /* 1: registered, or matched */
    bit<1> result_q_occupancy_c2; /* 1: registered, or matched */
    bit<1> result_q_occupancy_c3; /* 1: registered, or matched */

    bit<1> result_time_flush_queue_rx; /* 1: timeout */
    bit<1> possibly_tail_before_timeout; /* 1: possibly TAIL before timeout */
    bit<1> flag_mirr_for_ctrl_loop; /* 1: mirror */
    bit<1> result_tail_send_reply_rx; /* 1: send TAIL's reply */
    bit<1> flag_finish_reorder_process; /* 1: reorder is resolved */
    bit<1> flag_resume_reorder_queue; /* 1: resume reorder queue */
    bit<1> flag_check_tail_resume; /* 1: queue is resumed in advance by TAIL */
    bit<32> result_q_pkt_cntr_ig; /* counter */

    /* Egress qdepth metadata */
    conweave_qdepth_idx_width_t idx_qdepth_history_rx; // 13 bits

    
    /***********  T E M P O R A R I L Y  ********/
    bit<1> cntr_additive;



    /***********************************************************
     *		 A D V A N C E D   F L O W   C O N T R O L
     ***********************************************************/
    afc_msg_t afc_msg_c1; // 32 bits, without PAUSE/RESUME instruction yet
    afc_msg_t afc_msg_c2; // 32 bits, without PAUSE/RESUME instruction yet
    afc_msg_t afc_msg_c3; // 32 bits, without PAUSE/RESUME instruction yet


    /***********************************************************
     *		  D C Q C N  -  E C N   M A R K I N G
     ***********************************************************/
    bit<1> mark_ecn_codepoint;
    bit<1> is_roce_v2;
    bit<8> dcqcn_prob_output;
    bit<8> dcqcn_random_number;


    /***********************************************************
     *		  S O M E T H I N G   D E B U G
     ***********************************************************/
    bit<1> flag_something_wrong;

    /***********************************************************
     *		  S O M E T H I N G   E G R E S S 
     ***********************************************************/
    bit<1> hit_idx_queue_occupancy_tbl_eg;
}

#endif