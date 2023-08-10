/* -*- P4_16 -*- */
#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "headers.p4"
#include "macro.p4"
#include "parser.p4"


/****************************************************************************
* C O M M O N   F U N C T I O N S   -   E C M P ,  L A S T H O P,  R D M A 
****************************************************************************/

/* Check RDMA data packets (to dynamically reroute) */
action set_rdma_data() {
    meta.flag_rdma_data = 1;
}
table check_rdma_data {
    key = {
        hdr.udp.dst_port : exact;
        hdr.bth.opcode : exact;
    }
    actions = {
        set_rdma_data; @defaultonly nop;
    }
    const default_action = nop();
    size = 64;
}

/* manually get switch_id from ingress port (PORT_METADATA has issue in bf-sde-9.11.0) */
action write_switch_id(switch_id_t switch_id) { 
    meta.switch_id = switch_id; 
}
table get_switch_id {
    key = {
        ig_intr_md.ingress_port: exact;
        hdr.bth.conweave_opcode: ternary;
        meta.meta_src_addr: ternary; // hdr.ipv4.src_addr
        meta.meta_dst_addr: ternary; // hdr.ipv4.dst_addr
    }
    actions = {
        write_switch_id;
        @defaultonly nop;
    }
    const default_action = nop();
    size = 1024;
}

/* Check last_hop */
action acknowledge_last_hop() { 
    meta.last_hop = 1; 
}
table check_last_hop { /* check last-hop pkt (including intra-ToR traffic) */
    key = {
        meta.switch_id: 	  exact; // switchId
        meta.meta_dst_addr:   exact; // hdr.ipv4.dst_addr
    }
    actions = { 
        acknowledge_last_hop; 
        @defaultonly nop; 
    }
    const default_action = nop();
    size = TABLE_IPV4_SIZE;
}

// action write_nexthop_id(nexthop_id_t nexthop_id) { meta.nexthop_id = nexthop_id; /* group id */ } // BUGGY
action write_nexthop_id(nexthop_id_t nexthop_id) { 
    /* NOTE: this is a bad implementation, but we did as our SDE version (9.10.0) had a buggy compiler issue */
    ig_intr_md_for_tm.level1_exclusion_id = (bit<16>)nexthop_id;
    meta.nexthop_id = (nexthop_id_t)ig_intr_md_for_tm.level1_exclusion_id;
}
table get_nexthop_id {
    key = { 
        meta.switch_id: 	exact;
        hdr.ipv4.dst_addr:  exact;
    }
    actions = { write_nexthop_id; @defaultonly nop; }
    const default_action = nop();
    size = TABLE_IPV4_SIZE;
}

Hash<bit<HASH_WIDTH>> (HashAlgorithm_t.CRC16) 	lag_ecmp_hash;
ActionProfile(size = MAX_PROFILE_MEMBERS) 		lag_ecmp;
ActionSelector(
    action_profile = lag_ecmp /* profile */,
    hash           = lag_ecmp_hash /* hash */,
    mode           = SelectorMode_t.FAIR /* fair */,
    max_group_size = MAX_GROUP_SIZE,
    num_groups     = MAX_GROUPS) lag_ecmp_sel /* selector */;

@selector_enable_scramble(SCRAMBLE_ENABLE) /* enable non-linear hash */
table nexthop {
    key = {
        meta.nexthop_id : 			exact;
        hdr.ipv4.src_addr : 		selector;
        hdr.ipv4.dst_addr :			selector;
        hdr.udp.src_port : 		    selector;
    }
    actions = { set_port; drop; }
    const default_action = drop(0x1);
    size = TABLE_NEXTHOP_SIZE;
    implementation = lag_ecmp_sel;
}



/****************************************************************************
*		    	 C O M M O N   C O N W E A V E   F U N C T I O N
****************************************************************************/

/* ConWeave Logical Cateogory -> TxToR / RxToR processing */
action categorize_conweave_logical_step(bit<2> val) {
    meta.conweave_logic = val;
}
table do_categorize_conweave_logical_step {
    key = {
        meta.last_hop : 				exact; // 1b
        hdr.bth.conweave_opcode :		exact; // 2b
    }
    actions = { categorize_conweave_logical_step; nop; }
    const entries = {
        (0, 0) : categorize_conweave_logical_step(1); // TxToR - Tx
        (1, 2) : categorize_conweave_logical_step(1); // TxToR - Received REPLY
        (1, 3) : categorize_conweave_logical_step(1); // TxToR - Received NOTIFY
        (1, 1) : categorize_conweave_logical_step(2); // RxToR - Rx 
        (0, 2) : categorize_conweave_logical_step(2); // RxToR - Sending REPLY
        (0, 3) : categorize_conweave_logical_step(2); // RxToR - Sending NOTIFY
        (0, 1) : categorize_conweave_logical_step(3); // WRONG CONFIG!! not last hop but has cwh header
        (1, 0) : categorize_conweave_logical_step(0); // Intra-ToR traffic - bypass
    }
    size = 8;
}

/* persistent connection -> hash_index (register idx), and base_rtt (for reply-deadline) */
action write_hashidx_basertt(hashidx_t idx, timestamp_t base_rtt) { 
    meta.hashidx = idx; 
    meta.ts_base_rtt = base_rtt;
    meta.flag_matched = 1;
}
table get_hashidx_basertt {
    key = {
        hdr.ipv4.src_addr : 		exact;
        hdr.ipv4.dst_addr :			exact;
        hdr.udp.src_port : 			exact;
    }
    actions = {write_hashidx_basertt; @defaultonly nop; }
    const default_action = nop();
    size = CONWEAVE_TABLE_SIZE;
}



/****************************************************************************
*    				 C O N W E A V E   -   T X   T O R  
****************************************************************************/

/* TWO OUTPORT SAMPLING */
action set_port_c1(bit<8> port) { meta.sample_port_c1 = port; }
Hash<bit<HASH_WIDTH>> (HashAlgorithm_t.CRC16) 	lag_ecmp_hash_c1;
ActionProfile(size = MAX_PROFILE_MEMBERS) 		lag_ecmp_c1;
ActionSelector(
    action_profile = lag_ecmp_c1 /* profile */,
    hash           = lag_ecmp_hash_c1 /* hash */,
    mode           = SelectorMode_t.FAIR /* fair */,
    max_group_size = MAX_GROUP_SIZE,
    num_groups     = MAX_GROUPS) lag_ecmp_sel_c1;

@selector_enable_scramble(SCRAMBLE_ENABLE) /* enable non-linear hash */
table nexthop_c1 {
    key = {
        meta.nexthop_id : 			exact;
        meta.ts_now 	: 			selector;
    }
    actions = { set_port_c1; drop; }
    const default_action = drop(0x1);
    size = TABLE_NEXTHOP_SIZE;
    implementation = lag_ecmp_sel_c1;
}

action set_port_c2(bit<8> port) { meta.sample_port_c2 = port; }
Hash<bit<HASH_WIDTH>> (HashAlgorithm_t.RANDOM) 	lag_ecmp_hash_c2;
ActionProfile(size = MAX_PROFILE_MEMBERS) 		lag_ecmp_c2;
ActionSelector(
    action_profile = lag_ecmp_c2 /* profile */,
    hash           = lag_ecmp_hash_c2 /* hash */,
    mode           = SelectorMode_t.FAIR /* fair */,
    max_group_size = MAX_GROUP_SIZE,
    num_groups     = MAX_GROUPS) lag_ecmp_sel_c2;

@selector_enable_scramble(SCRAMBLE_ENABLE) /* enable non-linear hash */
table nexthop_c2 {
    key = {
        meta.nexthop_id : 			exact;
        meta.ts_now 	: 			selector;
    }
    actions = { set_port_c2; @defaultonly drop; }
    const default_action = drop(0x1);
    size = TABLE_NEXTHOP_SIZE;
    implementation = lag_ecmp_sel_c2;
}



table do_check_and_update_port {
    key = {
        meta.result_expired:        ternary;
        meta.result_reply_timeout:  ternary;
    }
    actions = { 
        do_update_port_if_expired;
        do_update_port_if_reply_timeout;
        do_get_current_port;
    }
    const entries = {
        (1, _) : do_update_port_if_expired(); /* change port from now (i.e., this packet) */
        (_, 1) : do_update_port_if_reply_timeout(); /* change port from next packet */
        (0, 0) : do_get_current_port(); /* e.g., meta.result_stability = 1 */
    }
    size = 3;
}



table do_check_and_update_tail_ts {
    key = {
        meta.result_expired: 		ternary;
        meta.result_reply_timeout:	ternary;
        meta.result_stability: 		ternary;
    }
    actions = { 
        do_get_tail_ts;
        do_set_tail_ts_now;
        do_set_tail_ts_zero;
    }
    const entries = {
        (1, _, _) : do_set_tail_ts_zero(); // meta.ts_tail = 0
        (_, 1, _) : do_set_tail_ts_now(); // meta.ts_tail = meta.ts_now
        (_, _, 1) : do_set_tail_ts_zero(); // meta.ts_tail = 0
        (0, 0, 0) : do_get_tail_ts();
    }
    size = 4;
}

/* update header and decode 8bits -> 9bits port */
action update_header_and_decode_port(PortId_t decoded_port) {
    hdr.bth.out_port = meta.final_port; /* conweave's encoded port */ 
    meta.out_port = decoded_port;  /* decoded port to forward pkt at switch (PortId_t = bit<9>) */
}
table do_update_conweave_header_out_port { /* decoding 8-bits portId to 9-bits */
    key = {
        meta.final_port: exact;
    }
    actions = { update_header_and_decode_port; @defaultonly nop; }
    const default_action = nop();
    size = 256;
}


/* ask reply */
action update_conweave_header_ask_reply() {
    hdr.bth.conweave_ask_reply = 1;
}
table do_update_conweave_header_ask_reply {
    key = {
        meta.result_expired: 		ternary; // new start
        meta.result_reply_timeout:	ternary; // TAIL
        meta.result_stability: 		ternary; // new start
    }
    actions = { update_conweave_header_ask_reply; @defaultonly nop; }
    const entries = {
        (1, _, _) : update_conweave_header_ask_reply(); // INIT
        (_, 1, _) : update_conweave_header_ask_reply(); // TAIL
        (_, _, 1) : update_conweave_header_ask_reply(); // INIT
    }
    const default_action = nop();
    size = 4;
}




/****************************************************************************
*    				 C O N W E A V E   -   R X   T O R  
****************************************************************************/
/* check epoch - output: prev(2), curr(0), next(1) -> meta.result_epoch_rx */
table do_check_epoch_rx {
    key = {
        hdr.bth.conweave_epoch: exact;
    }
    actions = { 
        do_check_epoch_pkt_0_rx; 
        do_check_epoch_pkt_1_rx;
        do_check_epoch_pkt_2_rx;
        do_check_epoch_pkt_3_rx; 
    }
    const entries = { /* for bits wrap-around issue */
        (0) : do_check_epoch_pkt_0_rx();
        (1) : do_check_epoch_pkt_1_rx();
        (2) : do_check_epoch_pkt_2_rx();
        (3) : do_check_epoch_pkt_3_rx();
    }
    size = 4;
}

/* give default queue_id (phtsical) for a given dev_port */
action get_default_queue_id(QueueId_t qid) {
    meta.out_queue_id = qid;
}
table do_get_default_queue_id {
    key = {
        meta.out_port:  exact; // 9 bits
    }
    actions = { get_default_queue_id; @defaultonly nop; }
    const default_action = nop();
    size = 512;
}


/* get register index for queue occupancy & afc_msg */
action get_idx_queue_occupancy_array_c1(conweave_qreg_idx_width_t idx, afc_msg_t afc_msg) {
    meta.idx_q_occup_arr_rx_c1 = idx; // 12 bits
    meta.afc_msg_c1 = afc_msg; // 32 bits
}
table do_get_idx_queue_occupancy_array_c1 {
    key = {
        meta.out_port:              exact; // 9 bits
        meta.hash_qid_sample_c1:	exact; // 7 bits (e.g., 2 ~ 5 for 25G, 2 ~ 9 for 100G)
    }
    actions = { get_idx_queue_occupancy_array_c1; @defaultonly nop; }
    const default_action = nop();
    size = CONWEAVE_QREG_IDX_SIZE;
}
/* get register index for queue occupancy & afc_msg */
action get_idx_queue_occupancy_array_c2(conweave_qreg_idx_width_t idx, afc_msg_t afc_msg) {
    meta.idx_q_occup_arr_rx_c2 = idx; // 12 bits
    meta.afc_msg_c2 = afc_msg; // 32 bits
}
table do_get_idx_queue_occupancy_array_c2 {
    key = {
        meta.out_port:              exact; // 9 bits
        meta.hash_qid_sample_c2: 	exact; // 7 bits (e.g., 6 ~ 9 for 25G, 10 ~ 17 for 100G)
    }
    actions = { get_idx_queue_occupancy_array_c2; @defaultonly nop; }
    const default_action = nop();
    size = CONWEAVE_QREG_IDX_SIZE;
}

/* get register index for queue occupancy & afc_msg */
action get_idx_queue_occupancy_array_c3(conweave_qreg_idx_width_t idx, afc_msg_t afc_msg) {
    meta.idx_q_occup_arr_rx_c3 = idx; // 12 bits
    meta.afc_msg_c3 = afc_msg; // 32 bits
}
table do_get_idx_queue_occupancy_array_c3 {
    key = {
        meta.out_port:              exact; // 9 bits
        meta.hash_qid_sample_c3: 	exact; // 7 bits (e.g., 10 ~ 13 for 25G, 18 ~ 25 for 100G)
    }
    actions = { get_idx_queue_occupancy_array_c3; @defaultonly nop; }
    const default_action = nop();
    size = CONWEAVE_QREG_IDX_SIZE;
}


table update_q_occupancy_c1 {
    key = {
        meta.flag_finish_reorder_process:   exact; // 1b
        meta.result_reorder_status:         exact; // 2b
    }
    actions = {
        do_reset_q_occupancy_c1;
        do_register_q_occupancy_c1;
        do_check_q_occupancy_c1;
        @defaultonly nop;
    }
    const entries = {
        (1, 0) : do_reset_q_occupancy_c1();
        (1, 1) : do_reset_q_occupancy_c1();
        (1, 2) : do_reset_q_occupancy_c1();
        (1, 3) : do_reset_q_occupancy_c1();
        (0, 1) : do_check_q_occupancy_c1();
        (0, 2) : do_register_q_occupancy_c1();
    }
    const default_action = nop();
    size = 8;
}


table update_q_occupancy_c2 {
    key = {
        meta.flag_finish_reorder_process:   exact; // 1b
        meta.result_reorder_status:         exact; // 2b
    }
    actions = {
        do_reset_q_occupancy_c2;
        do_register_q_occupancy_c2;
        do_check_q_occupancy_c2;
        @defaultonly nop;
    }
    const entries = {
        (1, 0) : do_reset_q_occupancy_c2();
        (1, 1) : do_reset_q_occupancy_c2();
        (1, 2) : do_reset_q_occupancy_c2();
        (1, 3) : do_reset_q_occupancy_c2();
        (0, 1) : do_check_q_occupancy_c2();
        (0, 2) : do_register_q_occupancy_c2();
    }
    const default_action = nop();
    size = 8;
}



table update_q_occupancy_c3 {
    key = {
        meta.flag_finish_reorder_process:   exact; // 1b
        meta.result_reorder_status:         exact; // 2b
    }
    actions = {
        do_reset_q_occupancy_c3;
        do_register_q_occupancy_c3;
        do_check_q_occupancy_c3;
        @defaultonly nop;
    }
    const entries = {
        (1, 0) : do_reset_q_occupancy_c3();
        (1, 1) : do_reset_q_occupancy_c3();
        (1, 2) : do_reset_q_occupancy_c3();
        (1, 3) : do_reset_q_occupancy_c3();
        (0, 1) : do_check_q_occupancy_c3();
        (0, 2) : do_register_q_occupancy_c3();
    }
    const default_action = nop();
    size = 8;
}



// if (meta.result_tail_send_reply_rx == 1) { /* Send REPLY of TAIL (CLEAR) */
// 	ingress_mirroring(1);
// } else if (meta.pkt_ask_reply == 1 && meta.pkt_tail_flag == 0) { /* Send REPLY of INIT */
// 	ingress_mirroring(2);
// } else if (meta.flag_mirr_for_ctrl_loop == 1) { /* Craft ConWeave CTRL pkt */
//     ingress_mirroring(4); /* Note: NewOoO is always by phase1 pkt, which does not need to be replied */
// } else if (hdr.ipv4.ecn == 0x3) { /* Send NOTIFY */
// 	ingress_mirroring(3);
// }
table do_ingress_mirroring {
    key = {
        meta.result_tail_send_reply_rx : exact;  // 1b
        meta.pkt_ask_reply :            ternary;  // 1b
        meta.pkt_tail_flag :             ternary;  // 1b
        meta.flag_mirr_for_ctrl_loop :  ternary;  // 1b
        hdr.ipv4.ecn:                   ternary;  // 2b
    }
    actions = {
        ingress_mirroring;
        @defaultonly nop;
    }
    const entries = {
        (1, _, _, _, _):    ingress_mirroring(1); // TAIL
        (0, 1, 0, _, _):    ingress_mirroring(2); // INIT
        (0, _, _, 1, _):    ingress_mirroring(4); // CWCTRL
        (0, _, _, _, 3):    ingress_mirroring(3); // NOTIFY
    }
    const default_action = nop();
    size = 4;
}


