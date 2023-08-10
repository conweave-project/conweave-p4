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
*    				B A S I C   F U N C T I O N S 
****************************************************************************/
action nop() {}

action drop(bit<3> drop_bits) {
    ig_intr_md_for_dprsr.drop_ctl = drop_bits;
}

action set_port(PortId_t port) {
    meta.out_port = port;
}

action forward_port(PortId_t port) {
    ig_intr_md_for_tm.ucast_egress_port = port;
}

action forward_queue(QueueId_t qid) {
    ig_intr_md_for_tm.qid = qid;

}

action bypass_egress() {
    ig_intr_md_for_tm.bypass_egress = 1w1;
}

action resubmit_tx() { /* resubmit */
    ig_intr_md_for_dprsr.resubmit_type = RESUB_DPRSR_DIGEST_REPLY; 
}

action recirculate_rx() { // only for each out_port of ToR->Server
#if (LPBK_FOR_CTRL == 1)
    meta.out_port = (bit<9>)16; // loopback port XXX
#else
    meta.out_port[8:7] = meta.pipeline_index; // pipeline index
    meta.out_port[6:0] = (bit<7>)RECIRC_PORT; /* RECIRC PORT (for each pipe) */
#endif
    hdr.ipv4.ecn = 0x0; /* disable ECN during recirculation */
}

action swap_src_dst_fields() { /* swap srcip <-> dstip */
    meta.dummy_32b = hdr.ipv4.dst_addr;
    hdr.ipv4.dst_addr = hdr.ipv4.src_addr;
    hdr.ipv4.src_addr = meta.dummy_32b;
}

/****************************************************************************
*    				 C O N W E A V E   -   T X   T O R  
****************************************************************************/

/* REPLY DEADLINE */
action do_get_new_reply_timeout() {
    meta.ts_new_reply_timeout = meta.ts_now + meta.ts_base_rtt;
}
action do_get_max_reply_timeout() {
    meta.ts_new_reply_timeout = CONWEAVE_MAX_TIMESTAMP; 
}

/* HEADER UPDATE */
action do_update_conweave_header_epoch() {
    hdr.bth.conweave_epoch = meta.result_epoch; /* conweave epoch */
}
action do_update_conweave_header_phase() {
    hdr.bth.conweave_phase = meta.result_phase; /* conweave phase */
}
action do_update_conweave_header_opcode(bit<2> opcode) {
    hdr.bth.conweave_opcode = opcode; /* conweave data tag */
}
action update_conweave_header_tail_flag() { /* reply_timeout -> send TAIL packet */
    hdr.bth.conweave_tail_flag = 1;
}



/****************************************************************************
*    				 C O N W E A V E   -   R X   T O R  
****************************************************************************/
/* hashkey 32 bits */
Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_crc32;
action get_hash_flowkey_step1() { /* creates flow hashkey */
    meta.hash_flowkey = (bit<32>)hash_crc32.get({ hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.udp.src_port});
}
action get_hash_flowkey_step2() { /* crafts non-zero flow hashkey */
    meta.hash_flowkey = meta.hash_flowkey |+| 1;
}

/* Sample QueueID */
Hash<conweave_qid_width_t>(HashAlgorithm_t.CRC8) hash_crc8;
Hash<conweave_qid_width_t>(HashAlgorithm_t.CRC16) hash_crc16;
Hash<conweave_qid_width_t>(HashAlgorithm_t.IDENTITY) hash_identity;
action sample_hash_qid_step_one() {
    meta.hash_qid_sample_c1 = (QueueId_t)(hash_crc8.get({ hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.udp.src_port}));
    meta.hash_qid_sample_c2 = (QueueId_t)(hash_crc16.get({ hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.udp.src_port}));
    meta.hash_qid_sample_c3 = (QueueId_t)(hash_identity.get({ hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.udp.src_port}));
}
action sample_hash_qid_step_two() {
    meta.hash_qid_sample_c1 = meta.hash_qid_sample_c1 + CONWEAVE_QREG_IDX_OFFSET_C1;
    meta.hash_qid_sample_c2 = meta.hash_qid_sample_c2 + CONWEAVE_QREG_IDX_OFFSET_C2;
    meta.hash_qid_sample_c3 = meta.hash_qid_sample_c3 + CONWEAVE_QREG_IDX_OFFSET_C3;
}




/* ADJUST TIMESTAMP WRAP-AROUND */
action do_calc_tx_timegap_ts_rx() {
    meta.ts_timegap_rx = meta.ts_tail |-| meta.ts_phase0_tx; // no wrap-around
}
action do_default_tx_timegap_ts_rx() {
    meta.ts_timegap_rx = CONWEAVE_RX_DEFAULT_WAITING_TIME; // default flush waiting time
    meta.ts_phase0_rx = meta.ts_now; /** NOTE: overwrite as no phase0 info */
}
/* CALC EXPECTED TAIL ARRIVAL TIME */
action do_calc_expected_tail_arrival_phase0_ts_rx() {
    meta.ts_expected_tail_arrival_rx = meta.ts_now + meta.ts_timegap_rx;
}
action do_calc_expected_tail_arrival_phase1_ts_rx() {
    meta.ts_expected_tail_arrival_rx = meta.ts_phase0_rx + meta.ts_timegap_rx;
}


/* HEADER CLEANING */
action invalid_conweave_ig() {
    hdr.cwh.setInvalid(); /* remove conweave header */
}
action initialize_bth_header_ig() {
    hdr.bth.conweave_opcode = 0;
    hdr.bth.conweave_phase = 0;
    hdr.bth.conweave_epoch = 0;
    hdr.bth.conweave_ask_reply = 0;
    hdr.bth.conweave_tail_flag = 0;
    hdr.bth.out_port = 0;
}
