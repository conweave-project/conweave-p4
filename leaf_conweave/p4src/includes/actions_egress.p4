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
 *			 			B A S I C   F U N C T I O N S
****************************************************************************/
action nop() {}

action swap_src_dst_fields() { /* swap src and dst */
    /* swap srcip <-> dstip */
    meta.dummy_32b = hdr.ipv4.dst_addr;
    hdr.ipv4.dst_addr = hdr.ipv4.src_addr;
    hdr.ipv4.src_addr = meta.dummy_32b;
}

/* HEADER CLEANING */
action invalid_conweave_eg() {
    hdr.cwh.setInvalid(); /* remove conweave header */
}
action initialize_bth_header_eg() {
    hdr.bth.conweave_opcode = 0;
    hdr.bth.conweave_phase = 0;
    hdr.bth.conweave_epoch = 0;
    hdr.bth.conweave_ask_reply = 0;
    hdr.bth.conweave_tail_flag = 0;
    hdr.bth.out_port = 0;
}

// ##### DCTCP ECN Marking #####
action mark_ecn_ce_codepoint(){
    hdr.ipv4.ecn = 0b11;
}
