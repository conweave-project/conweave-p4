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
*       M A P   R E G - I N D E X   F O R   Q D E P T H   H I S T O R Y 
****************************************************************************/
action get_idx_queue_occupancy_array_data_eg(conweave_qdepth_idx_width_t idx) {
    meta.idx_qdepth_history_rx = idx;
    meta.hit_idx_queue_occupancy_tbl_eg = 1;
}

table do_get_idx_queue_occupancy_array_data_eg {
    key = {
        eg_intr_md.egress_port:     exact; // 9 bits
        eg_intr_md.egress_qid:	    exact; // 7 bits
    }
    actions = { get_idx_queue_occupancy_array_data_eg; @defaultonly nop; }
    const default_action = nop();
    size = CONWEAVE_QDEPTH_IDX_SIZE;
}

action get_idx_queue_occupancy_array_ctrl_eg(conweave_qdepth_idx_width_t idx) {
    meta.idx_qdepth_history_rx = idx;
    meta.hit_idx_queue_occupancy_tbl_eg = 1;
}

table do_get_idx_queue_occupancy_array_ctrl_eg {
    key = {
        hdr.cwctrl.afc_msg:     exact; // 32 bits
    }
    actions = { get_idx_queue_occupancy_array_ctrl_eg; @defaultonly nop; }
    const default_action = nop();
    size = CONWEAVE_QDEPTH_IDX_SIZE;
}

/****************************************************************************
*           		 D C Q C N   C O N F I G U R A T I O N 
****************************************************************************/


// ##### DCQCN ECN Marking #####
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

action dcqcn_check_ecn_marking() {
    meta.mark_ecn_codepoint = 1;
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
// ##### DCQCN ECN Marking (end) #####



/****************************************************************************
* 		 P O R T S   F R O M   T O R   T O   D E S T I N A T I O N  
****************************************************************************/

action check_toward_dst() { 
    meta.last_hop = 1; 
}
table do_check_toward_dst {
    key = {
        eg_intr_md.egress_port : 	exact;
    }
    actions = { 
        check_toward_dst; @defaultonly nop;
    }
    const default_action = nop();
    size = 256;
}

