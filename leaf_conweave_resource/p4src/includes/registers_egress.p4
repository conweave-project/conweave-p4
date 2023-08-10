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
*              D E Q U E U E   C O U N T E R   A T   E G R E S S
****************************************************************************/
Register<bit<32>, conweave_qdepth_idx_width_t>(size=CONWEAVE_QDEPTH_IDX_SIZE) reg_buffer_egress_cntr;
RegisterAction<bit<32>, conweave_qdepth_idx_width_t, bit<32>>(reg_buffer_egress_cntr) reg_read_reset_buffer_egress_cntr = { 
    void apply(inout bit<32> reg, out bit<32> result){
        if (hdr.cwctrl.drop == 1) {
            reg = 0; /** DROP: reorder is resolved, reset counter to 0 */
        }
        result = reg; /** READ: read register and save to cwctrl header  */
    }
};
RegisterAction<bit<32>, conweave_qdepth_idx_width_t, bit<32>>(reg_buffer_egress_cntr) reg_increment_buffer_egress_cntr = { 
    void apply(inout bit<32> reg){
        reg = reg |+| 1; /** DEQUEUE: increase counter by 1 */
    }
};
action do_read_reset_buffer_egress_cntr() {
    hdr.cwctrl.cntr_eg = reg_read_reset_buffer_egress_cntr.execute(meta.idx_qdepth_history_rx);
}
action do_increment_buffer_egress_cntr() {
    reg_increment_buffer_egress_cntr.execute(meta.idx_qdepth_history_rx);
}




/****************************************************************************
*			R E O R D E R   Q U E U E   F L U S H   B Y   T A I L
****************************************************************************/
Register<bit<8>, hashidx_t>(size=CONWEAVE_TABLE_SIZE) reg_tail_resume;
RegisterAction<bit<8>, hashidx_t, bit<1>>(reg_tail_resume) reg_check_tail_resume = { 
    void apply(inout bit<8> reg, out bit<1> result){
        result = (bit<1>)reg;
        if (reg == 1) {
            reg = 0;
        }
    }
};
RegisterAction<bit<8>, hashidx_t, bit<1>>(reg_tail_resume) reg_update_tail_resume = { 
    void apply(inout bit<8> reg, out bit<1> result){
        reg = 1;
    }
};
action do_check_tail_resume() {
    meta.flag_check_tail_resume = reg_check_tail_resume.execute((hashidx_t)hdr.cwctrl.hashidx);
}
action do_update_tail_resume() {
    reg_update_tail_resume.execute((hashidx_t)hdr.tailh.hashidx);
}



/****************************************************************************
*				 			E C N   M A R K I N G
****************************************************************************/

// ##### DCTCP ECN Marking #####
Register<bit<32>,bit<1>>(1,524287) reg_ecn_marking_threshold; // default = 2^19 - 1 
RegisterAction<bit<32>,bit<1>,bit<1>>(reg_ecn_marking_threshold) cmp_ecn_marking_threshold = {
    void apply(inout bit<32> reg_val, out bit<1> rv){
        if((bit<32>)eg_intr_md.deq_qdepth >= reg_val){
            rv = 1;
        }
        else{
            rv = 0;
        }
    }
};
action check_ecn_marking_threshold(){
    meta.mark_ecn_codepoint = cmp_ecn_marking_threshold.execute(0);
}



/****************************************************************************
*					 			 D E B U G G I N G  
****************************************************************************/
Register<bit<32>,bit<1>>(1, 0) reg_debug_eg_cntr1;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_eg_cntr1) reg_debug_eg_cntr1_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        reg = reg + 1;
    }
};
action do_debug_eg_cntr1() {
    reg_debug_eg_cntr1_action.execute(0);
}
Register<bit<32>,bit<1>>(1, 0) reg_debug_eg_cntr2;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_eg_cntr2) reg_debug_eg_cntr2_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        reg = reg + 1;
    }
};
action do_debug_eg_cntr2() {
    reg_debug_eg_cntr2_action.execute(0);
}
Register<bit<32>,bit<1>>(1, 0) reg_debug_eg_cntr3;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_eg_cntr3) reg_debug_eg_cntr3_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        reg = reg + 1;
    }
};
action do_debug_eg_cntr3() {
    reg_debug_eg_cntr3_action.execute(0);
}
Register<bit<32>,bit<1>>(1, 0) reg_debug_eg_cntr4;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_eg_cntr4) reg_debug_eg_cntr4_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        reg = reg + 1;
    }
};
action do_debug_eg_cntr4() {
    reg_debug_eg_cntr4_action.execute(0);
}
Register<bit<32>,bit<1>>(1, 0) reg_debug_eg_cntr5;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_eg_cntr5) reg_debug_eg_cntr5_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        reg = reg + 1;
    }
};
action do_debug_eg_cntr5() {
    reg_debug_eg_cntr5_action.execute(0);
}
