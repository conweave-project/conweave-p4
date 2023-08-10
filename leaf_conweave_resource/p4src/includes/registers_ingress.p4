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

/********************************************************************************
*	        R E G I S T E R / A C T I O N    D E C L A R A T I O N  	        *
*********************************************************************************/

/* Current Time */
Register<timestamp_t, bit<1>>(size=1) reg_dummy_ts_now_32b;
RegisterAction<timestamp_t, bit<1>, bit<32>>(reg_dummy_ts_now_32b) reg_get_ts_now = {
    void apply(inout timestamp_t reg, out bit<32> result) {
         // microseconds resolution
        reg = (timestamp_t)(ig_intr_md_from_prsr.global_tstamp[40+TIME_RESOLUTION_OFFSET2:10+TIME_RESOLUTION_OFFSET1]);
        result = reg;
    }
};
action get_now_timestamp_32b() {
    meta.ts_now = reg_get_ts_now.execute(0);  // 31-bits in microseconds

    // // PHV ERROR
    // meta.ts_now = (timestamp_t)(ig_intr_md_from_prsr.global_tstamp[40+TIME_RESOLUTION_OFFSET2:10+TIME_RESOLUTION_OFFSET1]);
}


/* ConWeave Switch On/Off */
Register<bit<1>, bit<1>>(size=1, initial_value=1) reg_conweave_switch;
RegisterAction<bit<1>, bit<1>, bit<1>>(reg_conweave_switch) reg_check_conweave_on = {
    void apply(inout bit<1> reg, out bit<1> result){
        result = reg;
    }
};
action check_conweave_on() {
    meta.conweave_on_off = reg_check_conweave_on.execute(0);
}


/****************************************************************************
*    				 C O N W E A V E   -   T X   T O R                      *
****************************************************************************/

/* Connection's active time states (don't need clock correction) */
Register<timestamp_t, hashidx_t>(size=CONWEAVE_TABLE_SIZE) reg_active_time;
RegisterAction<timestamp_t, hashidx_t, bit<1>>(reg_active_time) reg_check_active_time = {
    void apply(inout timestamp_t reg, out bit<1> result) {
        if (reg + CONWEAVE_TX_EXPIRED_TS < meta.ts_now) {
            result = 1; // timeout
        } else {
            result = 0; // not timeout	
        }
        reg = meta.ts_now;
    }
};
action do_check_active_time() { 
    meta.result_expired = reg_check_active_time.execute(meta.hashidx); 
}


/* Stability states */
/** NOTE: new conn starts with stabilized status. So, every new conn starts with epoch 1. */
Register<bit<8>, hashidx_t>(size=CONWEAVE_TABLE_SIZE, initial_value=1) reg_stability; 
RegisterAction<bit<8>, hashidx_t, bit<1>>(reg_stability) reg_check_stability = {
    void apply(inout bit<8> reg, out bit<1> result){
        result = (bit<1>)reg[0:0];
        if (reg == 1 || meta.result_expired == 1) { /* if expired, reset the stability status */
            reg = 0; // if true, reset to false
        }
    }
};
RegisterAction<bit<8>, hashidx_t, bit<1>>(reg_stability) reg_set_stability = {
    void apply(inout bit<8> reg, out bit<1> result){
        reg = 1; // when it got reply and stabilized
    }
};
action do_check_stability() {
    meta.result_stability = reg_check_stability.execute(meta.hashidx);
}
action do_set_stability() {
    reg_set_stability.execute(meta.hashidx);
}



/* Enforce not to reroute */
Register<timestamp_t, bit<1>>(size=1, initial_value=0) reg_enforce_no_reroute;
RegisterAction<timestamp_t, bit<1>, bit<1>>(reg_enforce_no_reroute) reg_check_enforce_no_reroute = {
    void apply(inout timestamp_t reg, out bit<1> result) {
        if (meta.ts_now > CONWEAVE_TX_STOP_REROUTING_TS) {
            reg = 1;
            result = 1;
        } else {
            reg = 0;
            result = 0;
        }
    }
};
action check_enforce_no_reroute() {
    meta.flag_enforce_no_reroute = reg_check_enforce_no_reroute.execute(0);
}




/* Reply Timeout */
Register<timestamp_t, hashidx_t>(size=CONWEAVE_TABLE_SIZE) reg_reply_timer;
RegisterAction<timestamp_t, hashidx_t, bit<1>>(reg_reply_timer) reg_check_reply_timeout = {
    void apply(inout timestamp_t reg, out bit<1> result){
        if (reg < meta.ts_now) { // timeout
            reg = CONWEAVE_MAX_TIMESTAMP; // enforce later pkts not to trigger this timeout
            result = 1;
        } else {
            result = 0;
        }
    }
};
RegisterAction<timestamp_t, hashidx_t, bit<1>>(reg_reply_timer) reg_reset_reply_timeout = {
    void apply(inout timestamp_t reg, out bit<1> result){
        reg = meta.ts_new_reply_timeout; // set new deadline
        result = 0;
    }
};
RegisterAction<timestamp_t, hashidx_t, bit<1>>(reg_reply_timer) reg_check_timely_replied = {
    void apply(inout timestamp_t reg, out bit<1> result){
        if (meta.ts_now <= reg && reg != CONWEAVE_MAX_TIMESTAMP) { /* timely replied && if not yet timeout */
            /* extend reply deadline to prevent timeout during REPLY's resubmission */
            reg = meta.ts_now |+| CONWEAVE_TX_REPLY_TIMEOUT_EXTENSION_TS; /* prohibit timeout until its resubmit */
            result = 1; /* timely replied */
        } else {
            result = 0; /* ignore this reply */
        }
    }
};

action do_check_reply_timeout() {
    meta.result_reply_timeout = reg_check_reply_timeout.execute(meta.hashidx);
}
action do_reset_reply_timeout() {
    meta.result_timely_replied = reg_reset_reply_timeout.execute(meta.hashidx);
}
action do_check_timely_replied() {
    meta.result_timely_replied = reg_check_timely_replied.execute(meta.hashidx);
}
action do_accept_timely_replied() {
    meta.result_timely_replied = 1;
}








/* EPOCH */
Register<bit<8>, hashidx_t>(size=CONWEAVE_TABLE_SIZE) reg_epoch;
RegisterAction<bit<8>, hashidx_t, bit<2>>(reg_epoch) reg_get_epoch = {
    void apply(inout bit<8> reg, out bit<2> result){
        result = reg[1:0]; // 2 bits
    }
};
RegisterAction<bit<8>, hashidx_t, bit<2>>(reg_epoch) reg_compare_epoch = {
    void apply(inout bit<8> reg, out bit<2> result){
        if ((bit<8>)meta.pkt_epoch == reg) {
            result = 1;
        } else {
            result = 0;
        }
    }
};
RegisterAction<bit<8>, hashidx_t, bit<2>>(reg_epoch) reg_increase_epoch = {
    void apply(inout bit<8> reg, out bit<2> result){
        if (reg == 3) {
            reg = 0;
        } else {
            reg = reg + 1;
        }
        result = reg[1:0];
    }
};
action do_get_epoch() { 
    meta.result_epoch = reg_get_epoch.execute(meta.hashidx);
}
action do_compare_epoch() {
    meta.result_epoch = reg_compare_epoch.execute(meta.hashidx);
}
action do_increase_epoch() { 
    meta.result_epoch = reg_increase_epoch.execute(meta.hashidx);
}









/* PHASE */
Register<bit<8>, hashidx_t>(size=CONWEAVE_TABLE_SIZE) reg_phase;
RegisterAction<bit<8>, hashidx_t, bit<1>>(reg_phase) reg_get_phase = {
    void apply(inout bit<8> reg, out bit<1> result){
        if (reg == 1) {
            result = 1;
        } else {
            result = 0;
        }
    }
};
RegisterAction<bit<8>, hashidx_t, bit<1>>(reg_phase) reg_compare_phase = {
    void apply(inout bit<8> reg, out bit<1> result){
        if ((bit<8>)meta.pkt_phase == reg) {
            result = 1;
        } else {
            result = 0;
        }
    }
};
RegisterAction<bit<8>, hashidx_t, bit<1>>(reg_phase) reg_set_update_phase = {
    void apply(inout bit<8> reg, out bit<1> result){
        if (meta.result_reply_timeout == 1) { /* reply-timeout */
            reg = 1; /* set to phase 1 */
        } else { /* expired or stable */
            reg = 0;
        }
    }
};
// RegisterAction<bit<8>, hashidx_t, bit<1>>(reg_phase) reg_set_zero_phase = {
//     void apply(inout bit<8> reg, out bit<1> result){
//         reg = 0; 
//         result = 0; // current packet's phase = 0
//     }
// };
// RegisterAction<bit<8>, hashidx_t, bit<1>>(reg_phase) reg_set_one_phase = {
//     void apply(inout bit<8> reg, out bit<1> result){
//         reg = 1; 
//         result = 0; // current packet's phase = 0
//     }
// };
action do_get_phase() { 
    meta.result_phase = reg_get_phase.execute(meta.hashidx);
}
action do_compare_phase() { 
    meta.result_phase = reg_compare_phase.execute(meta.hashidx);
}
action do_set_update_phase() {
    meta.result_phase = reg_set_update_phase.execute(meta.hashidx);
}
// action do_set_phase_to_zero() {
//     meta.result_phase = reg_set_zero_phase.execute(meta.hashidx); // when it's called, meta.result_reply_timeout is already 0
// }
// action do_set_phase_to_one() {
//     meta.result_phase = reg_set_one_phase.execute(meta.hashidx); // when it's called, meta.result_reply_timeout is already 1
// }








/* PORT STATUS FROM NOTIFY - MAINTAIN TWO DUPLICATED PORT STATES (C1,C2) FOR PARALLELISM */
/* C1 - stage 1 */
Register<pair, nexthop_id_t>(size=TABLE_NEXTHOP_SIZE, initial_value={0, 0}) reg_ecn_port_c1_1;
RegisterAction<pair, nexthop_id_t, bit<1>>(reg_ecn_port_c1_1) reg_check_ecn_port_c1_1 = {
    void apply(inout pair reg, out bit<1> result){
        /* lo: out_port, hi: timestamp */ 
        if (reg.hi > meta.ts_now) {
            if (reg.lo == (bit<32>)meta.sample_port_c1) {
                result = 1; // bad port
            } else {
                result = 0; // good to use
            }
        } else { // expired, so deactivate it
            reg.hi = 0;
            result = 0; // good to use
        }
    }
};
RegisterAction<pair, nexthop_id_t, bit<1>>(reg_ecn_port_c1_1) reg_reset_ecn_port_c1_1 = { // NOTE: overwrite portinfo
    void apply(inout pair reg, out bit<1> result){
        /* lo: out_port, hi: timestamp */
        reg.lo = (bit<32>)meta.sample_port_c1;
        reg.hi = meta.ts_now + CONWEAVE_TX_ECN_PORT_TS;
    }
};
/* C1 - stage 2 */
Register<pair, nexthop_id_t>(size=TABLE_NEXTHOP_SIZE, initial_value={0, 0}) reg_ecn_port_c1_2;
RegisterAction<pair, nexthop_id_t, bit<1>>(reg_ecn_port_c1_2) reg_check_ecn_port_c1_2 = {
    void apply(inout pair reg, out bit<1> result){
        /* lo: out_port, hi: timestamp */
        if (reg.hi > meta.ts_now) {
            if (reg.lo == (bit<32>)meta.sample_port_c1) {
                result = 1; // bad port
            } else {
                result = 0; // good to use
            }
        } else { // expired, so deactivate it
            reg.hi = 0;
            result = 0;
        }
    }
};
RegisterAction<pair, nexthop_id_t, bit<1>>(reg_ecn_port_c1_2) reg_reset_ecn_port_c1_2 = { // NOTE: overwrite portinfo
    void apply(inout pair reg, out bit<1> result){
        /* lo: out_port, hi: timestamp */
        reg.lo = (bit<32>)meta.sample_port_c1;
        reg.hi = meta.ts_now + CONWEAVE_TX_ECN_PORT_TS;
    }
};
/* C1 - stage 3 */
Register<pair, nexthop_id_t>(size=TABLE_NEXTHOP_SIZE, initial_value={0, 0}) reg_ecn_port_c1_3;
RegisterAction<pair, nexthop_id_t, bit<1>>(reg_ecn_port_c1_3) reg_check_ecn_port_c1_3 = {
    void apply(inout pair reg, out bit<1> result){
        /* lo: out_port, hi: timestamp */
        if (reg.hi > meta.ts_now) {
            if (reg.lo == (bit<32>)meta.sample_port_c1) {
                result = 1; // bad port
            } else {
                result = 0; // good to use
            }
        } else { // expired, so deactivate it
            reg.hi = 0;
            result = 0;
        }
    }
};
RegisterAction<pair, nexthop_id_t, bit<1>>(reg_ecn_port_c1_3) reg_reset_ecn_port_c1_3 = { // NOTE: overwrite portinfo
    void apply(inout pair reg, out bit<1> result){
        /* lo: out_port, hi: timestamp */
        reg.lo = (bit<32>)meta.sample_port_c1;
        reg.hi = meta.ts_now + CONWEAVE_TX_ECN_PORT_TS;
    }
};
/* C1 - stage 4 */
Register<pair, nexthop_id_t>(size=TABLE_NEXTHOP_SIZE, initial_value={0, 0}) reg_ecn_port_c1_4;
RegisterAction<pair, nexthop_id_t, bit<1>>(reg_ecn_port_c1_4) reg_check_ecn_port_c1_4 = {
    void apply(inout pair reg, out bit<1> result){
        /* lo: out_port, hi: timestamp */
        if (reg.hi > meta.ts_now) {
            if (reg.lo == (bit<32>)meta.sample_port_c1) {
                result = 1; // bad port
            } else {
                result = 0; // good to use
            }
        } else { // expired, so deactivate it
            reg.hi = 0;
            result = 0;
        }
    }
};
RegisterAction<pair, nexthop_id_t, bit<1>>(reg_ecn_port_c1_4) reg_reset_ecn_port_c1_4 = { // NOTE: overwrite portinfo
    void apply(inout pair reg, out bit<1> result){
        /* lo: out_port, hi: timestamp */
        reg.lo = (bit<32>)meta.sample_port_c1;
        reg.hi = meta.ts_now + CONWEAVE_TX_ECN_PORT_TS;
    }
};

/* C2 - stage 1 */
Register<pair, nexthop_id_t>(size=TABLE_NEXTHOP_SIZE, initial_value={0, 0}) reg_ecn_port_c2_1;
RegisterAction<pair, nexthop_id_t, bit<1>>(reg_ecn_port_c2_1) reg_check_ecn_port_c2_1 = {
    void apply(inout pair reg, out bit<1> result){
        /* lo: out_port, hi: timestamp */
        if (reg.hi > meta.ts_now) {
            if (reg.lo == (bit<32>)meta.sample_port_c2) {
                result = 1; // bad port
            } else {
                result = 0; // good to use
            }
        } else { // expired, so deactivate it
            reg.hi = 0;
            result = 0;
        }
    }
};
RegisterAction<pair, nexthop_id_t, bit<1>>(reg_ecn_port_c2_1) reg_reset_ecn_port_c2_1 = { // NOTE: overwrite portinfo
    void apply(inout pair reg, out bit<1> result){
        /* lo: out_port, hi: timestamp */
        reg.lo = (bit<32>)meta.sample_port_c2;
        reg.hi = meta.ts_now + CONWEAVE_TX_ECN_PORT_TS;
    }
};
/* C2 - stage 2 */
Register<pair, nexthop_id_t>(size=TABLE_NEXTHOP_SIZE, initial_value={0, 0}) reg_ecn_port_c2_2;
RegisterAction<pair, nexthop_id_t, bit<1>>(reg_ecn_port_c2_2) reg_check_ecn_port_c2_2 = {
    void apply(inout pair reg, out bit<1> result){
        /* lo: out_port, hi: timestamp */
        if (reg.hi > meta.ts_now) {
            if (reg.lo == (bit<32>)meta.sample_port_c2) {
                result = 1; // bad port
            } else {
                result = 0; // good to use
            }
        } else { // expired, so deactivate it
            reg.hi = 0;
            result = 0;
        }
    }
};
RegisterAction<pair, nexthop_id_t, bit<1>>(reg_ecn_port_c2_2) reg_reset_ecn_port_c2_2 = { // NOTE: overwrite portinfo
    void apply(inout pair reg, out bit<1> result){
        /* lo: out_port, hi: timestamp */
        reg.lo = (bit<32>)meta.sample_port_c2;
        reg.hi = meta.ts_now + CONWEAVE_TX_ECN_PORT_TS;
    }
};
/* C2 - stage 3 */
Register<pair, nexthop_id_t>(size=TABLE_NEXTHOP_SIZE, initial_value={0, 0}) reg_ecn_port_c2_3;
RegisterAction<pair, nexthop_id_t, bit<1>>(reg_ecn_port_c2_3) reg_check_ecn_port_c2_3 = {
    void apply(inout pair reg, out bit<1> result){
        /* lo: out_port, hi: timestamp */
        if (reg.hi > meta.ts_now) {
            if (reg.lo == (bit<32>)meta.sample_port_c2) {
                result = 1; // bad port
            } else {
                result = 0; // good to use
            }
        } else { // expired, so deactivate it
            reg.hi = 0;
            result = 0;
        }
    }
};
RegisterAction<pair, nexthop_id_t, bit<1>>(reg_ecn_port_c2_3) reg_reset_ecn_port_c2_3 = { // NOTE: overwrite portinfo
    void apply(inout pair reg, out bit<1> result){
        /* lo: out_port, hi: timestamp */
        reg.lo = (bit<32>)meta.sample_port_c2;
        reg.hi = meta.ts_now + CONWEAVE_TX_ECN_PORT_TS;
    }
};
/* C2 - stage 4 */
Register<pair, nexthop_id_t>(size=TABLE_NEXTHOP_SIZE, initial_value={0, 0}) reg_ecn_port_c2_4;
RegisterAction<pair, nexthop_id_t, bit<1>>(reg_ecn_port_c2_4) reg_check_ecn_port_c2_4 = {
    void apply(inout pair reg, out bit<1> result){
        /* lo: out_port, hi: timestamp */
        if (reg.hi > meta.ts_now) {
            if (reg.lo == (bit<32>)meta.sample_port_c2) {
                result = 1; // bad port
            } else {
                result = 0; // good to use
            }
        } else { // expired, so deactivate it
            reg.hi = 0;
            result = 0;
        }
    }
};
RegisterAction<pair, nexthop_id_t, bit<1>>(reg_ecn_port_c2_4) reg_reset_ecn_port_c2_4 = { // NOTE: overwrite portinfo
    void apply(inout pair reg, out bit<1> result){
        /* lo: out_port, hi: timestamp */
        reg.lo = (bit<32>)meta.sample_port_c2;
        reg.hi = meta.ts_now + CONWEAVE_TX_ECN_PORT_TS;
    }
};


// CHECK - first stage
action do_check_ecn_port_c1_s1() { 
    meta.result_port_c1_bad = reg_check_ecn_port_c1_1.execute(meta.nexthop_id); 
}
action do_check_ecn_port_c2_s1() { 
    meta.result_port_c2_bad = reg_check_ecn_port_c2_1.execute(meta.nexthop_id); 
}
// CHECK - second stage
action do_check_ecn_port_c1_s2() { 
    meta.result_port_c1_bad = reg_check_ecn_port_c1_2.execute(meta.nexthop_id); 
}
action do_check_ecn_port_c2_s2() { 
    meta.result_port_c2_bad = reg_check_ecn_port_c2_2.execute(meta.nexthop_id); 
}
// CHECK - third stage
action do_check_ecn_port_c1_s3() { 
    meta.result_port_c1_bad = reg_check_ecn_port_c1_3.execute(meta.nexthop_id); 
}
action do_check_ecn_port_c2_s3() { 
    meta.result_port_c2_bad = reg_check_ecn_port_c2_3.execute(meta.nexthop_id); 
}
// CHECK - fourth stage
action do_check_ecn_port_c1_s4() { 
    meta.result_port_c1_bad = reg_check_ecn_port_c1_4.execute(meta.nexthop_id); 
}
action do_check_ecn_port_c2_s4() { 
    meta.result_port_c2_bad = reg_check_ecn_port_c2_4.execute(meta.nexthop_id); 
}

// RESET - first stage
// Hash<bit<1>>(HashAlgorithm_t.CRC8) hash_conweave_port;
action do_reset_ecn_port_c1_s1() { 
    reg_reset_ecn_port_c1_1.execute(meta.nexthop_id); 
}
action do_reset_ecn_port_c2_s1() { 
    reg_reset_ecn_port_c2_1.execute(meta.nexthop_id); 
}
// RESET - second stage
action do_reset_ecn_port_c1_s2() { 
    reg_reset_ecn_port_c1_2.execute(meta.nexthop_id); 
}
action do_reset_ecn_port_c2_s2() { 
    reg_reset_ecn_port_c2_2.execute(meta.nexthop_id); 
}
// RESET - second stage
action do_reset_ecn_port_c1_s3() { 
    reg_reset_ecn_port_c1_3.execute(meta.nexthop_id); 
}
action do_reset_ecn_port_c2_s3() { 
    reg_reset_ecn_port_c2_3.execute(meta.nexthop_id); 
}
// RESET - second stage
action do_reset_ecn_port_c1_s4() { 
    reg_reset_ecn_port_c1_4.execute(meta.nexthop_id); 
}
action do_reset_ecn_port_c2_s4() { 
    reg_reset_ecn_port_c2_4.execute(meta.nexthop_id); 
}






/* OUT-PORT for each connection */
Register<bit<8>, hashidx_t>(size=CONWEAVE_TABLE_SIZE) reg_port;
RegisterAction<bit<8>, hashidx_t, bit<8>>(reg_port) reg_update_port_return_new = {
    void apply(inout bit<8> reg, out bit<8> result){
        if (meta.no_good_port == 0) { // update good port if we found
            reg = meta.good_port;
        }
        result = reg; /* return the port to use */
    }
};
RegisterAction<bit<8>, hashidx_t, bit<8>>(reg_port) reg_update_port_return_previous = {
    void apply(inout bit<8> reg, out bit<8> result){
        result = reg;
        if (meta.no_good_port == 0) { // update good port if we found
            reg = meta.good_port;
        }
    }
};
action do_update_port_if_expired () { /* change port from now (i.e., this packet) */
    meta.final_port = reg_update_port_return_new.execute(meta.hashidx); // get new path
}
action do_update_port_if_reply_timeout () { /* change port from next packet */
    meta.final_port = reg_update_port_return_previous.execute(meta.hashidx); // get previous path
}
action do_get_current_port() { /* just get current port */
    meta.final_port = reg_update_port_return_previous.execute(meta.hashidx); // get current path (always meta.no_good_port = 1)
}





/* TAIL TimeStamp */
Register<timestamp_t, hashidx_t>(size=CONWEAVE_TABLE_SIZE) reg_tail_ts;
RegisterAction<timestamp_t, hashidx_t, timestamp_t>(reg_tail_ts) reg_get_tail_ts = {
    void apply(inout timestamp_t reg, out timestamp_t result){
        result = reg;
    }
};
RegisterAction<timestamp_t, hashidx_t, timestamp_t>(reg_tail_ts) reg_set_tail_ts_to_now = {
    void apply(inout timestamp_t reg, out timestamp_t result){
        reg = meta.ts_now;
        result = reg;
    }
};
RegisterAction<timestamp_t, hashidx_t, timestamp_t>(reg_tail_ts) reg_set_tail_ts_to_zero = {
    void apply(inout timestamp_t reg, out timestamp_t result){
        reg = 0;
        result = 0;
    }
};
action do_get_tail_ts() { 
    meta.ts_tail = reg_get_tail_ts.execute(meta.hashidx); 
}
action do_set_tail_ts_now() { 
    meta.ts_tail = reg_set_tail_ts_to_now.execute(meta.hashidx); 
}
action do_set_tail_ts_zero() { 
    meta.ts_tail = reg_set_tail_ts_to_zero.execute(meta.hashidx); 
}








Register<bit<32>, bit<1>>(size=1) reg_dummy_ts_now_16b;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_dummy_ts_now_16b) reg_get_ts_now_16b = {
    void apply(inout bit<32> reg, out bit<32> result) {
        reg = meta.ts_now & 0x0000FFFF;
        result = reg;
    }
};
Register<bit<32>, bit<1>>(size=1) reg_dummy_ts_tail_16b;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_dummy_ts_tail_16b) reg_get_ts_tail_16b = {
    void apply(inout bit<32> reg, out bit<32> result) {
        reg = meta.ts_tail & 0x0000FFFF;
        result = reg;
    }
};
action do_update_conweave_header_now_ts_16b() { // to avoid redundant PHV slicing...
    hdr.cwh.ts_tx = reg_get_ts_now_16b.execute(0)[15:0];  // MAX: 65535

    // /* The following code has PHV slicing error (sde-9.11.0) */
    // hdr.cwh.ts_tx = meta.ts_now[15:0];
    // meta.ts_dummy1 = meta.ts_now & 0x0000FFFF;
    // hdr.cwh.ts_tx = meta.ts_dummy1[15:0]; 
}
action do_update_conweave_header_tail_ts_16b() { // to avoid redundant PHV slicing...
    hdr.cwh.ts_tail = reg_get_ts_tail_16b.execute(0)[15:0];  // MAX: 65535
    
    // /* The following code has PHV slicing error (sde-9.11.0) */
    // hdr.cwh.ts_tail = meta.ts_tail[15:0];
    // meta.ts_dummy2 = meta.ts_tail & 0x0000FFFF;
    // hdr.cwh.ts_tail = meta.ts_dummy2[15:0]; 
}







/* DIGEST */
Register<bit<32>, bit<1>>(size=1) reg_digest_on;
RegisterAction<bit<32>, bit<1>, bit<1>>(reg_digest_on) reg_check_digest_on = {
    void apply(inout bit<32> reg, out bit<1> result) {
        if (reg == 0) {
            reg = 1;
            result = 1;
        } else {
            result = 0;
        }
    }
};
action do_check_digest_on() { 
    meta.digest_on = reg_check_digest_on.execute(0);
}

Register<bit<32>, bit<1>>(size=1) reg_digest_src_ip;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_digest_src_ip) reg_update_digest_src_ip = {
    void apply(inout bit<32> reg, out bit<32> result) {
        if (meta.digest_on == 1) {
            reg = hdr.ipv4.src_addr;
        }
    }
};
action do_update_digest_src_ip() { 
    reg_update_digest_src_ip.execute(0);
}
Register<bit<32>, bit<1>>(size=1) reg_digest_dst_ip;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_digest_dst_ip) reg_update_digest_dst_ip = {
    void apply(inout bit<32> reg, out bit<32> result) {
        if (meta.digest_on == 1) {
            reg = hdr.ipv4.dst_addr;
        }
    }
};
action do_update_digest_dst_ip() { 
    reg_update_digest_dst_ip.execute(0);
}
Register<bit<16>, bit<1>>(size=1) reg_digest_src_port;
RegisterAction<bit<16>, bit<1>, bit<16>>(reg_digest_src_port) reg_update_digest_src_port = {
    void apply(inout bit<16> reg, out bit<16> result) {
        if (meta.digest_on == 1) {
            reg = hdr.udp.src_port;
        }
    }
};
action do_update_digest_src_port() { 
    reg_update_digest_src_port.execute(0);
}






/****************************************************************************
*	 				 C O N W E A V E   -   R X   T O R                      *
****************************************************************************/
Register<bit<8>, hashidx_t>(CONWEAVE_TABLE_SIZE, 0) reg_q_pkt_cntr_ig_filter;
RegisterAction<bit<8>, hashidx_t, bit<1>>(reg_q_pkt_cntr_ig_filter) reg_update_q_pkt_cntr_ig_filter = {
    void apply(inout bit<8> reg, out bit<1> result){
        if (meta.result_out_of_order_rx == 1) {
            reg = 1;
        } else if (ig_intr_md.resubmit_flag == 1) {
            reg = 0;
        }
        result = reg[0:0];
    }
};
RegisterAction<bit<8>, hashidx_t, bit<1>>(reg_q_pkt_cntr_ig_filter) reg_reset_q_pkt_cntr_ig_filter = {
    void apply(inout bit<8> reg, out bit<1> result){
        reg = 0;
        result = 0;
    }
};
action do_update_q_pkt_cntr_ig_filter() {
    meta.cntr_additive = reg_update_q_pkt_cntr_ig_filter.execute(meta.hashidx);
}
action do_reset_q_pkt_cntr_ig_filter() {
    meta.cntr_additive = reg_reset_q_pkt_cntr_ig_filter.execute(meta.hashidx);
}







/* Ingress Counter */
Register<bit<32>, hashidx_t>(CONWEAVE_TABLE_SIZE, 0) reg_q_pkt_cntr_ig;
RegisterAction<bit<32>, hashidx_t, bit<32>>(reg_q_pkt_cntr_ig) reg_reset_q_pkt_cntr_ig = {
    void apply(inout bit<32> reg){
        reg = 0; // reset
    }
};
RegisterAction<bit<32>, hashidx_t, bit<32>>(reg_q_pkt_cntr_ig) reg_update_q_pkt_cntr_ig = {
    void apply(inout bit<32> reg, out bit<32> result){
        if (ig_intr_md.resubmit_flag == 1) { /* in case of "Fail-to-get-Q" */
            reg = 0; // reset
        } else {
            reg = reg + (bit<32>)meta.cntr_additive;
        }
        result = reg;
    }
};
RegisterAction<bit<32>, hashidx_t, bit<32>>(reg_q_pkt_cntr_ig) reg_read_q_pkt_cntr_ig = {
    void apply(inout bit<32> reg, out bit<32> result){
        result = reg;
    }
};
action do_reset_q_pkt_cntr_ig() {
    reg_reset_q_pkt_cntr_ig.execute(meta.hashidx);
}
action do_update_q_pkt_cntr_ig() {
    meta.result_q_pkt_cntr_ig = reg_update_q_pkt_cntr_ig.execute(meta.hashidx);
}
action do_read_q_pkt_cntr_ig() {
    meta.result_q_pkt_cntr_ig = reg_read_q_pkt_cntr_ig.execute(meta.hashidx);
}





/* RX Epoch - we handle bit<2> wrap-around */
Register<bit<8>, hashidx_t>(size=CONWEAVE_TABLE_SIZE, initial_value=1) reg_epoch_rx; /* NOTE: rx's epoch starts from 1, as tx starts with "stabilized" */
RegisterAction<bit<8>, hashidx_t, bit<2>>(reg_epoch_rx) reg_check_epoch_pkt_0_rx = { /* pkt_epoch = 0 */
    void apply(inout bit<8> reg, out bit<2> result){
        if (reg >= 2) { /* pkt_epoch = 4, curr_epoch = 2 or 3 -> new epoch arrives */
            reg = (bit<8>)meta.pkt_epoch;
            result = 1; /* new epoch */
        } else if (reg == 1) { /* pkt_epoch = 0, curr_epoch = 1 -> prev epoch arrives */
            result = 2; /* bypass */
        } else {
            result = 0; /* current epoch */
        }
    }
};
RegisterAction<bit<8>, hashidx_t, bit<2>>(reg_epoch_rx) reg_check_epoch_pkt_3_rx = { /* pkt_epoch = 3 */
    void apply(inout bit<8> reg, out bit<2> result){
        if (reg == 0) { /* pkt_epoch = 3, curr_epoch = 4 -> prev epoch arrives */
            result = 2; /* bypass */
        } else if (reg < 3) { /* pkt_epoch = 3, curr_epoch = 1, 2 -> new epoch arrives */
            reg = (bit<8>)meta.pkt_epoch;
            result = 1; /* new epoch */
        } else {
            result = 0; /* current epoch */
        }
    }
};
RegisterAction<bit<8>, hashidx_t, bit<2>>(reg_epoch_rx) reg_check_epoch_pkt_1_rx = { /* pkt_epoch = 1 */
    void apply(inout bit<8> reg, out bit<2> result){
        if (reg == 1) { /* current epoch */
            result = 0;
        } else if (reg == 2) { /* pkt_epoch = 1, curr_epoch = 2 -> prev epoch arrives */
            result = 2; /* bypass */
        } else { /* pkt_epoch = 1, curr_epoch = 0, or pkt_epoch = 5, curr_epoch = 3 -> new epoch arrives */
            reg = (bit<8>)meta.pkt_epoch;
            result = 1; /* new epoch */
        }
    }
};
RegisterAction<bit<8>, hashidx_t, bit<2>>(reg_epoch_rx) reg_check_epoch_pkt_2_rx = { /* pkt_epoch = 2 */
    void apply(inout bit<8> reg, out bit<2> result){
        if (reg == 3) { /* pkt_epoch = 2, curr_epoch = 3 -> prev epoch arrives */
            result = 2; /* bypass */
        } else if (reg < 2) { /* pkt_epoch = 2, curr_epoch = 0 or 1 -> new epoch arrives */
            reg = (bit<8>)meta.pkt_epoch;
            result = 1; /* new epoch */
        } else {
            result = 0; /* current epoch */
        }
    }
};
action do_check_epoch_pkt_0_rx() { 
    meta.result_epoch_rx = reg_check_epoch_pkt_0_rx.execute(meta.hashidx);
}
action do_check_epoch_pkt_3_rx() { 
    meta.result_epoch_rx = reg_check_epoch_pkt_3_rx.execute(meta.hashidx);
}
action do_check_epoch_pkt_1_rx() { 
    meta.result_epoch_rx = reg_check_epoch_pkt_1_rx.execute(meta.hashidx);
}
action do_check_epoch_pkt_2_rx() { 
    meta.result_epoch_rx = reg_check_epoch_pkt_2_rx.execute(meta.hashidx);
}




/* Phase-0 Timestamp Record */
Register<timestamp_t, hashidx_t>(size=CONWEAVE_TABLE_SIZE) reg_phase0_tx_ts_rx;
RegisterAction<timestamp_t, hashidx_t, timestamp_t>(reg_phase0_tx_ts_rx) reg_update_phase0_tx_ts_rx = {
    void apply(inout timestamp_t reg, out timestamp_t result){
        if (meta.pkt_phase == 0) {
            reg = (timestamp_t)hdr.cwh.ts_tx; /* write ts_tx: 16bits */
        }
        result = reg; /* read phase0's tx_ts: 16bits */
    }
};
action do_update_phase0_tx_ts_rx() {
    meta.ts_phase0_tx = reg_update_phase0_tx_ts_rx.execute(meta.hashidx); // MAX: 2**16 - 1
}

Register<timestamp_t, hashidx_t>(size=CONWEAVE_TABLE_SIZE) reg_phase0_rx_ts_rx;
RegisterAction<timestamp_t, hashidx_t, timestamp_t>(reg_phase0_rx_ts_rx) reg_update_phase0_rx_ts_rx = {
    void apply(inout timestamp_t reg, out timestamp_t result){
        if (meta.pkt_phase == 0) {
            reg = meta.ts_now; /* write ts_rx: 32bits */
        }
        result = reg; /* read phase0's rx_ts: 32bits */
    }
};
action do_update_phase0_rx_ts_rx() {
    meta.ts_phase0_rx = reg_update_phase0_rx_ts_rx.execute(meta.hashidx); // MAX: 2**31 - 1
}





/* RX PHASE */
Register<bit<8>, hashidx_t>(size=CONWEAVE_TABLE_SIZE) reg_phase_rx;
RegisterAction<bit<8>, hashidx_t, bit<1>>(reg_phase_rx) reg_update_phase_new_epoch_rx = { /* for new epoch */
    void apply(inout bit<8> reg, out bit<1> result){
        if (meta.pkt_tail_flag == 1) { /* TAIL packet sets phase to 1 (MOST LIEKLY NOT BE CALLED IN NEW EPOCH) */
            reg = 1;
            result = 0; /* in-order */
        } else { /* by default, new epoch sets phase to 0 */
            reg = 0; /* reset to 0 */
            if (meta.pkt_phase == 1) { /* hdr.bth.conweave_phase */
                result = 1; /* out-of-order */
            }
        }
    }
};
RegisterAction<bit<8>, hashidx_t, bit<1>>(reg_phase_rx) reg_update_phase_current_epoch_rx = { /* for current epoch */
    void apply(inout bit<8> reg, out bit<1> result){
        if (meta.pkt_tail_flag == 1) { /* TAIL packet sets phase to 1 */
            reg = 1;
            result = 0; /* in-order */
        } else if ((bit<8>)meta.pkt_phase > reg) { /* pkt_phase=1 > curr_phase=0 */
            result = 1; /* out-of-order */
        }
    }
};
RegisterAction<bit<8>, hashidx_t, bit<1>>(reg_phase_rx) reg_update_reset_phase_to_one = { /* by timeout */
    void apply(inout bit<8> reg, out bit<1> result){
        reg = 1; /* Timeout sets phase to 1 */
        result = 0;
    }
};
action do_update_phase_new_epoch_rx() { /* for new epoch */
    meta.result_out_of_order_rx = reg_update_phase_new_epoch_rx.execute(meta.hashidx);
}
action do_update_phase_current_epoch_rx() { /* for matched epoch */
    meta.result_out_of_order_rx = reg_update_phase_current_epoch_rx.execute(meta.hashidx);
}
action do_update_reset_phase_to_one() { /* for timeout pkt's resubmit */
    meta.result_out_of_order_rx = reg_update_reset_phase_to_one.execute(meta.hashidx);
}







/* RX PHASE CACHE 
* If phase-0 pkt has passed for a current epoch, return 1 to meta.result_phase0_cch_rx (i.e., phase-0 is cached).
* This means, the current phase-0 timestamps (reg_phase0_tx_ts_rx, reg_phase0_rx_ts_rx) are usable for buffer-time calculation.
* If not, we don't have information and will use base waiting time (see macro.p4).
*/
Register<bit<8>, hashidx_t>(size=CONWEAVE_TABLE_SIZE) reg_phase_cch_rx;
RegisterAction<bit<8>, hashidx_t, bit<1>>(reg_phase_cch_rx) reg_update_phase_cch_new_epoch_rx = { /* for new epoch */
    void apply(inout bit<8> reg, out bit<1> result){
        if (meta.pkt_phase == 0) { /* phase-0 pkt is cached */
            reg = 1;
        } else { /* reset to zero if current pkt has phase 1 */
            reg = 0; 
        }
        result = (bit<1>)reg[0:0];
    }
};
RegisterAction<bit<8>, hashidx_t, bit<1>>(reg_phase_cch_rx) reg_update_phase_cch_current_epoch_rx = { /* for current epoch */
    void apply(inout bit<8> reg, out bit<1> result){
        if (meta.pkt_phase == 0) { /* phase-0 pkt is cached */
            reg = 1;
        }
        result = (bit<1>)reg[0:0];
    }
};
action do_update_phase_cch_new_epoch_rx() { /* for new epoch */
    meta.result_phase0_cch_rx = reg_update_phase_cch_new_epoch_rx.execute(meta.hashidx);
}
action do_update_phase_cch_current_epoch_rx() { /* for matched epoch */
    meta.result_phase0_cch_rx = reg_update_phase_cch_current_epoch_rx.execute(meta.hashidx);
}


/** RX TAIL CACHE 
 * If phase-0 TAIL packet has passed for a current epoch, return 1 to meta.result_tail_cch_rx (i.e., tail is cached)
 * This means, the resume of reorder queue should be after the TAIL arrives at the egress deparser.
 **/
Register<bit<8>, hashidx_t>(size=CONWEAVE_TABLE_SIZE) reg_tail_cch_rx;
RegisterAction<bit<8>, hashidx_t, bit<1>>(reg_tail_cch_rx) reg_update_tail_cch_new_epoch_rx = { /* for new epoch */
    void apply(inout bit<8> reg, out bit<1> result){
        // if (meta.pkt_tail_flag == 1) { /* tail pkt is cached */
        if (hdr.bth.conweave_tail_flag == 1) {
            reg = 1;
        } else { /* reset to zero if current pkt is not tail */
            reg = 0; 
        }
        result = (bit<1>)reg[0:0];
    }
};
RegisterAction<bit<8>, hashidx_t, bit<1>>(reg_tail_cch_rx) reg_update_tail_cch_current_epoch_rx = { /* for current epoch */
    void apply(inout bit<8> reg, out bit<1> result){
        // if (meta.pkt_tail_flag == 1) { /* tail pkt is cached */
        if (hdr.bth.conweave_tail_flag == 1) {
            reg = 1;
        }
        result = (bit<1>)reg[0:0];
    }
};
action do_update_tail_cch_new_epoch_rx() { /* for new epoch */
    meta.result_tail_cch_rx = reg_update_tail_cch_new_epoch_rx.execute(meta.hashidx);
}
action do_update_tail_cch_current_epoch_rx() { /* for matched epoch */
    meta.result_tail_cch_rx = reg_update_tail_cch_current_epoch_rx.execute(meta.hashidx);
}



/** TAIL TIMESTAMP at TxToR */
Register<timestamp_t, hashidx_t>(size=CONWEAVE_TABLE_SIZE) reg_tail_ts_rx;
RegisterAction<timestamp_t, hashidx_t, timestamp_t>(reg_tail_ts_rx) reg_update_tail_ts_rx = {
    void apply(inout timestamp_t reg, out timestamp_t result){
        reg = (timestamp_t)hdr.cwh.ts_tail; /* write ts_tail: 16bits */
        result = reg;
    }
};
RegisterAction<timestamp_t, hashidx_t, timestamp_t>(reg_tail_ts_rx) reg_read_tail_ts_rx = {
    void apply(inout timestamp_t reg, out timestamp_t result){
        result = reg;
    }
};
action do_update_tail_ts_rx() {
    meta.ts_tail = reg_update_tail_ts_rx.execute(meta.hashidx);
}
action do_read_tail_ts_rx() {
    meta.ts_tail = reg_read_tail_ts_rx.execute(meta.hashidx);
}







/* RX REORDERING STATUS */
Register<bit<8>, hashidx_t>(size=CONWEAVE_TABLE_SIZE) reg_reorder_status_rx;
RegisterAction<bit<8>, hashidx_t, bit<2>>(reg_reorder_status_rx) reg_check_reorder_status_rx = { 
    void apply(inout bit<8> reg, out bit<2> result){
        if (reg == 0) {
            if (meta.result_out_of_order_rx == 1) {
                reg = 1;
                result = 2; // new reordering
            } else {
                result = 0; // nothing
            }
        } else {
            result = 1; // on-going reordering
        }
    }
};
RegisterAction<bit<8>, hashidx_t, bit<2>>(reg_reorder_status_rx) reg_reset_reorder_status_rx = { 
    void apply(inout bit<8> reg, out bit<2> result){
        reg = 0;
        result = 0;
    }
};
action do_check_reorder_status_rx() {
    meta.result_reorder_status = reg_check_reorder_status_rx.execute(meta.hashidx); // 2: new register, 1: on-going OoO
}
action do_reset_reorder_status_rx() {
    meta.result_reorder_status = reg_reset_reorder_status_rx.execute(meta.hashidx); // return always 0
}






/* Queue Occupancy Array 1 */
Register<bit<32>, conweave_qreg_idx_width_t>(size=CONWEAVE_QREG_IDX_SIZE) reg_q_occupancy_c1;
RegisterAction<bit<32>, conweave_qreg_idx_width_t, bit<1>>(reg_q_occupancy_c1) reg_register_q_occupancy_c1 = { 
    void apply(inout bit<32> reg, out bit<1> result){
        if (reg == 0) {
            reg = meta.hash_flowkey;
            result = 1;
        } else {
            result = 0; // already occupied by someone else
        }
    }
};
RegisterAction<bit<32>, conweave_qreg_idx_width_t, bit<1>>(reg_q_occupancy_c1) reg_check_q_occupancy_c1 = { 
    void apply(inout bit<32> reg, out bit<1> result){
        if (reg == meta.hash_flowkey) {
            result = 1; /* queue is occupied by this flow */
        } else {
            result = 0; /* not matched */
        }
    }
};
RegisterAction<bit<32>, conweave_qreg_idx_width_t, bit<1>>(reg_q_occupancy_c1) reg_reset_q_occupancy_c1 = { 
    void apply(inout bit<32> reg, out bit<1> result){
        if (reg == meta.hash_flowkey) {
            reg = 0; /* reset */
        }
    }
};
action do_register_q_occupancy_c1() {
    meta.result_q_occupancy_c1 = reg_register_q_occupancy_c1.execute(meta.idx_q_occup_arr_rx_c1);
}
action do_check_q_occupancy_c1() {
    meta.result_q_occupancy_c1 = reg_check_q_occupancy_c1.execute(meta.idx_q_occup_arr_rx_c1);
}
action do_reset_q_occupancy_c1() {
    reg_reset_q_occupancy_c1.execute(meta.idx_q_occup_arr_rx_c1);
}

/* Queue Occupancy Array 2 */
Register<bit<32>, conweave_qreg_idx_width_t>(size=CONWEAVE_QREG_IDX_SIZE) reg_q_occupancy_c2;
RegisterAction<bit<32>, conweave_qreg_idx_width_t, bit<1>>(reg_q_occupancy_c2) reg_register_q_occupancy_c2 = { 
    void apply(inout bit<32> reg, out bit<1> result){
        if (reg == 0) {
            reg = meta.hash_flowkey;
            result = 1;
        } else {
            result = 0; // already occupied by someone else
        }
    }
};
RegisterAction<bit<32>, conweave_qreg_idx_width_t, bit<1>>(reg_q_occupancy_c2) reg_check_q_occupancy_c2 = { 
    void apply(inout bit<32> reg, out bit<1> result){
        if (reg == meta.hash_flowkey) {
            result = 1; /* queue is occupied by this flow */
        } else {
            result = 0; /* not matched */
        }
    }
};
RegisterAction<bit<32>, conweave_qreg_idx_width_t, bit<1>>(reg_q_occupancy_c2) reg_reset_q_occupancy_c2 = { 
    void apply(inout bit<32> reg, out bit<1> result){
        if (reg == meta.hash_flowkey) {
            reg = 0; /* reset */
        }
    }
};
action do_register_q_occupancy_c2() {
    meta.result_q_occupancy_c2 = reg_register_q_occupancy_c2.execute(meta.idx_q_occup_arr_rx_c2);
}
action do_check_q_occupancy_c2() {
    meta.result_q_occupancy_c2 = reg_check_q_occupancy_c2.execute(meta.idx_q_occup_arr_rx_c2);
}
action do_reset_q_occupancy_c2() {
    reg_reset_q_occupancy_c2.execute(meta.idx_q_occup_arr_rx_c2);
}


/* Queue Occupancy Array 3 */
Register<bit<32>, conweave_qreg_idx_width_t>(size=CONWEAVE_QREG_IDX_SIZE) reg_q_occupancy_c3;
RegisterAction<bit<32>, conweave_qreg_idx_width_t, bit<1>>(reg_q_occupancy_c3) reg_register_q_occupancy_c3 = { 
    void apply(inout bit<32> reg, out bit<1> result){
        if (reg == 0) {
            reg = meta.hash_flowkey;
            result = 1;
        } else {
            result = 0; // already occupied by someone else
        }
    }
};
RegisterAction<bit<32>, conweave_qreg_idx_width_t, bit<1>>(reg_q_occupancy_c3) reg_check_q_occupancy_c3 = { 
    void apply(inout bit<32> reg, out bit<1> result){
        if (reg == meta.hash_flowkey) {
            result = 1; /* queue is occupied by this flow */
        } else {
            result = 0; /* not matched */
        }
    }
};
RegisterAction<bit<32>, conweave_qreg_idx_width_t, bit<1>>(reg_q_occupancy_c3) reg_reset_q_occupancy_c3 = { 
    void apply(inout bit<32> reg, out bit<1> result){
        if (reg == meta.hash_flowkey) {
            reg = 0; /* reset */
        }
    }
};
action do_register_q_occupancy_c3() {
    meta.result_q_occupancy_c3 = reg_register_q_occupancy_c3.execute(meta.idx_q_occup_arr_rx_c3);
}
action do_check_q_occupancy_c3() {
    meta.result_q_occupancy_c3 = reg_check_q_occupancy_c3.execute(meta.idx_q_occup_arr_rx_c3);
}
action do_reset_q_occupancy_c3() {
    reg_reset_q_occupancy_c3.execute(meta.idx_q_occup_arr_rx_c3);
}







/* TIME TO FLUSH */
Register<timestamp_t, hashidx_t>(size=CONWEAVE_TABLE_SIZE) reg_time_to_flush_queue_rx;
RegisterAction<timestamp_t, hashidx_t, bit<1>>(reg_time_to_flush_queue_rx) reg_set_time_to_flush_queue_rx = {
    void apply(inout timestamp_t reg, out bit<1> result){
        if (reg != 0) {
            result = 1; /* XXX: this should not happen.. New-reorder must start after resolving previous-reorder */
        }
        reg = meta.ts_expected_tail_arrival_rx; // OoO, phase1 -> new flush deadline
    }
};
RegisterAction<timestamp_t, hashidx_t, bit<1>>(reg_time_to_flush_queue_rx) reg_reset_time_to_flush_queue_rx = {
    void apply(inout timestamp_t reg, out bit<1> result){
        reg = 0;
    }
};
RegisterAction<timestamp_t, hashidx_t, bit<1>>(reg_time_to_flush_queue_rx) reg_update_time_to_flush_queue_rx = {
    void apply(inout timestamp_t reg, out bit<1> result){
        if (reg < meta.ts_now) {
            reg = 0; /* if timeout, set to 0 */
        } else if (reg > 0) {
            reg = meta.ts_expected_tail_arrival_rx; // NOTE: TAIL always sets the reg to 0 
            /** POSSIBLY TAIL BEFORE TIMEOUT (need further checking later) 
             * Later, we check "meta.pkt_tail_flag == 0" to ensure TAIL before timeout.
            */
            result = 1; 
        }
    }
};
RegisterAction<timestamp_t, hashidx_t, bit<1>>(reg_time_to_flush_queue_rx) reg_check_time_to_flush_queue_rx = {
    void apply(inout timestamp_t reg, out bit<1> result){
        if (reg < meta.ts_now || reg == 0) {
            result = 1; /* timeout is catched !! */
            reg = 0;
        } 
    }
};

action do_set_time_to_flush_queue_rx() { /* return 1 if abnormal */
    meta.result_time_flush_queue_rx = reg_set_time_to_flush_queue_rx.execute(meta.hashidx);
    
    /* ingress_mirroring for control loop (i.e., keep checking timeout) */
    meta.flag_mirr_for_ctrl_loop = 1;
}
action do_reset_time_to_flush_queue_rx() {
    meta.result_time_flush_queue_rx = reg_reset_time_to_flush_queue_rx.execute(meta.hashidx);
}
action do_update_time_to_flush_queue_rx() { /* return 1 if probably TAIL before timeout */
    meta.possibly_tail_before_timeout = reg_update_time_to_flush_queue_rx.execute(meta.hashidx);
}
action do_check_time_to_flush_queue_rx() {
    meta.result_time_flush_queue_rx = reg_check_time_to_flush_queue_rx.execute(meta.hashidx);
}







/* Mirroring per pipeline */
Register<bit<8>, bit<1>>(size=1) reg_mir_session;
RegisterAction<bit<8>, hashidx_t, bit<8>>(reg_mir_session) reg_calc_mir_session = {
    void apply(inout bit<8> reg, out bit<8> result){
        reg = (bit<8>)meta.pipeline_index + MIRROR_SESSION_CONWEAVE; // pipeline index + mirror_Id (220)
        result = reg;
    }
};
action ingress_mirroring(bit<8> mirror_option) { 
    meta.mirror_session = reg_calc_mir_session.execute(0); /* -> recirculation pipeline */
    ig_intr_md_for_dprsr.mirror_type = IG_MIRROR_TYPE_1;
    meta.ig_mirror1.mirror_option = mirror_option; // 1: TAIL's REPLY (CLEAR), 2: INIT's REPLY, 3: NOTIFY, 4: CTRL (loop)
}


/********************************************************************************
*	                         F O R   D E B U G G I N G   	        	        *
*********************************************************************************/

/**********************************************************************/
/*---------------- D E B U G G I N G  -  T X T O R  ------------------*/
/**********************************************************************/
Register<bit<32>,bit<1>>(1, 0) reg_debug_resubmit;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_resubmit) reg_debug_resubmit_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        reg = reg + 1;
    }
};	
action do_debug_resubmit() {
    reg_debug_resubmit_action.execute(0);
}

Register<bit<32>,bit<1>>(1, 0) reg_debug_recirc;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_recirc) reg_debug_recirc_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        reg = reg + 1;
    }
};
action do_debug_recirc() {
    reg_debug_recirc_action.execute(0);
}
Register<bit<32>,bit<1>>(1, 0) reg_debug_late_reply;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_late_reply) reg_debug_late_reply_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        reg = reg + 1;
    }
};
action do_debug_late_reply() {
    reg_debug_late_reply_action.execute(0);
}
Register<bit<32>,bit<1>>(1, 0) reg_debug_must_be_zero_0;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_must_be_zero_0) reg_debug_must_be_zero_0_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        reg = reg + 1;
    }
};
action do_debug_must_be_zero_0() {
    reg_debug_must_be_zero_0_action.execute(0);
}
Register<bit<32>,bit<1>>(1, 0) reg_debug_expired;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_expired) reg_debug_expired_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        if (meta.result_expired == 1) {
            reg = 1;
        } else {
            reg = 0;
        }
    }
};
action do_debug_expired() {
    reg_debug_expired_action.execute(0);
}
Register<bit<32>,bit<1>>(1, 0) reg_debug_reply_timeout;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_reply_timeout) reg_debug_reply_timeout_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        if (meta.result_reply_timeout == 1) {
            reg = 1;
        } else {
            reg = 0;
        }
    }
};
action do_debug_reply_timeout() {
    reg_debug_reply_timeout_action.execute(0);
}
Register<bit<32>,bit<1>>(1, 0) reg_debug_tx_data_matched_pkts;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_tx_data_matched_pkts) reg_debug_tx_data_matched_pkts_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        reg = reg + 1;
    }
};
action do_debug_tx_data_matched_pkts() {
    reg_debug_tx_data_matched_pkts_action.execute(0);
}


/**********************************************************************/
/*------------------ D E B U G G I N G -  R X T O R  -----------------*/
/**********************************************************************/
Register<bit<32>,bit<1>>(1, 0) reg_debug_cwctrl_pkts;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_cwctrl_pkts) reg_debug_cwctrl_pkts_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        reg = reg + 1;
    }
};
action do_debug_cwctrl_pkts() {
    reg_debug_cwctrl_pkts_action.execute(0);
}
Register<bit<32>,bit<1>>(1, 0) reg_debug_rx_prev_epoch;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_rx_prev_epoch) reg_debug_rx_prev_epoch_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        reg = reg + 1;
    }
};
action do_debug_rx_prev_epoch() {
    reg_debug_rx_prev_epoch_action.execute(0);
}
Register<bit<32>,bit<1>>(1, 0) reg_debug_rx_match;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_rx_match) reg_debug_rx_match_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        reg = reg + 1;
    }
};
action do_debug_rx_match() {
    reg_debug_rx_match_action.execute(0);
}
Register<bit<32>,bit<1>>(1, 0) reg_debug_must_be_zero_1;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_must_be_zero_1) reg_debug_must_be_zero_1_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        reg = reg + 1;
        // reg = meta.pkt_cwctrl_cntr_eg;
    }
};
action do_debug_must_be_zero_1() {
    reg_debug_must_be_zero_1_action.execute(0);
}
Register<bit<32>,bit<1>>(1, 0) reg_debug_must_be_zero_2;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_must_be_zero_2) reg_debug_must_be_zero_2_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        reg = reg + 1;
    }
};
action do_debug_must_be_zero_2() {
    reg_debug_must_be_zero_2_action.execute(0);
}
Register<bit<32>,bit<1>>(1, 0) reg_debug_must_be_zero_3;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_must_be_zero_3) reg_debug_must_be_zero_3_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        reg = reg + 1;
    }
};
action do_debug_must_be_zero_3() {
    reg_debug_must_be_zero_3_action.execute(0);
}
Register<bit<32>,bit<1>>(1, 0) reg_debug_must_be_zero_4;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_must_be_zero_4) reg_debug_must_be_zero_4_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        reg = reg + 1;
    }
};
action do_debug_must_be_zero_4() {
    reg_debug_must_be_zero_4_action.execute(0);
}
Register<bit<32>,bit<1>>(1, 0) reg_debug_must_be_zero_5;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_must_be_zero_5) reg_debug_must_be_zero_5_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        reg = reg + 1;
    }
};
action do_debug_must_be_zero_5() {
    reg_debug_must_be_zero_5_action.execute(0);
}
Register<bit<32>,bit<1>>(1, 0) reg_debug_must_be_zero_6;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_must_be_zero_6) reg_debug_must_be_zero_6_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        reg = reg + 1;
    }
};
action do_debug_must_be_zero_6() {
    reg_debug_must_be_zero_6_action.execute(0);
}
Register<bit<32>,bit<1>>(1, 0) reg_debug_must_be_zero_7;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_must_be_zero_7) reg_debug_must_be_zero_7_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        reg = reg + 1;
    }
};
action do_debug_must_be_zero_7() {
    reg_debug_must_be_zero_7_action.execute(0);
}
// Register<bit<32>,bit<1>>(1, 0) reg_debug_flush_time_prediction;
// RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_flush_time_prediction) reg_debug_flush_time_prediction_action = {
//     void apply(inout bit<32> reg, out bit<32> result) {
//         reg = (bit<32>)meta.ts_expected_tail_arrival_rx;
//     }
// };
// action do_debug_set_flush_time_prediction() {
//     reg_debug_flush_time_prediction_action.execute(0);
// }
// action do_debug_update_flush_time_prediction() {
//     reg_debug_flush_time_prediction_action.execute(0);
// }
Register<bit<32>,bit<1>>(1, 0) reg_debug_intra_tor_or_unmatched;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_intra_tor_or_unmatched) reg_debug_intra_tor_or_unmatched_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        reg = reg + 1;
    }
};
action do_debug_intra_tor_or_unmatched() {
    reg_debug_intra_tor_or_unmatched_action.execute(0);
}
Register<bit<32>,bit<1>>(1, 0) reg_debug_hashidx;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_hashidx) reg_debug_hashidx_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        reg = (bit<32>)meta.hashidx;
    }
};
action do_debug_hashidx() {
    reg_debug_hashidx_action.execute(0);
}
Register<bit<32>,bit<1>>(1, 0) reg_debug_outport;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_outport) reg_debug_outport_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        reg = (bit<32>)meta.out_port;
    }
};
action do_debug_outport() {
    reg_debug_outport_action.execute(0);
}
Register<bit<32>,bit<1>>(1, 0) reg_debug_adv_ctl;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_adv_ctl) reg_debug_adv_ctl_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        reg = ig_intr_md_for_dprsr.adv_flow_ctl;
    }
};
action do_debug_adv_ctl() {
    reg_debug_adv_ctl_action.execute(0);
}
Register<bit<32>,bit<1>>(1, 0) reg_debug_newOoO;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_newOoO) reg_debug_newOoO_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        // if (meta.result_reorder_status == 2) {
            reg = reg + 1;
        // }
    }
};
action do_debug_newOoO() {
    reg_debug_newOoO_action.execute(0);
}
Register<bit<32>,bit<1>>(1, 0) reg_debug_eg_mirroring;
RegisterAction<bit<32>, bit<1>, bit<32>>(reg_debug_eg_mirroring) reg_debug_eg_mirroring_action = {
    void apply(inout bit<32> reg, out bit<32> result) {
        reg = (bit<32>)meta.ig_mirror1.mirror_option;
    }
};
action do_debug_eg_mirroring() {
    reg_debug_eg_mirroring_action.execute(0);
}


