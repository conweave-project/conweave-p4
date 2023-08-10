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

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control SwitchEgress(
    inout header_t hdr,
    inout metadata_t meta,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
    inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {
    /* include actions, registers, and tables */

#include "actions_egress.p4"
#include "registers_egress.p4"
#include "tables_egress.p4"

    apply {
        /*------------------------------------------------------------------------------------------
            Tx REPLY, NOTIFY -> {swap src/dst, update phase, and update opcode} based on metadata

            TODO: REPLY will have no delay by queue.
            But, NOTIFY can be delayed because we craft using the "original" packet (mirror_option > 0).
            Later, we should craft using the mirrored packet (how?)
        -------------------------------------------------------------------------------------------*/
        if (meta.ig_mirror1.mirror_option == 1) { /** Reply of TAIL (NOTE:using original packet) */
            swap_src_dst_fields();
            if (hdr.cwctrl.isValid()) {
                /* this step is necessary, because we sometimes mirror CTRL pkt (see CWCTRL part at ingress pipeline) */
                hdr.cwctrl.setInvalid();
                hdr.ethernet.ether_type = ether_type_t.IPV4;
            }
            hdr.bth.conweave_opcode = 2;
            hdr.bth.conweave_phase = 1;
            hdr.bth.conweave_ask_reply = 0;
            hdr.bth.conweave_tail_flag = 0;
            hdr.bth.flags = 0;
            hdr.ipv4.ecn = 0b00;
            do_debug_eg_cntr1();  // XXX

            // use same epoch
            // exit;
        } else if (meta.ig_mirror1.mirror_option == 2) { /** Reply of INIT (NOTE:using original packet) */
            swap_src_dst_fields();
            hdr.bth.conweave_opcode = 2;
            hdr.bth.conweave_phase = 0;
            hdr.bth.conweave_ask_reply = 0;
            hdr.bth.conweave_tail_flag = 0;
            hdr.bth.flags = (bit<8>)hdr.ipv4.ecn; /* INIT Reply with NOTIFY */
            hdr.ipv4.ecn = 0b00;
            do_debug_eg_cntr2();  // XXX

            // use same epoch
            // exit;
        } 
#if (LPBK_FOR_NOTIFY == 1)
        else if (eg_intr_md.egress_port == 8) { /** NOTIFY (NOTE: using crafted packet) */
#else
        else if (meta.ig_mirror1.mirror_option == 3) { /* NOTIFY */
#endif
            swap_src_dst_fields();
            hdr.bth.conweave_opcode = 3;
            hdr.bth.conweave_ask_reply = 0;
            hdr.bth.conweave_tail_flag = 0;
            hdr.bth.flags = 0;
            hdr.ipv4.ecn = 0b00;
            do_debug_eg_cntr3();  // XXX

            // use same epoch
            // use same out_port in bth
            // exit;
        } else { /* rest of packets toward recirc/lbpk -> CWCTRL */
/** NOTE: RUN ONLY ONCE PER CWCTRL PKT, Newly mirrored packet for Ctrl */
#if (LPBK_FOR_CTRL == 1)
            if (eg_intr_md.egress_port == 16 && hdr.cwctrl.isValid() == false) { /** CTRL (NOTE: using crafted packet) */
#else
            if (eg_intr_md.egress_port [6:0] == (bit<7>)RECIRC_PORT && hdr.cwctrl.isValid() == false) {
#endif
                /* validate hdr.cwctrl header!! */
                hdr.cwctrl.setValid();
                hdr.cwctrl.pre_timeout = 0;
                hdr.cwctrl.timeout = 0;
                hdr.cwctrl.drop = 0;
                hdr.cwctrl.cntr_eg = 0;
                hdr.cwctrl.afc_msg = 0;
                hdr.ethernet.ether_type = (bit<16>)ether_type_t.CWCTRL;

                /* update/initialize header */
                hdr.bth.conweave_ask_reply = 0;
                hdr.bth.conweave_tail_flag = 0;
                hdr.bth.flags = 0;
                hdr.ipv4.ecn = 0b00;
                do_debug_eg_cntr4();  // XXX
                // use same epoch
                // use same phase (phase-1)
                // use same opcode (1)
                // exit;
            } else {
                /* mirror_option = 4 -> ORIGINAL NewOoO PACKET !! */

#if (LPBK_FOR_CTRL == 1)
                if (eg_intr_md.egress_port == 16 && hdr.cwctrl.isValid()) { /* CTRL */
#else
                if (eg_intr_md.egress_port [6:0] == (bit<7>)RECIRC_PORT && hdr.cwctrl.isValid()) { /* CTRL */
#endif
                    /*-----------------------------------------------------------
                                    Egress Dequeue Depth History
                    ------------------------------------------------------------*/
                    /* hdr.cwctrl.afc_msg (32bits) -> meta.idx_qdepth_history_rx */
                    do_get_idx_queue_occupancy_array_ctrl_eg.apply();
                    if (meta.hit_idx_queue_occupancy_tbl_eg == 1) { /* if hit */
                        /** DROP: reorder is resolved, reset counter to 0 */
                        /** READ: read register and save to cwctrl header  */
                        do_read_reset_buffer_egress_cntr(); /* READ -> hdr.cwctrl.cntr_eg */
                    }

                    if (hdr.cwctrl.pre_timeout == 1) {
                        // hdr.cwctrl.hashidx
                        do_check_tail_resume(); // -> meta.flag_check_tail_resume = 1 if TAIL already resumed the reorder queue
                        if (meta.flag_check_tail_resume == 1) { 
                            hdr.cwctrl.pre_timeout = 0;
                            hdr.cwctrl.timeout = 1;
                        }
                    }

                } else {
                    /*-------------------------------------------------------------------------------------*/
                    /*------ Only DATA packets (at both srcToR/dstToR) will be processed by following -----*/
                    /*-------------------------------------------------------------------------------------*/

                    /*------------------------------------------
                            Resume Reorder Queue - by TAIL
                    -------------------------------------------*/
                    if (hdr.tailh.isValid()) { /* resume the reorder queue at egress deparser*/
                        eg_intr_md_for_dprsr.adv_flow_ctl = hdr.tailh.afc_msg_resume;

                        /* return back to original packet header */
                        hdr.tailh.setInvalid();
                        hdr.ethernet.ether_type = ether_type_t.IPV4;

                        /* record TAIL has resumed the reorder queue. CTRL will check it. */
                        do_update_tail_resume();
                        do_debug_eg_cntr5();  // XXX
                    }

                    /*-----------------------------------------------------------
                                    Egress Dequeue Depth History
                    ------------------------------------------------------------*/
                    /* eg_intr_md.egress_port (9 bits), eg_intr_md.egress_qid (7 bits) -> meta.idx_qdepth_history_rx **/
                    do_get_idx_queue_occupancy_array_data_eg.apply();
                    if (meta.hit_idx_queue_occupancy_tbl_eg == 1) { /* if hit */
                        /** DEQUEUE: increase counter by 1 */
                        do_increment_buffer_egress_cntr();
                    }

                    /*-----------------------------------------------------------
                                ECN MARKING (DCQCN <- RDMA, DCTCP <- TCP)
                    ------------------------------------------------------------*/
                    if (hdr.ipv4.ecn == 0b01 || hdr.ipv4.ecn == 0b10) {
                        if (meta.is_roce_v2 == 1) {  // RoCEv2 Pkt
                            /* DCQCN (RED-like marking) */
                            dcqcn_get_ecn_probability.apply();  // get probability to ecn-mark
                            dcqcn_get_random_number();          // get random number for sampling
                            dcqcn_compare_probability.apply();  // fills meta.mark_ecn_codepoint
                        } else {                                // use DCTCP-like marking
                            check_ecn_marking_threshold();      // fills meta.mark_ecn_codepoint
                        }

                        if (meta.mark_ecn_codepoint == 1) {
                            mark_ecn_ce_codepoint();
                        }
                    }  // #### ECN Marking (end) ######

                    /*---------------------------------------------------------------------
                        CLEAR BTH & CWH HEADERS OF ORIGINAL (NON-MIRRORING) PKTS TO DST
                    ----------------------------------------------------------------------*/
                    do_check_toward_dst.apply(); /* -> meta.last_hop */
                    if (meta.last_hop == 1) {
                        if (hdr.cwh.isValid()) {
                            invalid_conweave_eg();
                        }
                        if (hdr.bth.isValid()) {
                            initialize_bth_header_eg();
                        }
                        
                    }
                }
            }
        }
    }
}  // End of SwitchEgress