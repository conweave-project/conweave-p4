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
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control SwitchIngress(
    inout header_t hdr,
    inout metadata_t meta,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_intr_md_from_prsr,
    inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr,
    inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm) {
/* include actions, registers, and tables */
#include "actions_ingress.p4"
#include "registers_ingress.p4"
#include "tables_ingress.p4"

    apply {
        if (hdr.ethernet.ether_type == (bit<16>)ether_type_t.ARP) {  // ARP
            ig_intr_md_for_tm.mcast_grp_a = MCAST_GRP_ID;
            ig_intr_md_for_tm.rid = 0;
        } else {
            /********************************************************************************
             *		      V I R T U A L   S W I T C H   &  P R E L I M I N A R Y 	    	*
             ********************************************************************************/
			get_hash_flowkey_step1(); 	/* get flow's hashkey */
			get_hash_flowkey_step2(); 	/* get flow's hashkey (non-zero) */
			sample_hash_qid_step_one(); 	/* -> meta.hash_qid_sample_c1, meta.hash_qid_sample_c2, meta.hash_qid_sample_c3 */
			sample_hash_qid_step_two(); 	/* For DstToR Logic: sample 3 reorder-queue indices */
			
            get_now_timestamp_32b(); 	/* get current timestamp manually (due to bf's phv issue) -> meta.ts_now */
            check_conweave_on();     	/* check conweave switch on/off -> meta.conweave_on_off */
            check_rdma_data.apply(); 	/* check RDMA data packets -> meta.flag_rdma_data */
            get_switch_id.apply();   	/* -> meta.switch_id */
			
			/* swap src <-> dst, when NOTIFY / REPLY arrives at its destination */
			if (ig_intr_md.ingress_port [6:0] != (bit<7>)RECIRC_PORT) {     		/* at SrcToR (DstToR uses RECIRC_PORT)*/
            	if (hdr.bth.conweave_opcode == 2 || hdr.bth.conweave_opcode == 3) { /* NOTIFY or REPLY */
					swap_src_dst_fields();                                      	/* swap src/dst_addr at Rx */
                    drop(0x1);                                                  	/* do not forward REPLY / NOTIFY pkts at SrcToR */
                }
            } else { /* debugging */
				do_debug_recirc();  // XXX
			}

			/* debugging */
            if (ig_intr_md.resubmit_flag == 1) { // XXX
				do_debug_resubmit();  // XXX
            }
			
			/* ECMP */
            if (hdr.ipv4.isValid()) {   /* get basic ECMP -> meta.out_port */
                check_last_hop.apply(); /* check this is last hop -> meta.last_hop */
                get_nexthop_id.apply(); /* (switch_id, ipv4.dst_addr) -> meta.nexthop_id */
                nexthop.apply();        /* -> meta.out_port */
            }


            /********************************************************************************
             *					    C O N W E A V E   M A I N   L O G I C S     			*
			 *																				*
			 * 			          IMPORTANT: WE ASSUME RUNNING ON TOR SWITCHES			 	*
             ********************************************************************************/

            if (meta.conweave_on_off == 1 && meta.flag_rdma_data == 1) { /* conweave ON and RDMA DATA pkt */
                do_categorize_conweave_logical_step.apply(); /* categorize for p4-compiler-friendly coding (SrcToR/DstToR) */

				/*------------------------------------------------------------------
							Common Block (Rx/Tx) - ConWeave Entry Lookup
				------------------------------------------------------------------*/
				if (meta.conweave_logic == 1 || (meta.conweave_logic == 2 && hdr.bth.conweave_opcode == 1)) {
					get_hashidx_basertt.apply(); /* ConWeave entry -> meta.hashidx, meta.ts_base_rtt, meta.flag_matched */
				}


                /************************************************************
                 ****        L O G I C S   A T   S r c T O R ( T x )  	 ****
                 ************************************************************/
                if (meta.conweave_logic == 1) { /* Cases: 1) Tx Data, 2) Rx NOTIFY, 3) Rx REPLY */
                    if (meta.flag_matched == 1) { /* entry exists */
						do_debug_tx_data_matched_pkts(); // XXX

                        /*----------------------------------------------
								Preconfig & ActiveTime & Stability
						----------------------------------------------*/
						if (hdr.bth.conweave_opcode == 0) { /* DATA */
							do_get_new_reply_timeout(); /* get new REPLY timeout -> meta.ts_new_reply_timeout */
							do_check_active_time(); /* check active time -> meta.result_expired */
							do_check_stability(); /* check stability -> meta.result_stability */
							
							nexthop_c1.apply(); /* sample port 1 -> meta.sample_port_c1 */
							nexthop_c2.apply(); /* sample port 2 -> meta.sample_port_c2 */

							// /** Do NOT REROUTE if current time < 2**31 - 10000 (10ms) for bit wrap-around <- check_enforce_no_reroute() */ 
							// check_enforce_no_reroute(); /* -> meta.flag_enforce_no_reroute (to solve bits wrap-around issue) */
							// if (meta.flag_enforce_no_reroute == 1) {
							// 	meta.result_expired = 0;
							// 	meta.result_stability = 0;
							// }
						} else if (hdr.bth.conweave_opcode == 2) { /* REPLY */
							if (ig_intr_md.resubmit_flag == 1) { /* resubmitted */
								do_get_max_reply_timeout(); /* get maximum REPLY timeout -> meta.ts_new_reply_timeout = TS_MAX (make no more timeout!) */
								do_set_stability(); /* set the stabilized state to 1 : ready to start new epoch */
							} else { /* first pass */
								/* DO NOTHING for active time & stability */ 
								if (hdr.bth.flags == 0b11 && hdr.bth.conweave_phase == 0) { /* Reply INIT with ECN NOTIFY */
									meta.result_reply_with_notify = 1;
								}
							}
						} /* DO NOTHING for NOTIFY: (hdr.bth.conweave_opcode == 3) */


                        /*----------------------------------------------------------------
											Reply Timer Check / Update
						----------------------------------------------------------------*/
                        if (hdr.bth.conweave_opcode == 0) { /* DATA */
							if (meta.result_expired == 1 || meta.result_stability == 1) { /* expired or stable */
								do_reset_reply_timeout(); /* set new deadline <- meta.ts_new_reply_timeout */
							} else { /* not stabilized */
								do_check_reply_timeout(); /* check REPLY timeout -> meta.result_reply_timeout */
							}
						} else if (hdr.bth.conweave_opcode == 2) { /* REPLY */
							if (ig_intr_md.resubmit_flag == 1) { /* resubmitted */
								do_reset_reply_timeout(); /* set reply_timeout to maximum (see prev step) */
							} else { /* first pass */
								if (hdr.bth.conweave_phase == 1) { /* REPLY of TAIL */
									do_accept_timely_replied(); /* always resubmit (if phase/epoch are matched) -> meta.result_timely_replied = 1 */
								} else { /* REPLY of INIT */
									do_check_timely_replied(); /* check timely replied or not -> meta.result_timely_replied */
								}
							}
						} /* DO NOTHING for NOTIFY: (hdr.bth.conweave_opcode == 3) */



						/*-------------------------------------------------------------------
													Epoch Update
						--------------------------------------------------------------------*/
						if (hdr.bth.conweave_opcode == 0) { /* DATA */
							if (meta.result_expired == 1 || meta.result_stability == 1) { /* expired or stable */
								do_increase_epoch(); /* increase epoch -> meta.result_epoch */
							} else { /* not stabilized */
								do_get_epoch(); /* epoch check -> meta.result_epoch */
							}
						} else if (hdr.bth.conweave_opcode == 2) { /* REPLY */
							if (ig_intr_md.resubmit_flag == 0) { /* first pass */
								do_compare_epoch(); /* epoch check -> meta.result_epoch */
							}
						}
						
                        

						/*-------------------------------------------------------------------
												Phase Update / Reset
						--------------------------------------------------------------------*/
						if (hdr.bth.conweave_opcode == 0) { /* DATA */
							if (meta.result_expired == 1 || meta.result_stability == 1) { /* expired or stable */
								// do_set_phase_to_zero(); /* set phase to 0 -> meta.result_phase = 0 */
								do_set_update_phase();
							} else if (meta.result_reply_timeout == 1) { /* REPLY timeout */
								// do_set_phase_to_one(); /* start phase 1 -> meta.result_phase = 0 */
								do_set_update_phase();
							} else { /* /* not expired nor stabilized -> get phase to send  */
								do_get_phase(); /* -> meta.result_phase */
							}
							/*--------------------------------------------------
											Update ConWeave Header (1)
							---------------------------------------------------*/
							do_update_conweave_header_epoch(); /* update header -> hdr.bth.conweave_epoch */
							do_update_conweave_header_phase(); /* update header -> hdr.bth.conweave_phase */
						} else {
							if (hdr.bth.conweave_opcode == 2) { /* REPLY */
								if (ig_intr_md.resubmit_flag == 0) { /* first pass */
									do_compare_phase(); /* check phase is same -> meta.result_phase */
								}
							}
							/*-------------------------------------------------------------------
												Decide Where to Record ECN-port
							--------------------------------------------------------------------*/
							if (hdr.bth.conweave_opcode == 3 || meta.result_reply_with_notify == 1) { /* NOTIFY or REPLY w/ ECN */
								/* prepare ECN-marked ports and where to record */
								meta.sample_port_c1 = hdr.bth.out_port;
								meta.sample_port_c2 = hdr.bth.out_port;
								meta.stage_to_record_port = hdr.bth.out_port[1:0]; // sample among 4 stages

								/** optional: hash-based 
								 * meta.stage_to_record_port = hash_conweave_port.get({ hdr.bth.out_port }); /* calculate hash from hdr.bth.out_port 
								 */	
							}
						}


						



						/*---------------------------------------------------------------------------------------
							Port Status: Sample 2 Outports and Check Goodport, or Update ECN Info From NOTIFY
						----------------------------------------------------------------------------------------*/
						if (hdr.bth.conweave_opcode == 0) { /* DATA */
                            /** STAGE: 1 **/
							do_check_ecn_port_c1_s1(); /* sample port 1, stage 1 -> meta.result_port_c1_bad */
							do_check_ecn_port_c2_s1(); /* sample port 2, stage 1 -> meta.result_port_c2_bad */
                            /** STAGE: 2 **/
							if (meta.result_port_c1_bad == 0) { do_check_ecn_port_c1_s2(); } else { meta.result_port_c1_bad = 1; } /* sample port 1, stage 2 -> meta.result_port_c1_bad */
							if (meta.result_port_c2_bad == 0) { do_check_ecn_port_c2_s2(); } else { meta.result_port_c2_bad = 1; } /* sample port 2, stage 2 -> meta.result_port_c2_bad */
                            /** STAGE: 3 **/
							if (meta.result_port_c1_bad == 0) { do_check_ecn_port_c1_s3(); } else { meta.result_port_c1_bad = 1; } /* sample port 1, stage 3 -> meta.result_port_c1_bad */
							if (meta.result_port_c2_bad == 0) { do_check_ecn_port_c2_s3(); } else { meta.result_port_c2_bad = 1; } /* sample port 2, stage 3 -> meta.result_port_c2_bad */
                            /** STAGE: 4 **/
							if (meta.result_port_c1_bad == 0) { do_check_ecn_port_c1_s4(); } else { meta.result_port_c1_bad = 1; } /* sample port 1, stage 4 -> meta.result_port_c1_bad */
							if (meta.result_port_c2_bad == 0) { do_check_ecn_port_c2_s4(); } else { meta.result_port_c2_bad = 1; } /* sample port 2, stage 4 -> meta.result_port_c2_bad */
						} else {
							if (hdr.bth.conweave_opcode == 3 || meta.result_reply_with_notify == 1) { /* NOTIFY */
								/** STAGE: 1 **/
								if (meta.stage_to_record_port == 0) {  do_reset_ecn_port_c1_s1(); do_reset_ecn_port_c2_s1(); } /* update port status - stage 1 */ 
								/** STAGE: 2 **/
								if (meta.stage_to_record_port == 1) {  do_reset_ecn_port_c1_s2(); do_reset_ecn_port_c2_s2(); } /* update port status - stage 2 */ 
								/** STAGE: 3 **/
                                if (meta.stage_to_record_port == 2) {  do_reset_ecn_port_c1_s3(); do_reset_ecn_port_c2_s3(); } /* update port status - stage 3 */ 
								/** STAGE: 4 **/
                                if (meta.stage_to_record_port == 3) {  do_reset_ecn_port_c1_s4(); do_reset_ecn_port_c2_s4(); } /* update port status - stage 4 */ 
							}
						}

						if (hdr.bth.conweave_opcode == 0) { /* DATA */
							if ((meta.result_expired == 0 && meta.result_reply_timeout == 0) /* enforce not to change path */
								|| (meta.result_port_c1_bad == 1 && meta.result_port_c2_bad == 1) /* no good port among samples */ ) { 
								meta.no_good_port = 1; /* no good port, so we do not change the out_port */
							}

							if (meta.result_port_c1_bad == 0) { /* good port selection -> meta.good_port */
								meta.good_port = meta.sample_port_c1; 
							} else if (meta.result_port_c2_bad == 0) { /* good port selection -> meta.good_port */
								meta.good_port = meta.sample_port_c2; 
							} 
						}


                        /*--------------------------------------------------------------
								Decide New Outport to Send & Get TAIL Time
						---------------------------------------------------------------*/
						/* NOTE: change outport only for (1) expired, or (2) replied_timeout */
						if (hdr.bth.conweave_opcode == 0) { /* DATA */
							do_check_and_update_port.apply(); /* update final out port -> meta.final_port */
							do_check_and_update_tail_ts.apply(); /* check/update TAIL timestamp -> meta.ts_tail */
						} else if (hdr.bth.conweave_opcode == 2) { /* REPLY */
							if (ig_intr_md.resubmit_flag == 0) { /* first pass */
								if (meta.result_timely_replied == 1 && meta.result_phase == 1 && meta.result_epoch == 1) { /* if both epoch and phase are matched, do resubmit the REPLY */
									resubmit_tx(); /* enable resubmit */
                                    drop(0x0); /* do NOT drop non-resubmitted REPLY */
								} else {
									do_debug_late_reply(); // XXX: total count
								}
							}
						}



                        /*--------------------------------------------------
							 			Update ConWeave Header (2)
						---------------------------------------------------*/
						if (hdr.bth.conweave_opcode == 0) { /* DATA */
							do_debug_reply_timeout(); // XXX
							do_debug_expired(); // XXX

							hdr.cwh.setValid(); /* validate conweave header -> hdr.cwh */
							do_update_conweave_header_out_port.apply(); /* update header -> hdr.bth.out_port, and meta.final_port -> meta.out_port */
							do_update_conweave_header_now_ts_16b(); /* update header -> hdr.cwh.ts_tx */
							do_update_conweave_header_tail_ts_16b(); /* update header -> hdr.cwh.ts_tail */
							do_update_conweave_header_opcode(1); /* update header -> hdr.bth.conweave_opcode */
							do_update_conweave_header_ask_reply.apply(); /* update header -> hdr.bth.conweave_ask_reply */
							if (meta.result_reply_timeout == 1) { /* TAIL packet, so update tail_flag in header */
								update_conweave_header_tail_flag(); /* update header -> hdr.bth.conweave_tail_flag */
							}
						}
						
						/*--------------------End of SrcToR logics-------------------*/

                    } else if (hdr.bth.conweave_opcode == 0) { /* no matched entry of DATA at SrcToR, inform to control plane !! */
						/* 
						 * We save ip/port into registers and let control plane keep polling values.
						 * But, this can be done using "digest" - directly send packet to control plane. 
						 * This will save more stateful resources such as SALUs.
						*/
                        do_check_digest_on();                  /* -> meta.digest_on */
                        if (meta.digest_on == 1) {             /* digest */
                            do_update_digest_src_ip();
                            do_update_digest_dst_ip();
                            do_update_digest_src_port();
                        }
                    } else {
                        /* unmatched REPLY or NOTIFY at SrcToR, which must not happen... */
                        do_debug_must_be_zero_0();  // XXX
                    }
                }
				/****************************************************
				****        L O G I C S   A T   R x T O R   	 ****
				*****************************************************/
				else if (meta.conweave_logic == 2) { /* cases: 1) Rx Data, 2) sending NOTIFY, 3) sending REPLY */

					/*----------------------------------------------
							Mirrored NOTIFY / Reply Pkts
					-----------------------------------------------*/
					if (hdr.bth.conweave_opcode != 1) { /* Reply or NOTIFY -> just forward to SrcToR */
						bypass_egress(); /* bypass egress */
					}

					// /*------------------------------------------------
					//         Get Default Queue_Id (for CTRL Pkts)
					// ------------------------------------------------*/
					// /** TODO: later, ack / control packets will be sent to queueId=1 for priorization */
					// /** NOTE: we don't need this for now... (currently no bi-directional expt) */
					// do_get_default_queue_id.apply(); /* get default queue_id -> meta.out_queue_id */ 


					if (meta.flag_matched == 1) { /* DATA entry exists */
						do_debug_rx_match(); // XXX
                        

						/*----------------------------------------------
								Epoch check & Bypass Previous Epoch
						----------------------------------------------*/
						do_check_epoch_rx.apply();  /* check pkt's epoch -> meta.result_epoch_rx (1: new epoch, 2: prev epoch) */
						if (meta.result_epoch_rx == 2) { /* previous epoch -> jsut forward to dst with default queue */
							do_debug_rx_prev_epoch(); // XXX
						} else { /* current or new epoch */

							/*-----------------------------------------------------
										GET QUEUE OCCUPANCY REGISTER INDEX 
							------------------------------------------------------*/
							do_get_idx_queue_occupancy_array_c1.apply(); /* -> meta.idx_q_occup_arr_rx_c1, meta.afc_msg_c1  */ 
							do_get_idx_queue_occupancy_array_c2.apply(); /* -> meta.idx_q_occup_arr_rx_c2, meta.afc_msg_c2  */ 
							do_get_idx_queue_occupancy_array_c3.apply(); /* -> meta.idx_q_occup_arr_rx_c3, meta.afc_msg_c3  */ 


							/*------------------------------------------------
									PHASE0_TS & PHASE & PHASE_CCH & TAIL_CCH
							-------------------------------------------------*/
							do_update_phase0_tx_ts_rx(); /* phase-0 Tx timestamp -> meta.ts_phase0_tx (16 bits) */
							do_update_phase0_rx_ts_rx(); /* phase-0 Rx timestamp -> meta.ts_phase0_rx (32 bits) */
							if (meta.result_epoch_rx == 1) { /* new epoch */
								do_update_phase_new_epoch_rx(); /* phase update and check out-of-order -> meta.result_out_of_order_rx (1: OoO) */
								do_update_phase_cch_new_epoch_rx(); /* update phase-0 cache -> meta.result_phase0_cch_rx */
								do_update_tail_cch_new_epoch_rx(); /* update tail cache -> meta.result_tail_cch_rx */
							} else { /* current epoch */
								if ((meta.flag_cwctrl_active == 1 && meta.pkt_cwctrl_timeout == 1) || ig_intr_md.resubmit_flag == 1) { /* timeout CTRL or Resubmit (fail-to-get-Q) */
									do_update_reset_phase_to_one(); /* reset phase to 1 by timeout */
								} else { /* normal packets */
									do_update_phase_current_epoch_rx(); /* phase update and check out-of-order -> meta.result_out_of_order_rx */
								}
								do_update_phase_cch_current_epoch_rx(); /* update phase-0 cache -> meta.result_phase0_cch_rx */
								do_update_tail_cch_current_epoch_rx(); /* update tail cache -> meta.result_tail_cch_rx */
							}



							/*----------------------------------------
									PREDICTION OF TAIL_ARRIVAL TIME
							-----------------------------------------*/
							/**
							 *  -- SUMMARY OF TIME PREDICTION -- 
							 * Phase 1, Cch (O) -> phase0_rx + timegap
							 * Phase 1, Cch (X) -> now + default
							 * Phase 0, TAIL or in-ordered new epoch -> 0
							 * Phase 0, Otherwise -> now + timegap (*be careful*)
                             * 
                             * -- meta.ts_expected_tail_arrival_rx = 0 when
                             * (1) TAIL pkt
                             * (2) in-ordered new epoch pkt
							 */


							/* Step 1: TAIL Timestamp at SrcToR */
							if (meta.pkt_tail_flag == 1 || meta.pkt_phase == 1) {
								/* NOTE: tail_ts is always updated for its epoch */
								do_update_tail_ts_rx(); /* update & read -> meta.ts_tail (16 bits) */
							} else {
								do_read_tail_ts_rx(); /* read -> meta.ts_tail (16 bits) */
							}

							/* Step 2-1: correct a wrap-around overflow 
							* Example case: ts_phase0_tx = 65530, ts_tail = 10
							*/
							if ((meta.ts_phase0_tx & 0xffff8000 == 0x8000) && (meta.ts_tail & 0xffff8000 != 0x8000)) { /* bits wrap-around */
								meta.ts_tail = meta.ts_tail + CONWEAVE_RX_ADJUST_TS_TAIL_WRAP_WITH_BASE; /* 2**16 + @(8) */
							} else {
								meta.ts_tail = meta.ts_tail + CONWEAVE_RX_BASE_WAITING_TIME; /* + @(8) */
							}

							/* Step 2-2: compute timegap at Tx */
							if (meta.result_phase0_cch_rx == 1) { /* phase-0 path timestamp is available */
								do_calc_tx_timegap_ts_rx(); /* -> meta.ts_timegap_rx (tail_tx - phase0_tx)*/
							} else { /* no information of phase-0 path, so use default waiting time */
								do_default_tx_timegap_ts_rx(); /* -> meta.ts_timegap_rx (default, e.g., 256 us)*/
								/** NOTE: meta.ts_phase0_rx <- meta.ts_now */
							}

							/* Step 3: get expected flush-time */
							if (meta.pkt_phase == 1) { /* predict when pkt_phase = 1 */
								do_calc_expected_tail_arrival_phase1_ts_rx(); /* -> meta.ts_expected_tail_arrival_rx = tx_phase0 + timegap_tx > 0 */
							} else { /* predict when pkt_phase = 0 */
								if (meta.pkt_tail_flag == 1 || (meta.result_epoch_rx == 1 && meta.result_out_of_order_rx == 0)) { /* TAIL or in-ordered New-Epoch */
									meta.ts_expected_tail_arrival_rx = 0; /* -> meta.ts_expected_tail_arrival_rx = 0 */
								} else { /* NOTE: for TAIL, meta.ts_expected_tail_arrival_rx = now */
									do_calc_expected_tail_arrival_phase0_ts_rx(); /* -> meta.ts_expected_tail_arrival_rx = now + timegap_tx > 0 */
								}
							}



                            /*-------------------------------------------------------------------------
                                	Filter of Counting - we count only after out-of-order
                            --------------------------------------------------------------------------*/
							if (meta.flag_cwctrl_active == 0) { /* normal pkt */
								do_update_q_pkt_cntr_ig_filter(); /* -> meta.cntr_additive = 1 if OoO has been */
							} else { /* CTRL pkt */
								if (meta.pkt_cwctrl_timeout == 1) {
									do_reset_q_pkt_cntr_ig_filter(); /* <- 0 (reset) as no more pkts go to reorder-queue */
								}
							}
							/* -> this enables to count phase-1 packets after (including) newOoO */


                            /*-------------------------------------------------------------------------
                                	CWCTRL -  Drop / Recirculate / Ingress Counter and Check Finish
                            --------------------------------------------------------------------------*/
							if (meta.flag_cwctrl_active == 1) { /* CTRL pkt */
								do_debug_cwctrl_pkts(); // XXX

								if (meta.pkt_cwctrl_drop == 1) { /* DROP */
									drop(0x1); /* drop this packet */
									do_reset_q_pkt_cntr_ig(); // reset to 0
									exit;
								} else { /* ACTIVE */
									recirculate_rx(); /* recirculate CTRL pkts */

									/*----- update/check ingress counter -----*/
									do_read_q_pkt_cntr_ig(); /* read counter -> meta.result_q_pkt_cntr_ig */

									/*----- check finishing reorder process (timeout & ig/eg counts are same) -----*/
									if (meta.pkt_cwctrl_timeout == 1 && meta.result_q_pkt_cntr_ig == meta.pkt_cwctrl_cntr_eg) { 
										hdr.cwctrl.drop = 1; /* drop the packet in next recirc */
										meta.flag_finish_reorder_process = 1; /* meta flag */
										meta.result_tail_send_reply_rx = 1; /* trigger to REPLY TAIL (mirror this CTRL pkt -> must change ether_type at egress!!) */
									}
								}
							} else { /* normal pkt */
								if (meta.pkt_phase == 1) { /* for phase-1 DATA pkt */
									/** NOTE: if pkt is resubmitted, cntr_ig is reset to 0 */
									do_update_q_pkt_cntr_ig(); /* read prev counter -> meta.result_q_pkt_cntr_ig */
								} else {
									do_read_q_pkt_cntr_ig(); /* read counter -> meta.result_q_pkt_cntr_ig */
								}
							}



							/*-------------------------------------------
										CHECK REORDERING STATUS
							--------------------------------------------*/
							if ((meta.flag_cwctrl_active == 1 && meta.pkt_cwctrl_timeout == 1) || ig_intr_md.resubmit_flag == 1) { /* timeout CTRL or Resubmit (fail-to-get-Q) */
								/* reset to 0 so that all packets go to normal queue */
								do_reset_reorder_status_rx(); /* -> meta.result_reorder_status = 0 */
							} else { /* new reorder? on-going? no reorder? (check for both phase0/1) */
								do_check_reorder_status_rx(); /* -> meta.result_reorder_status, 2: newOoO, 1: on-going */
							}



                            /** DEBUG: this must not happen */
                            if (meta.result_epoch_rx == 1 && meta.result_reorder_status == 1) { /* WARNING - new epoch, but already there is non-finished reordering */
								do_debug_must_be_zero_1(); // XXX
                            }


							/*----------------------------------------------------
								TAIL REPLY --- If no reorder, REPLY right now!
							------------------------------------------------------*/
							if (meta.pkt_tail_flag == 1 && meta.result_reorder_status == 0 && meta.result_q_pkt_cntr_ig == 0) {
								meta.result_tail_send_reply_rx = 1;  
							}


                            /*----------------------------------------------------
									REORDER QUEUE RESET / CHECK / RETRIEVE
							------------------------------------------------------*/
							{
								/* ------ COPY 1 ------- */
								update_q_occupancy_c1.apply(); /* -> meta.result_q_occupancy_c1 (1: succcessful, or exists) */
								
								/* ------ COPY 2 ------- */
								if (meta.result_q_occupancy_c1 == 0) {
									update_q_occupancy_c2.apply(); /* -> meta.result_q_occupancy_c2 (1: succcessful, or exists) */
									
									/* ------ COPY 3 ------- */
									if (meta.result_q_occupancy_c2 == 0) {
										update_q_occupancy_c3.apply(); /* -> meta.result_q_occupancy_c3 (1: succcessful, or exists) */
									}
								}
							}


                            /*------------------------------------------------------------------
												QUEUE FLUSH TIME RESET / UPDATE
							--------------------------------------------------------------------*/
							if (meta.flag_cwctrl_active == 1 && meta.pkt_cwctrl_timeout == 1) { /* CTRL timeout: reset the queue status */
								do_reset_time_to_flush_queue_rx(); /* timer */
							} else if (meta.result_reorder_status == 2) { /* new OoO, so try to occupy one empty queue */
								if (meta.result_q_occupancy_c1 == 1 || meta.result_q_occupancy_c2 == 1 || meta.result_q_occupancy_c3 == 1) { /* occupied queue */
									/** <- meta.ts_expected_tail_arrival_rx */
									do_set_time_to_flush_queue_rx(); /* -> meta.result_time_flush_queue_rx (MUST BE 0), -> meta.flag_mirr_for_ctrl_loop = 1 */
								} else { /* failed to find empty queue...*/
									/** DEBUG: this must not happen - must find per-flow queue. As an alternative, we just send to default queue */
									do_debug_must_be_zero_2();
									// /** RESUBMIT: if newOoO could not find an empty queue, we resubmit to reset the states:
									//  * (1) phase_Rx <- 1
									//  * (2) reorder_status <- 0
									//  * (3) ingress_cntr <- 0 */
									ig_intr_md_for_dprsr.resubmit_type = RESUB_DPRSR_DIGEST_REPLY; 
								}
							} else if (meta.result_reorder_status == 1) { /* on-going reordering */
								if (meta.result_q_occupancy_c1 == 1 || meta.result_q_occupancy_c2 == 1 || meta.result_q_occupancy_c3 == 1) { /* occupied queue */
									if (meta.flag_cwctrl_active == 0) { /* normal data pkt */
                                        if (meta.pkt_phase == 0) { /* update timer only for phase-0. If timeout (reg=0), no update. TAIL sets the reg to 0 */
											/** <- meta.ts_expected_tail_arrival_rx */
                                            do_update_time_to_flush_queue_rx(); /* -> meta.possibly_tail_before_timeout (0: timeout, 1: (a) reg update or (b) possibly tail before timeout) */
                                        }
                                    } else { /* CTRL pkt */
                                        if (meta.pkt_cwctrl_timeout == 0) {
                                            do_check_time_to_flush_queue_rx(); /* -> meta.result_time_flush_queue_rx (1: timeout) */
                                        } else {
                                            do_reset_time_to_flush_queue_rx(); /* reset timer to 0 */
                                        }
                                    }
								} else {
									/** DEBUG: reorder is on-going but queue is not allocated... */
									do_debug_must_be_zero_4(); // XXX
								}
							}




                            /*------------------------------------------------------------------
													ADVANCED FLOW CONTROL
							--------------------------------------------------------------------*/
							if (meta.flag_finish_reorder_process == 1) { /* finish reorder process, reset the queue status */
                                /* ADVANCED FLOW CONTROL - PAUSE THE REORDER-QUEUE */
                                ig_intr_md_for_dprsr.adv_flow_ctl = meta.pkt_cwctrl_afc_msg + AFC_CREDIT_PAUSE; /* XXX: Redundant!! */
							} else if (meta.result_reorder_status == 2) { /* new OoO (Phase1), so try to occupy one empty queue */
								do_debug_newOoO(); // XXX
								if (meta.result_q_occupancy_c1 == 1 || meta.result_q_occupancy_c2 == 1 || meta.result_q_occupancy_c3 == 1) { /* occupied queue */
                                    if (meta.result_time_flush_queue_rx == 1) { // (MUST NOT BE 1) 
                                        /** DEBUG: this must not happen - previous reordering is not resolved yet */
                                        do_debug_must_be_zero_3(); // XXX
                                    }

                                    /* 1) Which queue to forward? */
									/* 2) ADVANCED FLOW CONTROL - PAUSE THE REORDER-QUEUE */
                                    if (meta.result_q_occupancy_c1 == 1) {
                                        meta.out_queue_id = (QueueId_t)meta.hash_qid_sample_c1;
                                        ig_intr_md_for_dprsr.adv_flow_ctl = meta.afc_msg_c1 + AFC_CREDIT_PAUSE; 
                                    } else if (meta.result_q_occupancy_c2 == 1) { 
                                        meta.out_queue_id = (QueueId_t)meta.hash_qid_sample_c2;
                                        ig_intr_md_for_dprsr.adv_flow_ctl = meta.afc_msg_c2 + AFC_CREDIT_PAUSE;
                                    } else {
										meta.out_queue_id = (QueueId_t)meta.hash_qid_sample_c3;
                                        ig_intr_md_for_dprsr.adv_flow_ctl = meta.afc_msg_c3 + AFC_CREDIT_PAUSE;
									}
								}
							} else if (meta.result_reorder_status == 1) { /* on-going reordering */
                                if (meta.result_q_occupancy_c1 == 1 || meta.result_q_occupancy_c2 == 1 || meta.result_q_occupancy_c3 == 1) { /* occupied queue */
                                    if (meta.flag_cwctrl_active == 0) { /* normal data pkt */
                                        /* phase-1 pkts: which queue to forward? */
                                        if (meta.pkt_phase == 1) { /* only phase-1 pkts are sent to reorder-buffer */
                                            if (meta.result_q_occupancy_c1 == 1) {
                                                meta.out_queue_id = (QueueId_t)meta.hash_qid_sample_c1;
                                            } else if (meta.result_q_occupancy_c2 == 1) {
                                                meta.out_queue_id = (QueueId_t)meta.hash_qid_sample_c2;
                                            } else {
                                                meta.out_queue_id = (QueueId_t)meta.hash_qid_sample_c3;
                                            }
                                        } /* phase-0 pkts: sent to default queue */
                                    } else { /* ctrl-loop pkt (phase does not matter) */
                                        if (hdr.cwctrl.timeout == 0) {
                                            if (meta.result_time_flush_queue_rx == 1) { /* timeout */
												// set flag to resume reorder queue by either TAIL or CTRL
												meta.flag_resume_reorder_queue = 1; 

												/* update afc_msg in CTRL header */
												if (meta.result_q_occupancy_c1 == 1) {
                                                    // meta.pkt_cwctrl_afc_msg = meta.afc_msg_c1;
													hdr.cwctrl.afc_msg = meta.afc_msg_c1;
												} else if (meta.result_q_occupancy_c2 == 1) {
													// meta.pkt_cwctrl_afc_msg = meta.afc_msg_c2;
													hdr.cwctrl.afc_msg = meta.afc_msg_c2;
												} else {
													// meta.pkt_cwctrl_afc_msg = meta.afc_msg_c3;
													hdr.cwctrl.afc_msg = meta.afc_msg_c3;
												}
                                            }
                                        }
                                    }
                                } 
								// else, reorder is on-going but queue is not allocated...
							}

							// /** BUGGY: making OoO queue flush  */
							// if (meta.flag_resume_reorder_queue == 1) {
							// 	ig_intr_md_for_dprsr.adv_flow_ctl = hdr.cwctrl.afc_msg + AFC_CREDIT_RESUME;
							// }

							
                            /*------------------------------------------
								(1)	Resume Reorder Queue - by Timeout
								(2)	Resume Reorder Queue - by TAIL
							-------------------------------------------*/
							/** BUGFIX: ADVANCED FLOW CONTROL - resume the reorder queue
							 * (1) by timeout (CTRL) 
							 * 		-> If CTRL timeout before TAIL, immediately resume the queue. 
							 * 		-> If CTRL timeout after TAIL, check TAIL is dequeued and then reset states. 
							 * (2) by TAIL -> TAIL should be dequeued before the reorder queue packets. 
							 * 		Thus, CTRL packet does not trigger RESUME. Instead, TAIL triggers RESUME at egress deparser.
							*/
							if (meta.flag_resume_reorder_queue == 1 && hdr.cwctrl.pre_timeout == 0) { /* (1) */
								if (meta.result_tail_cch_rx == 0) { /* before TAIL */
									/* timeout not by TAIL -> immediately flush the queue */
									ig_intr_md_for_dprsr.adv_flow_ctl = hdr.cwctrl.afc_msg + AFC_CREDIT_RESUME;
									/** NOTE: timeout triggers to set phase to 1 during the next recirc */
									hdr.cwctrl.timeout = 1; /* set timeout_triggered in CTRL header */
								} else { /* after TAIL */
									/* check TAIL has passed egress pipeline. If then, cwctrl.timeout <- 1 at egress pipeline */
									hdr.cwctrl.pre_timeout = 1; 
									hdr.cwctrl.hashidx = (bit<16>)meta.hashidx;
								}
							}


							/** TAIL: TAIL Arrival before timeout -> make TAIL to resume the reorder queue at egress deparser 
							 * Already "meta.possibly_tail_before_timeout == 1" implies the reordering is in-progress 
							 * (i.e., meta.result_reorder_status != 0, and no mirroring)
							*/
							if (meta.possibly_tail_before_timeout == 1 && meta.pkt_tail_flag == 1) { /* (2) */
								hdr.tailh.setValid();
								hdr.tailh.hashidx = (bit<16>)meta.hashidx;
								hdr.ethernet.ether_type = (bit<16>)ether_type_t.CWTAIL;
								/* update afc_msg in TAIL header */
								if (meta.result_q_occupancy_c1 == 1) {
									hdr.tailh.afc_msg_resume = meta.afc_msg_c1 + AFC_CREDIT_RESUME;
								} else if (meta.result_q_occupancy_c2 == 1) {
									hdr.tailh.afc_msg_resume = meta.afc_msg_c2 + AFC_CREDIT_RESUME;
								} else if (meta.result_q_occupancy_c3 == 1){
									hdr.tailh.afc_msg_resume = meta.afc_msg_c3 + AFC_CREDIT_RESUME;
								} else {
									meta.flag_something_wrong = 1;// XXX
								}
								do_debug_must_be_zero_6(); // XXX
							}



                            /*------------------------------------------
									MIRRORING FOR REPLY & NOTIFY
							-------------------------------------------*/
							do_ingress_mirroring.apply();
						}
						
						#if (LPBK_FOR_CTRL == 1)
						/** XXX: for debugging... loopback to 16 (switch 2) */
						if (meta.ig_mirror1.mirror_option == 4) { /* CTRL */
							meta.mirror_session = 16; /* ==> egress_port = 16 */
						}
						#endif
						#if (LPBK_FOR_NOTIFY == 1)
						/** XXX: for debugging... loopback to 8 (switch 2) */
						if (meta.ig_mirror1.mirror_option == 3) { /* NOTIFY */
							meta.mirror_session = 8; /* ==> egress_port = 8 */
						}
						#endif

                        /* send to the dedicated queue */
                        forward_queue(meta.out_queue_id);

					} else if (hdr.bth.conweave_opcode == 1) { /* WRONG CONFIG - lasthop but no matched entry */
                        // do_debug_must_be_zero_5(); // XXX
						meta.flag_something_wrong = 1;	
                    }

                    // /*-----------------------------------------------------------------------------
					// 	CLEAR BTH & CWH HEADERS (EXCEPT MIRROR PKTS -> HANDLE AT EGRESS) - UNNECESSARY?
					// ------------------------------------------------------------------------------*/
					// if (hdr.bth.conweave_opcode == 1 && meta.mirror_session == 0 && meta.flag_cwctrl_active == 0) { /* DATA w/o mirror */
					// 	/* Initialize header when sending to destination */
					// 	invalid_conweave_ig(); /* setInvalid conweave header */ 
					// 	initialize_bth_header_ig(); /* initialize rdma header */
					// }
				} else if (meta.conweave_logic == 3) {
					/*--------------------------------------------------------------------
					**** 			 W R O N G   C O N F I G U R A T I O N   		 ****
					---------------------------------------------------------------------*/
					meta.flag_something_wrong = 1;	
				} else {
					/*--------------------------------------------------------------------
					**** 	 I N T R A - T O R   o r   U N M A T C H E D   C O N N	 ****
					---------------------------------------------------------------------*/
					// do_debug_intra_tor_or_unmatched(); // XXX
				}
			}

			if (meta.flag_something_wrong == 1) {
				do_debug_must_be_zero_5(); // XXX
			}

			// if (meta.result_reorder_status != 0) {
			do_debug_adv_ctl(); // XXX
			do_debug_eg_mirroring(); // XXX
			// }

			forward_port(meta.out_port); /* meta.out_port -> ig_intr_md_for_tm.ucast_egress_port */
        }
    }
}
