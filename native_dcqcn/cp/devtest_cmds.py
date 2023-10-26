import math
import time 

INGRESS_PORT = 128
EGRESS_PORT = 129

# CC Mode
reg_cc_mode = bfrt.dcqcn_buffering_test.pipe.SwitchEgress.reg_cc_mode # cc mode (5: DCTCP, 9: DCQCN)

# DCTCP
reg_ecn_marking_threshold = bfrt.dcqcn_buffering_test.pipe.SwitchEgress.reg_ecn_marking_threshold # cells

# DCQCN
DCQCN_K_MIN = 1250 # 100KB - 1250
DCQCN_K_MAX = 3000 # 240KB  # 400KB - 5000
DCQCN_P_MAX = 0.2 # 20%
QDEPTH_RANGE_MAX = 2**19
SEED_RANGE_MAX = 256 # random number range ~ [0, 255] (8bits)
SEED_K_MAX = math.ceil(DCQCN_P_MAX * SEED_RANGE_MAX) # 52
QDEPTH_STEPSIZE = math.floor((DCQCN_K_MAX - DCQCN_K_MIN) / SEED_K_MAX) # 72
last_range = DCQCN_K_MIN
dcqcn_get_ecn_probability = bfrt.dcqcn_buffering_test.pipe.SwitchEgress.dcqcn_get_ecn_probability # table 

# DEBUGGING
reg_ecn_marking_cntr = bfrt.dcqcn_buffering_test.pipe.SwitchEgress.reg_ecn_marking_cntr # ECN marked packets

def check_status():
    """
    Check status of current values and configuration

    Returns:
        None
    """
    print("---- CHECK STATUS ----")

    # ECN marking threshold (unit: cells, 80Bytes)
    val_reg_cc_mode = reg_cc_mode.get(REGISTER_INDEX=0, from_hw=True, print_ents=False).data[b'SwitchEgress.reg_cc_mode.f1'][1]
    val_reg_ecn_marking_threshold = reg_ecn_marking_threshold.get(REGISTER_INDEX=0, from_hw=True, print_ents=False).data[b'SwitchEgress.reg_ecn_marking_threshold.f1'][1]
    threshold_kb = (val_reg_ecn_marking_threshold * 80) / 1000
    val_reg_ecn_marking_cntr = reg_ecn_marking_cntr.get(REGISTER_INDEX=0, from_hw=True, print_ents=False).data[b'SwitchEgress.reg_ecn_marking_cntr.f1'][1]

    print("[CC Mode]Current CC Mode: {} (5: DCTCP, 9: DCQCN)".format(val_reg_cc_mode))
    print("\tDCTCP -- ECN Marking Threshold (KB): {}".format(threshold_kb))
    print("\tDCQCN -- Kmin: {}, Kmax: {}, Pmax: {} (maxQueueDepth:{})".format(DCQCN_K_MIN, DCQCN_K_MAX, DCQCN_P_MAX, QDEPTH_RANGE_MAX))

    info_dropped_pkts = bfrt.tf1.tm.counter.eg_port.get(dev_port=129, from_hw=True, pipe=0, print_ents=False).data
    print("[Debugging]")
    print("\tECN-Marked packet number: {}".format(val_reg_ecn_marking_cntr))
    print("\tDropped packet at egress port({}): {}, watermark_cells: {}".format(EGRESS_PORT, info_dropped_pkts[b'drop_count_packets'], info_dropped_pkts[b'watermark_cells']))


def change_cc_mode(cc_mode: int):
    """
    Change CC Mode: 5 (DCTCP), 9 (DCQCN)

    Returns:
        None
    """
    print("---- CHANGE CC MODE ----")
    if cc_mode == 5:
        print("Change CC Mode to DCTCP!")
        reg_cc_mode.mod(REGISTER_INDEX=0, f1=cc_mode)
    elif cc_mode == 9:
        print("Change CC Mode to DCQCN!")
        reg_cc_mode.mod(REGISTER_INDEX=0, f1=cc_mode)
    else:
        print("ERROR!! input should be either 5 (DCTCP) or 9 (DCQCN). Do nothing.")

    print("Reset ECN-marked packet counter as 0")
    reg_ecn_marking_cntr.clear()

def reconfig_dctcp_ecn_threshold(ecn_marking: int):
    val_reg_cc_mode = reg_cc_mode.get(REGISTER_INDEX=0, from_hw=True, print_ents=False).data[b'SwitchEgress.reg_cc_mode.f1'][1]
    if val_reg_cc_mode != 5:
        print("ALERT!! CC Mode is not DCTCP")
    
    reg_ecn_marking_threshold.mod(REGISTER_INDEX=0, f1=ecn_marking)
    print("Changed ECN Marking threshold to {}".format(ecn_marking))

    print("Reset ECN-marked packet counter as 0")
    reg_ecn_marking_cntr.clear()

def reconfig_dcqcn_ecn_threshold(Kmin:int, Kmax: int, Pmax: float):
    val_reg_cc_mode = reg_cc_mode.get(REGISTER_INDEX=0, from_hw=True, print_ents=False).data[b'SwitchEgress.reg_cc_mode.f1'][1]
    if val_reg_cc_mode != 9:
        print("ALERT!! CC Mode is not DCQCN")
    
    
    DCQCN_K_MIN = Kmin
    DCQCN_K_MAX = Kmax
    DCQCN_P_MAX = Pmax
    SEED_K_MAX = math.ceil(DCQCN_P_MAX * SEED_RANGE_MAX)
    QDEPTH_STEPSIZE = math.floor((DCQCN_K_MAX - DCQCN_K_MIN) / SEED_K_MAX)
    last_range = DCQCN_K_MIN
    dcqcn_get_ecn_probability = bfrt.dcqcn_buffering_test.pipe.SwitchEgress.dcqcn_get_ecn_probability
    dcqcn_compare_probability = bfrt.dcqcn_buffering_test.pipe.SwitchEgress.dcqcn_compare_probability

    #####################
    # PROBABILITY TABLE #
    #####################
    # clear table
    print("Clear DCQCN ECN marking / comparing table...")
    dcqcn_get_ecn_probability.clear()
    dcqcn_compare_probability.clear()

    print("Reconfigure DCQCN ECN marking table...")
    print("DCQCN Table -- Adding qdepth:[{}, {}] -> probability:{:.2f}% ({}/{})".format(0, DCQCN_K_MIN - 1, float(0/SEED_RANGE_MAX)*100, 0, SEED_RANGE_MAX))
    dcqcn_get_ecn_probability.add_with_dcqcn_mark_probability(deq_qdepth_start=0, deq_qdepth_end=DCQCN_K_MIN - 1, value=0)
    # K_MIN < qDepth < K_MAX
    for i in range(1, SEED_K_MAX):
        print("DCQCN Table -- Adding qdepth:[{}, {}] -> probability:{:.2f}% ({}/{})".format(last_range, last_range + QDEPTH_STEPSIZE - 1, float(i/SEED_RANGE_MAX)*100, i, SEED_RANGE_MAX))
        dcqcn_get_ecn_probability.add_with_dcqcn_mark_probability(deq_qdepth_start=last_range, deq_qdepth_end=last_range + QDEPTH_STEPSIZE - 1, value=i)
        last_range += QDEPTH_STEPSIZE
    # > K_MAX
    print("DCQCN Table -- Adding qdepth:[{}, {}] -> probability:{:.2f}%".format(last_range, QDEPTH_RANGE_MAX - 1, float(SEED_RANGE_MAX/SEED_RANGE_MAX)*100))
    dcqcn_get_ecn_probability.add_with_dcqcn_mark_probability(deq_qdepth_start=last_range, deq_qdepth_end=QDEPTH_RANGE_MAX - 1, value=SEED_RANGE_MAX - 1)

    ####################
    # COMPARISON TABLE #
    ####################
    # Less than 100%
    for prob_output in range(1, SEED_K_MAX): 
        for random_number in range(SEED_RANGE_MAX): # 0 ~ 255
            if random_number < prob_output:
                print("Comparison Table -- ECN Marking for Random Number {}, Output Value {}".format(random_number, prob_output))
                bfrt.dcqcn_buffering_test.pipe.SwitchEgress.dcqcn_compare_probability.add_with_dcqcn_check_ecn_marking(dcqcn_prob_output=prob_output, dcqcn_random_number=random_number)
    # 100% ECN Marking
    for random_number in range(SEED_RANGE_MAX):
        prob_output = SEED_RANGE_MAX - 1
        print("Comparison Table -- ECN Marking for Random Number {} < Output Value {}".format(random_number, prob_output))
        bfrt.dcqcn_buffering_test.pipe.SwitchEgress.dcqcn_compare_probability.add_with_dcqcn_check_ecn_marking(dcqcn_prob_output=prob_output, dcqcn_random_number=random_number)


    print("Reset ECN-marked packet counter as 0")
    reg_ecn_marking_cntr.clear()