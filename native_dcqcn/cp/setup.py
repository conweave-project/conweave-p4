import socket
import sys
import os
import time
import math

### HOW TO RUN ###
# $SDE/run_bfshell.sh -b `pwd`/setup.py -i
###

# interfaces
INFO_DEV_PORT_PATRONUS_ENS1F1 = 147

MIRROR_SESSION_RDMA_SNIFF_IG = 777 # mirroring's session id for sniffing RDMA packets for IG_MIRROR 
MIRROR_SESSION_RDMA_SNIFF_EG = 888 # mirroring's session id for sniffing RDMA packets for EG_MIRROR

# config_pktgen_script='..../config_pktgen.py'
devtest_cmds_file = "<FILL THE CURRENT ABSOLUTE DIRECTORY>/devtest_cmds.py"

hostname = socket.gethostname()
print("Hostname: {}".format(hostname))

if hostname == "tofino1b":
    fp_port_configs = [
                    ('31/0', '25G', 'NONE', 2),  # lumos ens2f1
                    ('31/1', '25G', 'NONE', 2),  # hajime enp6s0f1
                    ('29/3', '25G', 'NONE', 2),  # monitoring patronus ens1f1
                    ]

def add_port_config(port_config):
    speed_dict = {'10G':'BF_SPEED_10G', '25G':'BF_SPEED_25G', '40G':'BF_SPEED_40G','50G':'BF_SPEED_50G', '100G':'BF_SPEED_100G'}
    fec_dict = {'NONE':'BF_FEC_TYP_NONE', 'FC':'BF_FEC_TYP_FC', 'RS':'BF_FEC_TYP_RS'}
    an_dict = {0:'PM_AN_DEFAULT', 1:'PM_AN_FORCE_ENABLE', 2:'PM_AN_FORCE_DISABLE'}
    lanes_dict = {'10G':(0,1,2,3), '25G':(0,1,2,3), '40G':(0,), '50G':(0,2), '100G':(0,)}
    
    # extract and map values from the config first
    conf_port = int(port_config[0].split('/')[0])
    lane = port_config[0].split('/')[1]
    conf_speed = speed_dict[port_config[1]]
    conf_fec = fec_dict[port_config[2]]
    conf_an = an_dict[port_config[3]]


    if lane == '-': # need to add all possible lanes
        lanes = lanes_dict[port_config[1]]
        for lane in lanes:
            dp = bfrt.port.port_hdl_info.get(CONN_ID=conf_port, CHNL_ID=lane, print_ents=False).data[b'$DEV_PORT']
            bfrt.port.port.add(DEV_PORT=dp, SPEED=conf_speed, FEC=conf_fec, AUTO_NEGOTIATION=conf_an, PORT_ENABLE=True)
    else: # specific lane is requested
        conf_lane = int(lane)
        dp = bfrt.port.port_hdl_info.get(CONN_ID=conf_port, CHNL_ID=conf_lane, print_ents=False).data[b'$DEV_PORT']
        bfrt.port.port.add(DEV_PORT=dp, SPEED=conf_speed, FEC=conf_fec, AUTO_NEGOTIATION=conf_an, PORT_ENABLE=True)

for config in fp_port_configs:
    add_port_config(config)


port_metadata_tbl = bfrt.dcqcn_buffering_test.pipe.SwitchIngressParser.PORT_METADATA # switch_id
l2_forward = bfrt.dcqcn_buffering_test.pipe.SwitchIngress.l2_forward

# For topology figure: https://app.diagrams.net/#G1hy8wHlz500QMTVTgnsO1ZrWA1gGPQ_zx

if hostname == "tofino1b":
    # FORM virtual switches - aka fill the port_metadata table
    port_metadata_tbl.add(ingress_port=128, switch_id=0)
    port_metadata_tbl.add(ingress_port=129, switch_id=0)

    # Add entries to the l2_forward table
    l2_forward.add_with_forward(dst_addr=0xb8cef6046c05, switch_id=0, port=129) # to sender (DATA)
    l2_forward.add_with_forward(dst_addr=0xb8cef6046bd1, switch_id=0, port=128) # to receiver (ACK)

    # XXX monitoring entry to patronus ens1f1 (dp 29/3)
    l2_forward.add_with_forward(dst_addr=0x649d99b10ee1, switch_id=0, port=147)

    # #  Pktgen pkt's forwarding from sw2 to sw3
    # l2_forward.add_with_forward(dst_addr=RECEIVER_SW_ADDR, switch_id=2, port=172)


# Setup ARP broadcast for the active dev ports
active_dev_ports = []

if hostname == 'tofino1b':
    active_dev_ports = [128, 129, 147]
else:
    print("This setup script is for tofino1b/1c. But you are running on {}".format(hostname))
    sys.exit(1)

# ARP
bfrt.pre.node.add(MULTICAST_NODE_ID=0, MULTICAST_RID=0, MULTICAST_LAG_ID=[], DEV_PORT=active_dev_ports)
bfrt.pre.mgid.add(MGID=1, MULTICAST_NODE_ID=[0], MULTICAST_NODE_L1_XID_VALID=[False], MULTICAST_NODE_L1_XID=[0])

# Setup mirroring
if hostname == "tofino1b":
    bfrt.mirror.cfg.add_with_normal(sid=MIRROR_SESSION_RDMA_SNIFF_IG, direction='INGRESS', session_enable=True, ucast_egress_port=INFO_DEV_PORT_PATRONUS_ENS1F1, ucast_egress_port_valid=1, max_pkt_len=16384)
    bfrt.mirror.cfg.add_with_normal(sid=MIRROR_SESSION_RDMA_SNIFF_EG, direction='EGRESS', session_enable=True, ucast_egress_port=INFO_DEV_PORT_PATRONUS_ENS1F1, ucast_egress_port_valid=1, max_pkt_len=16384)


# Setup ECN marking for DCTCP
reg_ecn_marking_threshold = bfrt.dcqcn_buffering_test.pipe.SwitchEgress.reg_ecn_marking_threshold
# reg_ecn_marking_threshold.mod(REGISTER_INDEX=0, f1=375) # 375 x 80 = 30KB (20 pkts) | 1 Gbps
reg_ecn_marking_threshold.mod(REGISTER_INDEX=0, f1=1250) # 1250 x 80 = 100KB (65 pkts) | 10 Gbps

# Setup RED-based ECN marking for DCQCN
DCQCN_K_MIN = 1250 # 100KB
DCQCN_K_MAX = 3000 # 240KB  # 400KB - 5000
DCQCN_P_MAX = 0.2 # 20%
QDEPTH_RANGE_MAX = 2**19
SEED_RANGE_MAX = 256 # random number range ~ [0, 255] (8bits)
SEED_K_MAX = math.ceil(DCQCN_P_MAX * SEED_RANGE_MAX) # 52
QDEPTH_STEPSIZE = math.floor((DCQCN_K_MAX - DCQCN_K_MIN) / SEED_K_MAX) # 72

last_range = DCQCN_K_MIN
#####################
# PROBABILITY TABLE #
#####################
dcqcn_get_ecn_probability = bfrt.dcqcn_buffering_test.pipe.SwitchEgress.dcqcn_get_ecn_probability
# < K_MIN
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
dcqcn_compare_probability = bfrt.dcqcn_buffering_test.pipe.SwitchEgress.dcqcn_compare_probability
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


# #######################
# ###  CONFIG PKTGEN  ### 
# #######################
# print("######## CONFIGURING PKTGEN ########")
# os.system("$SDE/run_pd_rpc.py {}".format(config_pktgen_script))
# time.sleep(0.5)
# print("PktGen configured for test traffic!")

###############################
###  LOAD DEVTEST_CMDS FILE ###
###############################
print("######## LOADING DEVTEST COMMANDS ########")
if hostname == "tofino1b":
    with open(devtest_cmds_file, "rb") as src_file:
        code = compile(src_file.read(), devtest_cmds_file, "exec")
        exec(code)
print("devtest_cmds.py loaded!")




