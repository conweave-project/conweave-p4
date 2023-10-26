import socket
import sys
import os
import time

hostname = socket.gethostname()
def add_port_config(bfrt, port_config):
    speed_dict = {'10G':'BF_SPEED_10G', '25G':'BF_SPEED_25G', '40G':'BF_SPEED_40G','50G':'BF_SPEED_50G', '100G':'BF_SPEED_100G', '400G': 'BF_SPEED_400G'}
    fec_dict = {'NONE':'BF_FEC_TYP_NONE', 'FC':'BF_FEC_TYP_FC', 'RS':'BF_FEC_TYP_REED_SOLOMON'}
    an_dict = {0:'PM_AN_DEFAULT', 1:'PM_AN_FORCE_ENABLE', 2:'PM_AN_FORCE_DISABLE'}
    lanes_dict = {'10G':(0,1,2,3), '25G':(0,1,2,3), '40G':(0,), '50G':(0,2), '100G':(0,)}
    lpbk_dict = {"none": "BF_LPBK_NONE", "mac-near": "BF_LPBK_MAC_NEAR"}
    
    if len(port_config) == 4: # no loopback option
        port_config += ("none", )
    assert(len(port_config) == 5)
    
    # extract and map values from the config first
    conf_port = int(port_config[0].split('/')[0])
    lane = port_config[0].split('/')[1]
    conf_speed = speed_dict[port_config[1]]
    conf_fec = fec_dict[port_config[2]]
    conf_an = an_dict[port_config[3]]
    conf_lpbk = lpbk_dict[port_config[4]]

    if lane == '-': # need to add all possible lanes
        lanes = lanes_dict[port_config[1]]
        for lane in lanes:
            dp = bfrt.port.port_hdl_info.get(CONN_ID=conf_port, CHNL_ID=lane, print_ents=False).data[b'$DEV_PORT']
            bfrt.port.port.add(DEV_PORT=dp, SPEED=conf_speed, FEC=conf_fec, AUTO_NEGOTIATION=conf_an, PORT_ENABLE=True, LOOPBACK_MODE=conf_lpbk)
    else: # specific lane is requested
        conf_lane = int(lane)
        dp = bfrt.port.port_hdl_info.get(CONN_ID=conf_port, CHNL_ID=conf_lane, print_ents=False).data[b'$DEV_PORT']
        bfrt.port.port.add(DEV_PORT=dp, SPEED=conf_speed, FEC=conf_fec, AUTO_NEGOTIATION=conf_an, PORT_ENABLE=True, LOOPBACK_MODE=conf_lpbk)

    print("Port Configuration - FP:{}, SPEED:{}, FEC:{}, AN:{}, LPBK:{}".format(port_config[0], port_config[1], port_config[2], port_config[3], port_config[4]))

        
hostname = socket.gethostname()
if hostname == 'tofino2a':
    fp_port_configs = [
                ('1/0', '25G', 'NONE', 2),  # lumos cwh52a
                ('1/1', '25G', 'NONE', 2),  # lumos cwh52b
                ]
    
    # loopback
    fp_lpbk_configs = [
    ('4/0', '400G', 'RS', 2, "mac-near"), # 400G needs RS FEC, 
    ('32/0', '400G', 'RS', 2, "mac-near"), # 400G needs RS FEC, 
    ]
    
    active_dev_ports = [136, 137] # connected to servers
else:
    print("This setup script is for tofino2a/p4campus-proc1. But you are running on {}".format(hostname))
    sys.exit(1)

# port setup
for config in fp_port_configs:
    add_port_config(bfrt, config)

# lpbk port setup
for lpbk_config in fp_lpbk_configs:
    add_port_config(bfrt, lpbk_config)


# ARP
if len(active_dev_ports) > 0:
    try:
        bfrt.pre.node.add(MULTICAST_NODE_ID=0, MULTICAST_RID=0, MULTICAST_LAG_ID=[], DEV_PORT=active_dev_ports)
        bfrt.pre.mgid.add(MGID=1, MULTICAST_NODE_ID=[0], MULTICAST_NODE_L1_XID_VALID=[False], MULTICAST_NODE_L1_XID=[0])
    except:
        print("ARP entries may already exist, so skip!")

p4 = bfrt.native_afc.pipe
if hostname == 'tofino2a':
    ## for only one-switch config
    p4.SwitchIngress.simple_l2_forward.add_with_forward(ingress_port=136, port=137) 
    p4.SwitchIngress.simple_l2_forward.add_with_forward(ingress_port=137, port=136)

elif hostname == "p4campus-proc1":
    ### 3-hop topology
    p4.SwitchIngress.simple_l2_forward.add_with_forward(ingress_port=160, port=168)
    p4.SwitchIngress.simple_l2_forward.add_with_forward(ingress_port=168, port=160)
else:
    print("This setup script is for tofino2a/p4campus-proc1. But you are running on {}".format(hostname))
    sys.exit(1)



# Advanced Flow Control
## get pg_id, pg_queue
def get_pg_info(dev_port, queue_id):
    pipe  = dev_port >> 7
    entry = bfrt.tf2.tm.port.cfg.get(dev_port, print_ents=False)
    pg_id = entry.data[b'pg_id']
    pg_queue = entry.data[b'egress_qid_queues'][queue_id]
    print('DEV_PORT: {}  QueueID: {}  --> Pipe: {},  PG_ID: {}, PG_QUEUE: {}'.format(dev_port, queue_id, pipe, pg_id, pg_queue))
    return (pipe, pg_id, pg_queue) # 137 -> 1, 1, 16

pg_info = get_pg_info(dev_port=137, queue_id=0)
# bfrt.tf2.tm.queue.sched_cfg.mod(pipe=pg_info[0], pg_id=pg_info[1], pg_queue=pg_info[2], advanced_flow_control="XOFF")

def set_afc_activate(ingress_0_or_egress_1=0):
    p4.SwitchIngress.afc_where.mod(REGISTER_INDEX=0, f1=ingress_0_or_egress_1)
    p4.SwitchIngress.afc_where.dump(from_hw=True)

def set_afc_forward(dev_port=137):
    p4.SwitchIngress.afc_forward.mod(REGISTER_INDEX=0, f1=dev_port)
    p4.SwitchIngress.afc_forward.dump(from_hw=True)

def set_afc_egress_bypass(bypass_1_or_0=1):
    p4.SwitchIngress.afc_egress_bypass.mod(REGISTER_INDEX=0, f1=bypass_1_or_0)
    p4.SwitchIngress.afc_egress_bypass.dump(from_hw=True)

def get_queue(dev_port=137, queue_id=0):
    pg_info = get_pg_info(dev_port, queue_id)
    bfrt.tf2.tm.counter.queue.get(from_hw=True, pipe=pg_info[0], pg_id=pg_info[1], pg_queue=pg_info[2])

def get_afc_record():
    p4.SwitchIngress.afc_record.dump(from_hw=True)

def help():
    print("set_afc_activate(ingress_0_or_egress_1)")
    print("set_afc_forward(dev_port)")
    print("set_afc_egress_bypass(bypass_1_or_0)")
    print("get_afc_record()")

