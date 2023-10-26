#!/usr/bin/env python3

import os
import sys
import time
import math

# python3 get_rx_info.py 000 lg blk

### INPUT ARGUMENT ###
# 1. loss rate (000, 010, 100)
# 2. expt_type (baseline, lg)
# 3. block mode (blk, noblk)

if len(sys.argv) != 4:  # TODO: take cmdline arguments
    print("Usage: {} <loss_rate> <expt_type> <block_mode>")
    exit(1)

loss_rate = sys.argv[1]
expt_type = sys.argv[2]
block_mode = sys.argv[3]

if loss_rate not in ["000", "100", "010"]:
    print("Loss rate should be either 000, 100, 010")
    exit(1)  
if expt_type not in ["baseline", "lg"]:
    print("expt_type should be either baseline, lg")
    exit(1)
if block_mode not in ["blk", "noblk"]:
    print("block_mode should be either blk, noblk")
    exit(1)

logname = "rxinfo_{loss_rate}_{expt_type}_{block_mode}.txt".format(loss_rate=loss_rate, expt_type=expt_type, block_mode=block_mode)

if os.path.exists(logname):
    os.remove(logname)

SDE_INSTALL = os.environ['SDE_INSTALL']
PYTHON3_VER = '{}.{}'.format(
    sys.version_info.major,
    sys.version_info.minor)
SDE_PYTHON3 = os.path.join(SDE_INSTALL, 'lib', 'python' + PYTHON3_VER,
                             'site-packages')
sys.path.append(SDE_PYTHON3)
sys.path.append(os.path.join(SDE_PYTHON3, 'tofino'))
sys.path.append(os.path.join(SDE_PYTHON3, 'tofino', 'bfrt_grpc'))

import bfrt_grpc.client as gc

RX_DEV_PORT_ON_REMOTE_SWITCH = 132 # 60
BFRT_CLIENT_ID = 99

# running on tofino1a
bfrt_endpoint = 'localhost'
bfrt_port = 50052
bfrt_info = None
dev_tgt = None
interface = None

def init_bfrt():
    global bfrt_endpoint
    global bfrt_port
    global bfrt_info
    global dev_tgt
    global interface
    # for bfrt_client_id in range(10):
    try:
        interface = gc.ClientInterface(
            grpc_addr = str(bfrt_endpoint) + ":" + str(bfrt_port),
            client_id = BFRT_CLIENT_ID,
            device_id = 0,
            num_tries = 1)
        # break
    except:
        quit
    bfrt_info = interface.bfrt_info_get()
    # print('The target runs the program:', bfrt_info.p4_name_get())
    # if bfrt_client_id == 0:
    interface.bind_pipeline_config(bfrt_info.p4_name_get())
    dev_tgt = gc.Target(0)

init_bfrt()

port_stat_table = bfrt_info.table_get('$PORT_STAT')
key = port_stat_table.make_key([gc.KeyTuple('$DEV_PORT', RX_DEV_PORT_ON_REMOTE_SWITCH)])

start = time.perf_counter()
end = time.perf_counter()
elapsed = end - start
print("elapsed time = {:.12f} seconds".format(elapsed))

seconds = -1
start = time.perf_counter()
time_list = [0]
byte_list = [0]
while (True):
    current_time = time.perf_counter()
    elapsed = current_time - start
    if math.floor(elapsed) <= seconds:
        continue
    
    # (at least) 1 second elapsed
    seconds += (math.floor(elapsed) - seconds)
    
    # read from switch
    response = port_stat_table.entry_get(dev_tgt, [key], {'from_hw': False}, None)
    first_resp_entry = list(response)[0]  # only have 1 in this case
    # entry is a tuple: (data obj, key obj). Get the data obj and convert to a dict
    rx_port_stats = first_resp_entry[0].to_dict() 
    rx_octets = rx_port_stats['$OctetsReceived']
    
    # write file and close
    with open(logname, "a") as f: 
        f.write("{timestamp} {bytes}\n".format(timestamp=elapsed, bytes=rx_octets))
    
    
    # record locally
    time_list.append(elapsed)
    byte_list.append(rx_octets)
    delta_time = time_list[-1] - time_list[-2]
    delta_byte = byte_list[-1] - byte_list[-2]
    print("[Throughput] t:{:d} - {:.2f} Gbps".format(round(seconds), delta_byte / delta_time / 1000000000.0 * 8))

    



