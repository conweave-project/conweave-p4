from scapy.all import *
import os
import time


myhost = os.uname()[1]
assert(myhost=="lumos")
iface="ens2f0"

TOF2_0 = "64:9d:99:b1:26:0e"
TOF2_1 = "64:9d:99:b1:26:0f"

MINSIZE = 60
ETHERTYPE_PAD = 0x2000
ETHERTYPE_AFC = 0x2001

#test_port = 9 #31/1
#test_qid = 0

# def get_pg_id(dev_port):
#     # each pipe has 64 dev_ports + divide by 8 to get the pg_id
#     pg_id = ((dev_port % 128) >> 3)
#     return pg_id

# def get_pg_queue(dev_port, qid):
#     lane = dev_port % 8
#     pg_queue = lane * 16 + qid # there are 16 queues per lane
#     return pg_queue

class AFC(Packet):
    name = "adv_flow_ctl"
    fields_desc=[
        BitField("qfc", 0, 1),
        BitField("tm_pipe_id", 0, 2),
        BitField("tm_mac_id", 0, 4),
        BitField("pad", 0, 3),
        BitField("tm_mac_qid", 0, 7),
        BitField("credit", 0, 15) # 15-bit signed integer value
        ]


def send_pause(pg_pipe, pg_port, pg_queue):
    pkt_pause = Ether(type=ETHERTYPE_AFC, src=TOF2_0, dst=TOF2_1)
    pkt_pause = pkt_pause/AFC(
        qfc = 1, # 1 bit
        tm_pipe_id = pg_pipe, # 2 bits
        tm_mac_id = pg_port, # 4 bits
        tm_mac_qid = pg_queue, # 10 bits
        credit = 1
        )
    pkt_pause = pkt_pause/("0" * (MINSIZE - len(pkt_pause)))
    pkt_pause.show()
    sendp(pkt_pause, iface=iface)

def send_unpause(pg_pipe, pg_port, pg_queue):
    pkt_unpause = Ether(type=ETHERTYPE_AFC, src=TOF2_0, dst=TOF2_1)
    pkt_unpause = pkt_unpause/AFC(
        qfc = 1,
        tm_pipe_id = pg_pipe,
        tm_mac_id = pg_port,
        tm_mac_qid = pg_queue,
        credit = 0
        )
    pkt_unpause = pkt_unpause/("0" * (MINSIZE - len(pkt_unpause)))
    pkt_unpause.show()
    sendp(pkt_unpause, iface=iface)

# print("************ Pause ************")
send_pause(1, 1, 16) # dev_port = 137, qid = 0
# print("************ Sleep 5 Seconds ************")
# time.sleep(5)
# print("************ Un-Pause ************")
# send_unpause(1, 1, 16) # dev_port = 137, qid = 0
