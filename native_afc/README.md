# AFC Egress-Pause Speed Test
We compiled and tested the example using `bf-sde-9.11.1`. 

The important part you must focus on is the AFC header:
```c
header adv_flow_ctl_h {
    bit<32> adv_flow_ctl;

    /** 32-bit adv_flow_ctl format */
    // bit<1> qfc;
    // bit<2> tm_pipe_id;
    // bit<4> tm_mac_id;
    // bit<3> _pad;
    // bit<7> tm_mac_qid;
    // bit<15> credit; 
}
```


## Prerequisite
1. After building and running `native_afc.p4`, run the port setup using `cp/setup.py`:
```shell
$ ./run_bfshell.sh -b `pwd`/cp/setup.py
```
Note that based on your cabling, you should change the port number values in the script, appropriately. 


2. In `cp` directory,
* We implemented `send_afc_pause.py` that generates a AFC packet pausing the specific queue. 
* We implemented `rpc_afc_config.py`, a `run_pd_rpc` script that enables AFC on the pipe.

For more details such as mapping between logical and physical port numbering, see `Tofino Native Architecture` documentation. 

## Speed of PFC from Ingress to Egress (25Gbps Port Speed)
1. Config AFC at egress, and `eg_bypass = 0`:
```
set_afc_activate(1) # egress
set_afc_egress_bypass(0) # no bypass
```
then send `PAUSE`.

2. Use the scapy script `send_afc_pause.py`. Send 1 `PAUSE`, 10 `PING`. 
Check the Queue occupancy with `bfshell`. The queue should have 11 packets.
3. Config AFC at Ingress, and `eg_bypass=1`:
```
set_afc_activate(0) # ingress
set_afc_egress_bypass(1) # egress bypass
```
Then, send 1 `RESUME`.

4. Eventually, right after `RESUME`, the queued `PAUSE` will immediately pause the queue at egress deparser. 

### Result
We observe total 8 packets (10 cells) are dequeued, including `PAUSE` packet.