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


## Where AFC works
AFC packet (with AFC header) works at ingress deparser and/or egress deparser. 
Note that it must be very careful to clearly pause the queue and all packets
It is because the AFC packet must be activated at pipeline's deparser, but it takes a time to go through the pipeline.
So, there can be a minor leakage of some packets (dequeued) although you pause the queue.

Here is the toy example showing that although you resume and immediately pause a queue, due to the timing, some packets have dequeued and egressed. 

## Prerequisite
1. After building and running `native_afc.p4`, run the port setup using `cp/setup.py`:
```shell
$ ./run_bfshell.sh -b `pwd`/cp/setup.py
```
Note that based on your cabling, you should change the port number values in the script, appropriately. 


2. In `cp` directory,
* We implemented `send_afc_pause.py` that generates a AFC packet pausing the specific queue. 
* We implemented `rpc_afc_config.py`, a `run_pd_rpc` script that enables AFC on the pipe.

For more details such as mapping between logical and physical port numbering, see `Tofino Native Architecture (TNA)` documentation from Intel Barefoot. 

3. You must know the Tofino architecture. At a high level, it has a flow of ingress pipeline, traffic manager (queues), and egress pipeline. Each pipeline includes parser, processing pipeline, and deparser. 
You can refer to `Tofino Native Architecture (TNA)` documentation.


## Speed of PFC from Ingress to Egress (25Gbps Port Speed)
1. Config AFC at egress, and `eg_bypass = 0`:
```
set_afc_activate(1) # activate "AFC" at egress, deactivated at ingress
set_afc_egress_bypass(0) # no bypass
```
then send 1 `PAUSE` packet. This will pause the queue, and `PAUSE` packet will be egressed out.


2. Use the scapy script `send_afc_pause.py`. Send 1 `PAUSE` and 10 `PING`. 
Check the Queue occupancy with `bfshell`. The queue should have 11 packets (1 `PAUSE` and 10 `PING`).


3. Config AFC at Ingress, and `eg_bypass=1`:
```
set_afc_activate(0) # activate "AFC" at ingress, deactivated at egress
set_afc_egress_bypass(1) # egress bypass
```
Then, send 1 `RESUME`. 

This `RESUME` packet will resume the queue at ingress and be queued. 
After that, the previously enqueued `PAUSE` packet will go through egress pipeline and pause the queue (activated at egress deparser). 
 


### Result
We observe total 8 packets (10 cells) are dequeued, including `PAUSE` packet.

Why not 11 packets? It is because when `PAUSE` packet passing through egress pipeline, 2 ping packets have dequeued concurrently. They are not affected by `PAUSE` action as they are already dequeued and are being sent out to egress port.
In ConWeave, we carefully implemented P4 program to consider this issue. 
To solve this, we used priority queues (but we did not mention this issue in the paper since it is too detailed). 