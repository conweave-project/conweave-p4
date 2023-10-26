# ConWeave Implementation on Tofino2 Leaf (ToR) Switches

This repo includes the ConWeave P4 implementation which includes the logic of ConWeave load balancing and DCQCN ECN Marking at switches.
The key feature needed to run ConWeave is Tofino2's Advanced Flow Control (AFC) that enables queue pause/resume. 

## ConWeave Logic

Logically, ConWeave implementation is categorized into two parts based on "where the (DATA or CONTROL) packet comes from":
(1) Source ToR (or `SrcToR`) - in case where the packet comes from the sender RNIC, this is the first hop for the packet.
(2) Destination ToR (or `DstToR`) - in case where the switch is connected to the receiver RNIC and this is the last hop for the packet.

### ![Source ToR (Ingress)](https://github.com/conweave-project/conweave-p4/blob/1db645659574ffe15100bc4f3c75ba2e99548025/leaf_conweave/p4src/includes/conweave_ingress.p4#L88-L308)
At SrcToR, DATA packet gets a proper ConWeave header and transmitted to DstToR. The packet checks whether the timeout (for RTT_REQUEST) happened.
If not, it continues to be sent to the current path. If timeout, it updates the epoch/reroute status and prepares rerouting.

<figure>
  <img src="figs/system-flowchart-rerouting.pdf" alt="">
</figure>






### How to distinguish packets on a virtual topology
Note that this repository is used to evaluate ConWeave with our own testbed with 16 RNICs on a _virtualized switching topology_.
Under that virtualized setting, it becomes highly complicated to distinguish whether the virtual switch corresponds to `SrcToR` or `DstToR` for the given input packet. 
This logic is implemented using the match-action table (see ![lines](https://github.com/conweave-project/conweave-p4/blob/1db645659574ffe15100bc4f3c75ba2e99548025/leaf_conweave/p4src/includes/conweave_ingress.p4#L77-L78)):
```c
do_categorize_conweave_logical_step.apply(); /* categorize with p4-compiler-friendly coding (SrcToR/DstToR) */
```

## DCQCN Logic

DCQCN logic is implemented at Egress pipeline because it needs the egress queue occupancy. 
