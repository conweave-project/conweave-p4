# ConWeave Implementation on Tofino2 Leaf (ToR) Switches

This repo includes the ConWeave P4 implementation which includes the logic of ConWeave load balancing and DCQCN ECN Marking at switches.
The key feature needed to run ConWeave is Tofino2's Advanced Flow Control (AFC) that enables queue pause/resume. 

## ConWeave Logic

Logically, ConWeave implementation is categorized into two parts based on "where the (DATA or CONTROL) packet comes from":
1. Source ToR (or `SrcToR`) - in case where the packet comes from the sender RNIC, this is the first hop for the packet. For the logical flow, see [flowchart](figs/system-flowchart-rerouting.pdf)
2. Destination ToR (or `DstToR`) - in case where the switch is connected to the receiver RNIC and this is the last hop for the packet.

* To configure ConWeave parameters, see [macro.p4](p4src/includes/macro.p4) and comments for details.


### Virtual Topology
Note that this repository is used to evaluate ConWeave on our testbed with 16 RNICs and a _virtualized switching topology_.
Under that virtualized setup, it becomes complicated to distinguish whether the virtual switch corresponds to `SrcToR` or `DstToR` for the given input packet. 
This logic is implemented via assignment `switch_id` to each port and match-action tables (see [lines](https://github.com/conweave-project/conweave-p4/blob/1db645659574ffe15100bc4f3c75ba2e99548025/leaf_conweave/p4src/includes/conweave_ingress.p4#L77-L78)):
```c
...
get_switch_id.apply();   	/* -> meta.switch_id */
...
do_categorize_conweave_logical_step.apply(); /* categorize with p4-compiler-friendly coding (SrcToR/DstToR) */
...
```
