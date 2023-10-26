## DCQCN ECN-Marking Example

This repo includes DCQCN ECN marking example using range-based match-action table.
Please ignore some code blocks for ingress/egress mirroring, or you can reuse them to verify whether packets are correctly ECN-marked.

* There are two key scripts: `p4src/native_dcqcn.p4` and the control plane scripts in `cp/setup.py`.

* We built and tested using `bf-sde-9.11.1` and Tofino1 switch.
