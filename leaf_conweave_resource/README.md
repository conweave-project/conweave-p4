# CongWeave Implementation on Tofino2 Leaf Switches

CongWeave + DCQCN ECN Marking

using Advanced Flow Control in Tofino2 (queue pause/resume)


## Don't forget to configure static queues using run_pd_rpc.py !!


## Queue Id Mapping

```
Logical : dev_port (137), queue_id (0)
```

: input at ingress metadata (ig_intr_md_for_tm.ucast_egress_port, ig_intr_md_for_tm.qid), and output at egress metadata (eg_intr_md.egress_port, eg_intr_md.egress_qid)


```
Physical : pg_pipe (1), pg_port (1), pg_qid (16) -> for ```

: input for `run_pd_rpc`, and advanced flow control (`ig_intr_md_for_dprsr.adv_flow_ctl`). 