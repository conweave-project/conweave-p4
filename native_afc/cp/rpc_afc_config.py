# python3 $SDE/run_pd_rpc.py `pwd`/rpc_afc_config.py

# Step 1: enable AFC on the pipe
pipe_id = 1
qid = 0
dev_port = 137
rst = tm.sched_adv_fc_mode_enable_get(dev=0, pipe=pipe_id)
print("Default enable mode on the pipe is " + str(rst))
tm.sched_adv_fc_mode_enable_set(dev=0, pipe=pipe_id, enable=True)
rst = tm.sched_adv_fc_mode_enable_get(dev=0, pipe=pipe_id)
print("After, enable mode on the pipe is " + str(rst))

# Step 1: enable AFC *mode* on the queue
q_mode = tm.sched_q_adv_fc_mode_get(dev=0, port=dev_port, q=qid)
print("Default queue mode is " + str(q_mode))
tm.sched_q_adv_fc_mode_set(dev=0, port=dev_port, q=qid, mode=1) # mode: 1 is XOFF, 0 if CREDIT
q_mode = tm.sched_q_adv_fc_mode_get(dev=0, port=dev_port, q=qid)
print("After set, queue mode is " + str(q_mode))
assert(q_mode==1)
