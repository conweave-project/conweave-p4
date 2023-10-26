# ## Port rate limiting (dev_port = 129) -- Tofino1b
# # tm.set_port_shaping_rate(port=129, pps=False, burstsize=1500, rate=100, dev=0) # 100 Kbps 
# # tm.set_port_shaping_rate(port=129, pps=False, burstsize=1500, rate=1 * 1000000, dev=0) # 1 Gbps
# tm.set_port_shaping_rate(port=129, pps=False, burstsize=1100, rate=24336000, dev=0) # 23 Gbps
# tm.enable_port_shaping(port=129, dev=0)


## Port rate limiting (dev_port = 140) -- P4campus-proc1
tm.set_port_shaping_rate(port=140, pps=False, burstsize=1100, rate=24336000, dev=0) # 24.336 Gbps
tm.enable_port_shaping(port=140, dev=0)
