/* -*- P4_16 -*- */
#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "includes/conweave_egress.p4"
#include "includes/conweave_ingress.p4"
#include "includes/headers.p4"
#include "includes/macro.p4"
#include "includes/parser.p4"

Pipeline(SwitchIngressParser(),
		 SwitchIngress(),
		 SwitchIngressDeparser(),
		 SwitchEgressParser(),
		 SwitchEgress(),
		 SwitchEgressDeparser()
		 ) pipe;

Switch(pipe) main;