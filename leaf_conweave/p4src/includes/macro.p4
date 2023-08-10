#ifndef _MACROS_
#define _MACROS_

#define LPBK_FOR_CTRL (1)
#define LPBK_FOR_NOTIFY (1)

/*************************************************************************/
/****** IMPORTANT: Different configuration for 25G/100G link speed *******/
#define CONWEAVE_EVAL_Q16_OR_Q32 (0) // 0: 16 per port, 1: 32 per port
// check all {config_leaf.py, leaf_conweave.cpp, macro.p4}
/*************************************************************************/

/** IMPORTANT: We assume using 32 queues per front-panel port. (see python script) */
/*************************************************************************/

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
 *************************************************************************/

/* for ConWeave Table */
#define CONWEAVE_HASH_WIDTH (12)  // maximum 16 bits
#define CONWEAVE_TABLE_SIZE (1 << CONWEAVE_HASH_WIDTH)
typedef bit<CONWEAVE_HASH_WIDTH> hashidx_t;

/* for ConWeave Reordering Queue */
#define CONWEAVE_QREG_IDX_WIDTH (10)  // 13 bits, at ingress
#define CONWEAVE_QREG_IDX_SIZE (1 << CONWEAVE_QREG_IDX_WIDTH)
typedef bit<CONWEAVE_QREG_IDX_WIDTH> conweave_qreg_idx_width_t;

#if (CONWEAVE_EVAL_Q16_OR_Q32 == 0) // 0: Q16 (25Gbps), 1: Q32 (100Gbps)
    #define CONWEAVE_QREG_IDX_OFFSET_C1 (2)
    #define CONWEAVE_QREG_IDX_OFFSET_C2 (6)
    #define CONWEAVE_QREG_IDX_OFFSET_C3 (10)
#else
    #define CONWEAVE_QREG_IDX_OFFSET_C1 (2)
    #define CONWEAVE_QREG_IDX_OFFSET_C2 (10)
    #define CONWEAVE_QREG_IDX_OFFSET_C3 (18)
#endif

#define CONWEAVE_QDEPTH_IDX_WIDTH (10)  // 13 bits, at egress
#define CONWEAVE_QDEPTH_IDX_SIZE (1 << CONWEAVE_QDEPTH_IDX_WIDTH)
typedef bit<CONWEAVE_QDEPTH_IDX_WIDTH> conweave_qdepth_idx_width_t;

/* type definitions */
typedef bit<32> afc_msg_t;
typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;

typedef bit<12> nexthop_id_t;
typedef bit<8> switch_id_t;
typedef bit<32> timestamp_t;          // use middle of 31 bits, e.g., (bit<32>)X[40:10]
#if (CONWEAVE_EVAL_Q16_OR_Q32 == 0)
    typedef bit<2> conweave_qid_width_t;  // 2 bits - 4 queues with 3 stages - total 12 queues
#else
    typedef bit<3> conweave_qid_width_t;  // 3 bits - 8 queues with 3 stages - total 24 queues
#endif


/************************************************************************************************/
/*                              FOR DEBUGGING (MAKE SLOW)                                       */
#define TIME_RESOLUTION_OFFSET1 (0) /* 17: (debug) 0.13 actual sec per unit, 0: original speed  */
#define TIME_RESOLUTION_OFFSET2 (0)  /* 7: (debug) max resolution, 0: original speed            */
/************************************************************************************************/

/** CONWEAVE: PARAMETERS */
const timestamp_t CONWEAVE_MAX_TIMESTAMP = 2147483647;  // 2**31 - 1

const timestamp_t CONWEAVE_TX_EXPIRED_TS = 10000000;                // for lossless RDMA, timegap to resume new epoch, "inf" for test-purpose
const timestamp_t CONWEAVE_TX_ECN_PORT_TS = 32;                     // time to drain Kmin-bytes queue (us), e.g., 100KB 100G -> 8us, 100KB 25G -> 32us
const timestamp_t CONWEAVE_TX_REPLY_TIMEOUT_EXTENSION_TS = 4;       // 4us, when resubmit a reply pkt, we extend the reply timer to avoid reply_timeout during the resubmit
const timestamp_t CONWEAVE_TX_STOP_REROUTING_TS = 2147473647;       // 2**31 - 10ms, just stop re-routing during 10ms to avoid timestamp wrap-around at RxToR

const timestamp_t CONWEAVE_RX_DEFAULT_WAITING_TIME = 10000;             // for lossless RDMA, 10ms for sanity for test-purpose
const timestamp_t CONWEAVE_RX_BASE_WAITING_TIME = 1000;                 // 32 (us) for 25G, extra waiting time for uncertainty
const timestamp_t CONWEAVE_RX_ADJUST_TS_TAIL_WRAP = 65536;              // 65536, when TAIL arrives
const timestamp_t CONWEAVE_RX_ADJUST_TS_TAIL_WRAP_WITH_BASE = 66536;    // 66536 = 65536 + CONWEAVE_RX_BASE_WAITING_TIME

/** CONWEAVE: ADVANCED FLOW CONTROL */
#define AFC_CREDIT_PAUSE (1)
#define AFC_CREDIT_RESUME (0)

/* for resubmission */
const bit<3> RESUB_DPRSR_DIGEST_REPLY = 7;

/* for mirroring */
const bit<8> MIRROR_SESSION_CONWEAVE = 220;  // + pipe_id (0,1,2,3)

/* for custom hashing (crc32_mpeg) */
CRCPolynomial<bit<32>>(32w0x04C11DB7, false, false, false, 32w0xFFFFFFFF, 32w0x00000000) CRC32_MPEG;

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
 *************************************************************************/

/* ARP */
#define MCAST_GRP_ID (1)

/* Mirror Types & Recirculation */
#if __TARGET_TOFINO__ == 2
#define RECIRC_PORT (6)             // recirc port on Tofino2
const bit<4> EG_MIRROR_TYPE_1 = 1;  // corresponds to eg_mirror1_h
const bit<4> IG_MIRROR_TYPE_1 = 2;  // corresponds to ig_mirror1_h
#else
#define RECIRC_PORT (68)  // recirc port on Tofino1
const bit<3> EG_MIRROR_TYPE_1 = 1;  // corresponds to eg_mirror1_h
const bit<3> IG_MIRROR_TYPE_1 = 2;  // corresponds to ig_mirror1_h
#endif

/* Hashing and Registers */
struct pair {  // for 32-bit pair
    bit<32> lo;
    bit<32> hi;
}

/* for ECMP LAG */
#define MAX_GROUP_SIZE (32)
#define MAX_GROUPS (256)
#define MAX_PROFILE_MEMBERS (2048)
#define TABLE_IPV4_SIZE (2048)
#define TABLE_NEXTHOP_SIZE (2048)
#define SCRAMBLE_ENABLE (1)
#define HASH_WIDTH (16)

#endif