#ifndef _TOE_CHANNEL_H_
#define _TOE_CHANNEL_H_

#include <rte_ethdev.h>
#include <rte_mbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

struct toe_channel;
typedef int toe_err_t;

#define TOE_SUCCESS     0
#define TOE_FAIL        1


struct channel_option {
    struct rte_ether_addr   remote_ether;
    struct rte_ether_addr   local_ether;
    rte_be32_t remote_ip;
    rte_be32_t local_ip;
    uint16_t port_id;
    const char *name;
};

struct channel_stats {
    uint64_t tx_ether;
    uint64_t tx_bytes;
    uint64_t tx_drops;
    uint64_t tx_seq;
    uint64_t tx_seq_bytes;
    uint64_t rx_ether;
    uint64_t rx_bytes;
    uint64_t rx_seq;
    uint64_t rx_seq_bytes;
    uint64_t rx_error;
};


struct toe_channel *
toe_channel_create(struct channel_option *opt);

int
toe_channel_connect(struct toe_channel *channel);

__rte_unused void
toe_channel_close(struct toe_channel *channel);

toe_err_t
toe_channel_tx(struct toe_channel *channel, struct rte_mbuf *pkt);

struct rte_mbuf *
toe_channel_rx(struct toe_channel *channel);

const struct channel_stats *
toe_channel_stats(struct toe_channel *channel);

__rte_unused uint32_t
toe_channel_tx_capacity(struct toe_channel *channel);

#ifdef __cplusplus
}
#endif

#endif // _TOE_CHANNEL_H_
