#ifndef _TOE_CHANNEL_IMPL_H_
#define _TOE_CHANNEL_IMPL_H_

#include <rte_tcp.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_mbuf.h>

#include "toe_channel.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FLAG_SYN_FRAME          RTE_TCP_SYN_FLAG
#define FLAG_ACK_FRAME          RTE_TCP_ACK_FLAG
#define FLAG_NACK_FRAME         RTE_TCP_URG_FLAG
#define FLAG_DATA_FRAME         RTE_TCP_PSH_FLAG
#define FLAG_RESET_FRAME        RTE_TCP_RST_FLAG

#define STATE_INIT              0x0000
#define STATE_EST               0x0100
#define STATE_RESET             0x0200
#define STATE_SENT_SYN          0x0001
#define STATE_WAIT_LAST_ACK     0x0010
#define STATE_HANDSHAKE_MASK    0x00FF

/** 最大允许未确认包数 */
#define FRAME_ACK_SIZE          256
/** 收发队列，不能小于允许未确认数 */
#define RX_TX_QUEUE_SIZE        1024
/** 每次接收数量(rx_burst) */
#define RX_TX_BUFF_SIZE         32
/** retransmit 定时器 (毫秒) */
#define TX_RETRANSMIT_TIMER     20
/** tcp_port = port_offset + channel_id */
#define PORT_OFFSET             8000
/** 连接超时(秒) */
#define CONNECT_TIMEOUT         30

#define NAME_LEN                32

#define DEBUG_TX_RX_LOG         0
#define DEBUG_RANDOM_DROP       0

struct frame_hdr {
    struct rte_ether_hdr ether_hdr;
    struct rte_ipv4_hdr ip4_hdr;
    struct rte_tcp_hdr tcp_hdr;
} __rte_packed;

#define frame_ip_id     ip4_hdr.packet_id
#define frame_seq       tcp_hdr.sent_seq
#define frame_ack       tcp_hdr.recv_ack
#define frame_flag      tcp_hdr.tcp_flags

static_assert(sizeof(struct rte_ether_hdr) == 14, "assert size failed");
static_assert(sizeof(struct frame_hdr) == sizeof(struct rte_ether_hdr) \
 + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr), "assert size failed");

#define frame_hdr_mtod(m) rte_pktmbuf_mtod(m, struct frame_hdr *)
#define frame_set_flag(pkt, flag)   \
do{                                 \
    struct frame_hdr *hdr;          \
    hdr = frame_hdr_mtod(pkt);      \
    hdr->frame_flag = flag;         \
}while(0)

static void inline
frame_set_flags(struct rte_mbuf *pkt, uint8_t flag)
{
    struct frame_hdr *hdr;
    hdr = frame_hdr_mtod(pkt);
    hdr->frame_flag = flag;
}

void
format_frame_flag(char *buf, uint16_t size, const struct frame_hdr *hdr);
void
format_frame_hdr(char *buf, uint16_t size, const struct frame_hdr *hdr);

typedef enum {
    RX_STATE_NORMAL = 0,
    RX_STATE_NACK,
} rx_state_t;

struct rx_queue {
    uint32_t cur_ack;
    uint32_t send_ack;
    uint32_t last_nack;
    rx_state_t state;
    struct toe_channel *channel;
    struct rte_ring *items;     /** 保存已经发送过ACK的包 */
};

void
rx_queue_recv_data(struct rx_queue *queue, struct rte_mbuf *pkt);

struct rte_mbuf *
rx_queue_get_ack_pkt(struct rx_queue *queue, struct rte_mempool *pool);

struct rte_mbuf *
rx_queue_dequeue(struct rx_queue *queue);

struct rx_queue *
rx_queue_create(struct toe_channel *channel);

void
rx_queue_clear(struct rx_queue *queue);

struct tx_queue {
    uint32_t cur_ack;
    uint32_t head;
    uint32_t tail;
    uint32_t sent;
    uint64_t retry_cycles;
    struct toe_channel *channel;
    struct rte_mbuf *queue[RX_TX_QUEUE_SIZE];
};

void
tx_queue_recv_ack(struct tx_queue *queue, struct rte_mbuf *pkt);

void
tx_queue_free_ack(struct tx_queue *queue, uint32_t ack);

struct rte_mbuf *
tx_queue_dequeue(struct tx_queue *queue);

toe_err_t
tx_queue_enqueue(struct tx_queue *queue, struct rte_mbuf *pkt);

void
tx_queue_clear(struct tx_queue *queue);

uint32_t
tx_queue_capacity(struct tx_queue *queue);

struct tx_queue *
tx_queue_create(struct toe_channel *channel);

typedef enum {
   MODE_MASTER = 0,
   MODE_SLAVE
}channel_mode_t;

struct toe_channel{
    uint16_t channel_id;
    rte_atomic64_t ip_id;
    rte_atomic64_t seq;
    struct rte_mempool *pool;
    channel_mode_t mode;
    uint64_t reset_timer;
    uint32_t state;
    uint32_t retransmit;
    uint16_t port_id;
    uint16_t dev_rx_queue;
    struct rte_mbuf *rx_buf[RX_TX_QUEUE_SIZE];
    struct rx_queue *rx_queue;
    struct tx_queue *tx_queue;

    RTE_MARKER  fill_frame_fields;
    struct rte_ether_addr remote_ether;
    struct rte_ether_addr local_ether;
    rte_be32_t remote_ip;
    rte_be32_t local_ip;

    RTE_MARKER  other_field;
    struct channel_stats stats;
    char name[NAME_LEN];
};

void toe_channel_do_rx(struct toe_channel *channel);

uint16_t
toe_channel_do_rx_burst(struct toe_channel *channel, uint16_t queue_n);

void
toe_channel_do_tx(struct toe_channel *channel);

toe_err_t
toe_channel_do_tx_pkt(struct toe_channel *channel, struct rte_mbuf *pkt);

toe_err_t
toe_channel_do_connect_tx(struct toe_channel *channel);

void
toe_channel_do_tx_after_rx(struct toe_channel *channel);

toe_err_t
toe_channel_do_reset(struct toe_channel *channel);

struct rte_mbuf *
toe_channel_rx_queue_dequeue(struct toe_channel *channel);

toe_err_t
toe_channel_tx_queue_enqueue(struct toe_channel *channel, struct rte_mbuf *pkt);

void
toe_channel_do_retransmit(struct toe_channel *channel);

struct rte_mbuf *
toe_channel_tx_queue_dequeue(struct toe_channel *channel);

const uint16_t frame_hdr_len = sizeof (struct rte_ether_hdr) \
        + sizeof (struct rte_ipv4_hdr) \
        + sizeof (struct rte_tcp_hdr);

toe_err_t
toe_channel_frame_prepend(struct toe_channel *channel, struct rte_mbuf *pkt);

static inline void
toe_channel_frame_set_ack(struct toe_channel *channel, struct rte_mbuf *pkt)
{
    struct frame_hdr *hdr;
    uint32_t  ack;

    hdr = frame_hdr_mtod(pkt);
    ack = channel->rx_queue->cur_ack;
    hdr->tcp_hdr.recv_ack = htobe32(ack);

    if(likely(channel->rx_queue->state == RX_STATE_NORMAL)){
        hdr->tcp_hdr.tcp_flags &= (~FLAG_NACK_FRAME);
        hdr->tcp_hdr.tcp_flags |= FLAG_ACK_FRAME;
    } else {
        hdr->tcp_hdr.tcp_flags &= (~FLAG_ACK_FRAME);
        hdr->tcp_hdr.tcp_flags |= FLAG_NACK_FRAME;
    }
}

static inline void
toe_channel_frame_set_seq(struct toe_channel *channel, struct rte_mbuf *pkt)
{
    struct frame_hdr *hdr;
    uint32_t  seq;

    hdr = frame_hdr_mtod(pkt);
    seq = rte_atomic64_add_return(&channel->seq, 1);
    channel->stats.tx_seq = channel->seq.cnt;
    hdr->tcp_hdr.sent_seq = htobe32(seq - 1);
    hdr->tcp_hdr.tcp_flags |= FLAG_DATA_FRAME;
}

static inline void
toe_channel_frame_fill_id(struct toe_channel *channel, struct rte_mbuf *pkt)
{
    struct frame_hdr *hdr;
    uint64_t ip_id;
    uint16_t ip_id_be;

    ip_id = rte_atomic64_add_return(&channel->ip_id, 1);
    ip_id_be = (uint16_t)(ip_id & 0xFFFF);
    ip_id_be = htobe16(ip_id_be);

    hdr = frame_hdr_mtod(pkt);
    hdr->ip4_hdr.packet_id = ip_id_be;
}

void
toe_channel_recv_conn(struct toe_channel *channel, struct rte_mbuf *pkt);

struct rte_mbuf *
toe_channel_gen_pkt(struct toe_channel *channel);

__rte_unused void
prefetch_channel(struct toe_channel *channel)
{
    rte_prefetch2(channel->fill_frame_fields);
    rte_prefetch2(channel->other_field);
}

#ifdef __cplusplus
}
#endif

#endif // _TOE_CHANNEL_IMPL_H_
