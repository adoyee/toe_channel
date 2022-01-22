#include <rte_malloc.h>
#include "toe_channel.h"
#include "toe_channel_impl.h"

#define DEV_MTU (1024 * 9)

static struct rte_eth_conf port_conf = {
        .rxmode = {
                .split_hdr_size = 0,
                .offloads = DEV_RX_OFFLOAD_CHECKSUM,
        },
        .txmode = {
                .mq_mode = ETH_MQ_TX_NONE,
                .offloads = DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_TCP_CKSUM,
        },
};

void
setup_port(uint16_t port_id, struct rte_mempool *pool)
{
    int ret;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txq_conf;
    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_fc_conf fc_conf;
    struct rte_eth_conf local_port_conf = port_conf;
    RTE_LOG(INFO, EAL, "setup ethernet port:%d, pool=%p\n", port_id, pool);

    rte_eth_dev_set_mtu(port_id, DEV_MTU);
    ret = rte_eth_dev_info_get(port_id, &dev_info);
    if(ret != 0){
        rte_exit(EXIT_FAILURE,
                 "Error during getting device (port %u) info: %s\n",
                 port_id, strerror(-ret));
    }

    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
        local_port_conf.txmode.offloads |=
                DEV_TX_OFFLOAD_MBUF_FAST_FREE;
    ret = rte_eth_dev_configure(port_id, 1, 1, &local_port_conf);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
                 ret, port_id);
    uint16_t nb_rxd = 1024;
    uint16_t nb_txd = 1024;
    rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);

    rxq_conf = dev_info.default_rxconf;
    rxq_conf.offloads = local_port_conf.rxmode.offloads;
    ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd,
                                 rte_eth_dev_socket_id(port_id),
                                 &rxq_conf,
                                 pool);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%s, port=%u\n",
                 rte_strerror(ret), port_id);

    txq_conf = dev_info.default_txconf;
    txq_conf.offloads = local_port_conf.txmode.offloads;
    ret = rte_eth_tx_queue_setup(port_id, 0, nb_txd,
                                 rte_eth_dev_socket_id(port_id),
                                 &txq_conf);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
                 ret, port_id);

    memset(&fc_conf, 0, sizeof (fc_conf));
    fc_conf.mode = RTE_FC_FULL;
    rte_eth_dev_flow_ctrl_set(port_id, &fc_conf);

    ret = rte_eth_dev_start(port_id);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
                 ret, port_id);

    rte_eth_promiscuous_enable(port_id);
}

static void inline
set_timer(uint64_t *timer, uint64_t ms)
{
    uint64_t  now, hz, v;
    now = rte_get_timer_cycles();
    hz = rte_get_timer_hz();
    v = now +  hz * ms / 1000;
    *timer = v;
}

void
format_frame_flag(char *buf, uint16_t size, const struct frame_hdr *hdr)
{
    memset(buf, 0, size);
    uint8_t flag =  hdr->frame_flag;

    switch (flag) {
        case(FLAG_ACK_FRAME) :
            snprintf(buf, size, "FLAG_ACK");
            break;
        case (FLAG_NACK_FRAME):
            snprintf(buf, size, "FLAG_NACK");
            break;
        case FLAG_DATA_FRAME:
            snprintf(buf, size, "FLAG_DATA");
            break;
        case (FLAG_ACK_FRAME|FLAG_DATA_FRAME):
            snprintf(buf, size, "FLAG_ACK|FLAG_DATA");
            break;
        case (FLAG_NACK_FRAME|FLAG_DATA_FRAME):
            snprintf(buf, size, "FLAG_NACK|FLAG_DATA");
            break;
        case (FLAG_HANDSHAKE_FRAME |FLAG_SYN_FRAME):
            snprintf(buf, size, "FLAG_SYN");
            break;
        case (FLAG_HANDSHAKE_FRAME |FLAG_ACK_FRAME):
            snprintf(buf, size, "FLAG_SYN_ACK");
            break;
        case 0:
            snprintf(buf, size, "FLAG_NONE");
            break;
        default:
            snprintf(buf, size, "FLAG_UNKNOWN(%2X)", flag);
            break;
    }
}

void
format_frame_hdr(char *buf, uint16_t size, const struct frame_hdr *hdr)
{
    char flag[64];
    memset(buf, 0, size);

    format_frame_flag(flag, sizeof (flag), hdr);

    snprintf(buf, size, "[FRAME: ip_id=%d [%s] frame_seq=%d, frame_ack=%d, addr = %p]",
             be16toh(hdr->frame_ip_id),
             flag,
             be32toh(hdr->frame_seq),
             be32toh(hdr->frame_ack), hdr);
}

const struct channel_stats *
toe_channel_stats(struct toe_channel *channel)
{
    return &channel->stats;
}

__rte_unused void
toe_channel_close(__rte_unused struct toe_channel *channel)
{
    // TODO
}

struct toe_channel *
toe_channel_create(struct channel_option *opt)
{
    struct toe_channel *channel;

    channel = rte_malloc(NULL, sizeof (struct toe_channel), 0);
    memset(channel, 0, sizeof (struct toe_channel));

    char pool_name[256];
    memset(pool_name, 0, 256);
    snprintf(pool_name, 256, "pool-%d", opt->port_id);

    channel->remote_ether = opt->remote_ether;
    channel->local_ether = opt->local_ether;
    channel->remote_ip = opt->remote_ip;
    channel->local_ip = opt->local_ip;
    channel->rx_queue = rx_queue_create(channel);
    channel->tx_queue = tx_queue_create(channel);
    channel->port_id = opt->port_id;
    channel->pool = rte_pktmbuf_pool_create(pool_name, 2048, 256, 0, 4096, (int)rte_socket_id());
    channel->dev_rx_queue = 1;
    strncpy(channel->name, opt->name, NAME_LEN);

    if(!channel->pool){
        rte_exit(1, "channel pool is null\n");
    }

    void *p = rte_pktmbuf_alloc(channel->pool);
    if (!p){
        rte_exit(1, "pool alloc pkt failure socket:%d\n", rte_lcore_id());
    }
    rte_pktmbuf_free(p);

    if(!channel->rx_queue || !channel->tx_queue ){
        rte_free(channel);
        return NULL;
    }

    setup_port(channel->port_id, channel->pool);

    return channel;
}

toe_err_t
toe_channel_connect(struct toe_channel *channel)
{
    struct rte_mbuf *pkt;
    struct frame_hdr *hdr;
    toe_err_t  err;

    pkt = rte_pktmbuf_alloc(channel->pool);
    if(!pkt){
        return 1;
    }

    err = toe_channel_frame_prepend(channel, pkt);
    if(unlikely(err))
        return err;

    hdr = frame_hdr_mtod(pkt);
    hdr->frame_flag |= FLAG_SYN_FRAME;
    hdr->frame_flag |= FLAG_HANDSHAKE_FRAME;

    toe_channel_do_tx_pkt(channel, pkt);
    channel->state = CHANNEL_STATE_EST;
    return 0;
}

uint16_t
toe_channel_do_rx_burst(struct toe_channel *channel, uint16_t queue_n)
{
    uint16_t rxs = 0;

    assert(RX_TX_BUFF_SIZE * queue_n < RX_TX_QUEUE_SIZE);
    memset(channel->rx_buf, 0, sizeof (struct rte_mbuf *) * RX_TX_QUEUE_SIZE);

    for(uint16_t i = 0; i < queue_n; i++) {
        uint16_t n;
        n = rte_eth_rx_burst(channel->port_id, i, channel->rx_buf + rxs , FRAME_ACK_SIZE);
        rxs += n;
    }
    if(rxs != 0)
        channel->stats.rx_ether += rxs;
    channel->rx_buf_len = rxs;
    return rxs;
}

__rte_unused uint32_t
toe_channel_tx_capacity(struct toe_channel *channel)
{
    toe_channel_do_tx(channel);
    return tx_queue_capacity(channel->tx_queue);
}

toe_err_t
toe_channel_tx(struct toe_channel *channel, struct rte_mbuf *pkt)
{
    toe_err_t  err;
    err = toe_channel_tx_queue_enqueue(channel, pkt);
    if(err){
        rte_pktmbuf_free(pkt);
        return err;
    }
    toe_channel_do_tx(channel);
    return err;
}

void
toe_channel_recv_pkt(struct toe_channel *channel, uint16_t pkt_n)
{
    struct rte_mbuf *pkt;
    struct frame_hdr *hdr;
    uint8_t  flag;

    for(uint16_t i = 0; i < pkt_n; i++){
        pkt = channel->rx_buf[i];
        channel->stats.rx_bytes += rte_pktmbuf_pkt_len(pkt);

        if(pkt->ol_flags & PKT_RX_IP_CKSUM_BAD){
            channel->stats.rx_error += 1;
            continue;
        }

        if(unlikely(rte_pktmbuf_pkt_len(pkt) < frame_hdr_len))
            continue;

        hdr = frame_hdr_mtod(pkt);
        flag = hdr->frame_flag;

        /** TODO 完整握手流程 */
        if(unlikely(flag & FLAG_HANDSHAKE_FRAME)){
            channel->state = CHANNEL_STATE_EST;
            rte_pktmbuf_free(pkt);
            return;
        }

#if DEBUG_TX_RX_LOG
        char msg[256];
        format_frame_hdr(msg, 256, hdr);
        RTE_LOG(INFO, EAL, "%s RX %s\n", channel->name, msg);
#endif

        if(flag & FLAG_DATA_FRAME)
            rx_queue_recv_data(channel->rx_queue, pkt);
        if(flag & (FLAG_NACK_FRAME | FLAG_ACK_FRAME))
            tx_queue_recv_ack(channel->tx_queue, pkt);

        rte_pktmbuf_free(pkt);
    }
}

void
rx_queue_recv_data(struct rx_queue *queue, struct rte_mbuf *pkt)
{
    struct frame_hdr *hdr;
    uint32_t seq;

    hdr = frame_hdr_mtod(pkt);
    seq = be32toh(hdr->frame_seq);

    if(likely(seq == queue->cur_ack)){
        struct rte_mbuf *saved_pkt;
        int err;

        queue->state = RX_STATE_NORMAL;
        queue->channel->stats.rx_seq += 1;
        queue->channel->stats.rx_seq_bytes += rte_pktmbuf_pkt_len(pkt);
        queue->cur_ack = seq + 1;
        queue->send_ack = 1;
        saved_pkt = rte_pktmbuf_clone(pkt, pkt->pool);
        err = rte_ring_enqueue(queue->items, saved_pkt);
        if(unlikely(err)){
            RTE_LOG(ERR, RING, "can not enqueue saved pkt.\n");
            rte_pktmbuf_free(saved_pkt);
        }
        return;
    }

    int32_t step_len;
    step_len = (int32_t) (seq - queue->cur_ack);

    /** 收到的seq不在预期范围内 */
    if(unlikely(step_len > FRAME_ACK_SIZE || step_len < -FRAME_ACK_SIZE)){
        /** TODO: reset or ignore ? */
        return;
    }

    /** 已经收到过的 */
    if(step_len < 0){
        return;
    }

    /** 收到了不连续seq, NACK只发送一次 */
    queue->state = RX_STATE_NACK;
    if(queue->last_nack != queue->cur_ack){
        queue->send_ack = 1;
        queue->last_nack = queue->cur_ack;
    }
}

struct rte_mbuf *
rx_queue_get_ack_pkt(struct rx_queue *queue, struct rte_mempool *pool)
{
    struct rte_mbuf *pkt = NULL;
    if(!queue->send_ack){
        return NULL;
    }

    pkt = rte_pktmbuf_alloc(pool);
    assert(pkt);
    toe_channel_frame_prepend(queue->channel, pkt);
    toe_channel_frame_set_ack(queue->channel, pkt);
    return pkt;
}

struct rte_mbuf *
rx_queue_dequeue(struct rx_queue *queue)
{
    struct rte_mbuf *pkt = NULL;
    rte_ring_dequeue(queue->items, (void **)&pkt);
    return pkt;
}

struct rx_queue *
rx_queue_create(struct toe_channel *channel)
{
    static int ring_id = 0;
    char ring_name[64];
    memset(ring_name, 0, 64);
    snprintf(ring_name, 64, "rx_queue ring:%d", ring_id++);

    struct rx_queue *queue = NULL;
    queue  = rte_zmalloc(ring_name, 1024, 0);
    if(!queue)
        return NULL;
    memset(queue, 0, sizeof (struct rx_queue));
    queue->items = rte_ring_create(ring_name, RX_TX_QUEUE_SIZE, (int)rte_socket_id(), 0);
    if(!queue->items){
        rte_free(queue);
        return NULL;
    }
    queue->channel = channel;
    return queue;
}

void
tx_queue_free_ack(struct tx_queue *queue, uint32_t ack)
{
    if(queue->head == queue->tail)
        return;

    for(uint32_t i = queue->head; i != ack; i++){
        struct rte_mbuf *pkt;

        uint32_t index;
        index = i % RX_TX_QUEUE_SIZE;

        pkt = queue->queue[index];

        if (pkt != NULL){
            rte_pktmbuf_free(pkt);
            queue->queue[index] = NULL;
        }
    }
    queue->head = ack;
}

struct rte_mbuf *
tx_queue_dequeue(struct tx_queue *queue)
{
    struct rte_mbuf *pkt, *ret;
    uint32_t  index;

    /** check timer */
    uint64_t now = rte_get_timer_cycles();
    if (unlikely((int64_t)(now - queue->retry_cycles) > 0)){
        queue->sent = queue->cur_ack;
        set_timer(&queue->retry_cycles, TX_RETRANSMIT_TIMER);
    }

    if(unlikely(queue->tail == queue->head))
        return NULL;

    if(unlikely(queue->sent == queue->tail)){
        return NULL;
    }

    index = queue->sent % RX_TX_QUEUE_SIZE;
    pkt = queue->queue[index];
    queue->sent += 1;
    ret = rte_pktmbuf_clone(pkt, pkt->pool);
    return ret;
}


toe_err_t
tx_queue_enqueue(struct tx_queue *queue, struct rte_mbuf *pkt)
{
    uint32_t index, non_ack;

    non_ack = queue->tail - queue->cur_ack;
    if(non_ack > FRAME_ACK_SIZE){
        return 1;
    }

    index = queue->tail % RX_TX_QUEUE_SIZE;
    if(queue->queue[index] != NULL){
        RTE_LOG(ERR, EAL, "tx_queue enqueue not empty location:%d, index:%d\n",
                queue->tail, index);
        rte_pktmbuf_free(queue->queue[index]);
    }

    queue->queue[index] = pkt;
    queue->tail += 1;
    return 0;
}

void
tx_queue_recv_ack(struct tx_queue *queue, struct rte_mbuf *pkt)
{
    struct frame_hdr *hdr;
    uint32_t ack;

    hdr = frame_hdr_mtod(pkt);
    ack = be32toh(hdr->frame_ack);

    /** 排除掉数据包乱序因素，ack并无可能小于当前ack. 因为接收端不会发送这样的ack.
     *  如果是NACK, 有可能等于当前cur
     */
    if(likely((int32_t)(ack - queue->cur_ack)) < 0){
        return;
    }

    /** ack 可能会大于sent, 因为sent会被NACK和定时器重置到cur_ack处。
     * 但ack不应大于tail. */
    if(unlikely((int32_t)(ack - queue->tail) > 0)){
        //TODO reset;
        return;
    }

    queue->cur_ack = ack;

    /** 当前ACK比sent大 */
    if(unlikely((int32_t)(queue->cur_ack - queue->sent) > 0)){
        queue->sent = queue->cur_ack;
    }

    if(unlikely(hdr->tcp_hdr.tcp_flags & FLAG_NACK_FRAME)){
        queue->sent = queue->cur_ack;
    }

    tx_queue_free_ack(queue, ack);
    set_timer(&queue->retry_cycles, TX_RETRANSMIT_TIMER);
}

uint32_t
tx_queue_capacity(struct tx_queue *queue)
{
    uint64_t non_ack;

    non_ack = queue->tail - queue->cur_ack;
    if(non_ack > FRAME_ACK_SIZE){
        return 0;
    }

    return FRAME_ACK_SIZE - non_ack;
}

struct tx_queue *
tx_queue_create(struct toe_channel *channel)
{
    struct tx_queue * queue;
    queue = rte_malloc("create channel tx_queue", sizeof (struct tx_queue), 0);
    if(!queue)
        return queue;
    memset(queue, 0, sizeof (struct tx_queue));
    queue->channel = channel;
    return queue;
}

toe_err_t
toe_channel_do_tx_pkt(struct toe_channel *channel, struct rte_mbuf *pkt)
{
    int ret;
    uint32_t len;

    toe_channel_frame_fill_id(channel, pkt);

#if DEBUG_TX_RX_LOG
    char msg[64];
    format_frame_hdr(msg, 64, frame_hdr_mtod(pkt));
#endif

    len = rte_pktmbuf_pkt_len(pkt);

#if DEBUG_RANDOM_DROP
    uint64_t rand = rte_rand();
    if ((rand % DEBUG_RANDOM_DROP) == 0 ){
        rte_pktmbuf_free(pkt);
        channel->stats.tx_bytes += len;
        channel->stats.tx_ether += 1;
        channel->stats.tx_drops += 1;
        return TOE_SUCCESS;
    }
#endif

    ret = rte_eth_tx_burst(channel->port_id, 0, &pkt, 1);
    if(ret != 1){
        char err_msg[64];
        format_frame_hdr(err_msg, 64, frame_hdr_mtod(pkt));
        RTE_LOG(ERR, EAL, "tx packet failure:FRAME :%s\n", err_msg);
        return TOE_FAIL;
    }else{
        channel->stats.tx_bytes += len;
        channel->stats.tx_ether += 1;

#if  DEBUG_TX_RX_LOG
        RTE_LOG(ERR, EAL, "%s TX :FRAME :%s\n", channel->name, msg);
#endif

        return TOE_SUCCESS;
    }
}

void
toe_channel_do_tx(struct toe_channel *channel)
{
    struct rte_mbuf *pkt;
    for(;;){
        pkt = toe_channel_tx_queue_dequeue(channel);
        if(pkt == NULL){
            break;
        }
        toe_channel_do_tx_pkt(channel, pkt);
    }
}

void
toe_channel_do_tx_after_rx(struct toe_channel *channel)
{
    struct rte_mbuf *pkt;

    pkt = rx_queue_get_ack_pkt(channel->rx_queue, channel->pool);
    if(pkt == NULL)
        return;
    toe_channel_do_tx_pkt(channel, pkt);
}

struct rte_mbuf *
toe_channel_rx(struct toe_channel *channel)
{
    struct rte_mbuf *pkt;

    pkt = toe_channel_rx_queue_dequeue(channel);
    if (pkt != NULL)
        return pkt;

    toe_channel_do_rx(channel);
    toe_channel_do_tx_after_rx(channel);
    pkt = toe_channel_rx_queue_dequeue(channel);

    return pkt;
}

void
toe_channel_do_rx(struct toe_channel *channel)
{
    uint16_t total;

    channel->rx_queue->send_ack = 0;
    total = toe_channel_do_rx_burst(channel, channel->dev_rx_queue);
    if(total == 0)
        return;
    toe_channel_recv_pkt(channel, total);
}

struct rte_mbuf *
toe_channel_rx_queue_dequeue(struct toe_channel *channel)
{
    struct rte_mbuf *pkt;
    char *data;

    pkt = rx_queue_dequeue(channel->rx_queue);
    if(pkt == NULL)
        return NULL;

    data = rte_pktmbuf_adj(pkt, sizeof (struct frame_hdr));
    if(unlikely(data == NULL)){
        RTE_LOG(ERR, EAL, "pkt in rx_queue can not adj\n") ;
        rte_pktmbuf_free(pkt);
        pkt = NULL;
    }

    return pkt;
}

toe_err_t
toe_channel_tx_queue_enqueue(struct toe_channel *channel, struct rte_mbuf *pkt)
{
    uint32_t capacity;
    toe_err_t  err;

    capacity = tx_queue_capacity(channel->tx_queue);
    if(capacity == 0){
        RTE_LOG(ERR, USER1, "channel tx queue is full, drop the packet.\n");
        return TOE_FAIL;
    }
    err = tx_queue_enqueue(channel->tx_queue, pkt);
    if(err)
        return err;

    err = toe_channel_frame_prepend(channel, pkt);
    if(err){
        RTE_LOG(ERR, EAL, "can prepend packet, drop the packet.\n");
        rte_pktmbuf_free(pkt);
        return TOE_FAIL;
    }

    toe_channel_frame_set_seq(channel, pkt);
    channel->stats.tx_seq += 1;
    channel->stats.tx_seq_bytes += rte_pktmbuf_pkt_len(pkt);
    return err;
}

struct rte_mbuf *
toe_channel_tx_queue_dequeue(struct toe_channel *channel)
{
    struct rte_mbuf *pkt;
    pkt = tx_queue_dequeue(channel->tx_queue);
    return pkt;
}

toe_err_t
toe_channel_frame_prepend(struct toe_channel *channel, struct rte_mbuf *pkt)
{
    char *data;
    struct frame_hdr *hdr;

    data = rte_pktmbuf_prepend(pkt, frame_hdr_len);
    if(unlikely(!data))
        return 1;

    hdr = frame_hdr_mtod(pkt);
    memset(hdr, 0, frame_hdr_len);
    hdr->ether_hdr.ether_type = htobe16(RTE_ETHER_TYPE_IPV4);
    hdr->ip4_hdr.next_proto_id = IPPROTO_TCP;
    hdr->ip4_hdr.time_to_live = 64;
    hdr->ip4_hdr.version_ihl = RTE_IPV4_VHL_DEF;
    hdr->ip4_hdr.total_length = htobe16(pkt->pkt_len - sizeof(struct rte_ether_hdr));

    rte_ether_addr_copy(&channel->remote_ether, &hdr->ether_hdr.d_addr);
    rte_ether_addr_copy(&channel->local_ether, &hdr->ether_hdr.s_addr);
    hdr->ip4_hdr.dst_addr = channel->remote_ip;
    hdr->ip4_hdr.src_addr = channel->local_ip;
    hdr->tcp_hdr.src_port = htobe16(PORT_OFFSET + channel->channel_id);
    hdr->tcp_hdr.dst_port = htobe16(PORT_OFFSET + channel->channel_id);

    return 0;
}
