#include <rte_malloc.h>
#include "toe_channel.h"
#include "toe_channel_impl.h"

#define DEV_MTU (1024 * 9)

static struct rte_eth_conf port_conf = {
        .rxmode = {
                .split_hdr_size = 0,
        },
        .txmode = {
                .mq_mode = ETH_MQ_TX_NONE,
        },
};

static void
setup_port(uint16_t port_id, struct rte_mempool *pool)
{
    int ret;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txq_conf;
    struct rte_eth_rxconf rxq_conf;
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

    ret = rte_eth_dev_start(port_id);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
                 ret, port_id);

    rte_eth_promiscuous_enable(port_id);

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

static inline bool
uint32_less_than(uint32_t a, uint32_t b)
{
    if(likely(a < b))
        return true;

    if((a - b) > (UINT32_MAX - RX_TX_QUEUE_SIZE))
        return true;
    return false;
}

static inline bool
uint32_greater_than(uint32_t a, uint32_t b)
{
    if(likely(a > b))
        return true;

    if((b - a) > (UINT32_MAX - RX_TX_QUEUE_SIZE))
        return true;
    return false;
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
    channel->pool = rte_pktmbuf_pool_create(pool_name, 512, 256, 0, 4096, (int)rte_socket_id());
    channel->dev_rx_queue = 1;
    strncpy(channel->name, opt->name, NAME_LEN);

    if(!channel->pool){
        rte_exit(1, "channel pool is null\n");
    }

    void *p = rte_pktmbuf_alloc(channel->pool);
    if (!p){
        rte_exit(1, "pool alloc pkt failure socket:%d\n", rte_lcore_id());
    }

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
        n = rte_eth_rx_burst(channel->port_id, i, channel->rx_buf + rxs , RX_TX_BUFF_SIZE);
        rxs += n;
    }
    if(rxs != 0)
        channel->stats.rx_ether += rxs;
    return rxs;
}

__rte_unused uint32_t
toe_channel_tx_capacity(struct toe_channel *channel)
{
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

    err = toe_channel_frame_prepend(channel, pkt);
    if(err){
        RTE_LOG(ERR, USER1, "can prepend packet, drop the packet.\n");
        rte_pktmbuf_free(pkt);
        return 1;
    }

    toe_channel_frame_set_seq(channel, pkt);

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

        hdr = frame_hdr_mtod(pkt);
        flag = hdr->frame_flag;

        /** TODO 完整握手流程 */
        if(unlikely(flag & FLAG_HANDSHAKE_FRAME)){
            channel->state = CHANNEL_STATE_EST;
        }

//        char msg[256];
//        format_frame_hdr(msg, 256, hdr);
//        RTE_LOG(INFO, EAL, "%s RX %s\n", channel->name, msg);

        if(flag & FLAG_DATA_FRAME)
            rx_queue_recv_pkt(channel->rx_queue, pkt);
        if(flag & FLAG_NACK_FRAME)
            tx_queue_recv_nack(channel->tx_queue, pkt);
        if(flag & FLAG_ACK_FRAME)
            tx_queue_recv_ack(channel->tx_queue, pkt);

        rte_pktmbuf_free(pkt);
    }
}

void
rx_queue_recv_pkt(struct rx_queue *queue, struct rte_mbuf *pkt)
{
    switch (queue->state) {
        case RX_STATE_NORMAL:
        case RX_STATE_NACK_TO_NORMAL:
            rx_queue_recv_pkt_ack_state(queue, pkt);
            break;
        case RX_STATE_NACK:
        case RX_STATE_NORMAL_TO_NACK:
            rx_queue_recv_pkt_nack_state(queue, pkt);
    }
}

void
rx_queue_recv_pkt_ack_state(struct rx_queue *queue, struct rte_mbuf *pkt)
{
    struct frame_hdr *hdr;
    uint32_t seq;

    hdr = frame_hdr_mtod(pkt);
    seq = be32toh(hdr->frame_seq);

    if(likely(seq == queue->cur_ack)){
        struct rte_mbuf *saved_pkt;
        int err;

        queue->channel->stats.rx_seq += 1;
        queue->cur_ack += 1;
        saved_pkt = rte_pktmbuf_clone(pkt, pkt->pool);
        err = rte_ring_enqueue(queue->items, saved_pkt);
        if(err)
            rte_pktmbuf_free(saved_pkt);
        return;
    }

    /** 收到了不连续seq */
    if(uint32_greater_than(seq, queue->cur_ack)){
        queue->state = RX_STATE_NORMAL_TO_NACK;
        queue->cur_nack = seq;
        RTE_LOG(INFO, USER1, "rx_queue enter nack-state, %u, expected %u\n", seq, queue->cur_ack);
    }

    /** 忽略掉seq小于cur_ack的包 */
}

void
rx_queue_recv_pkt_nack_state(struct rx_queue *queue, struct rte_mbuf *pkt)
{
    struct frame_hdr *hdr;
    uint32_t seq;

    hdr = frame_hdr_mtod(pkt);
    seq = be32toh(hdr->frame_seq);

    /** nack 状态只接收cur_ack和cur_nack之间的重传包 */
    if(unlikely(seq != queue->cur_ack))
        return;

    if(likely(seq == queue->cur_ack)){
        struct rte_mbuf *saved_pkt;
        int err;

        queue->cur_ack += 1;
        saved_pkt = rte_pktmbuf_clone(pkt, pkt->pool);
        err = rte_ring_enqueue(queue->items, saved_pkt);
        if(err)
            rte_pktmbuf_free(saved_pkt);
    }

    /** 检查是否恢复 */
    if(seq == queue->cur_nack){
        queue->state = RX_STATE_NACK_TO_NORMAL;
        RTE_LOG(INFO, USER1, "rx_queue exit nack-state\n");
    }
}

struct rte_mbuf *
rx_queue_get_ack_pkt(struct rx_queue *queue, struct rte_mempool *pool)
{
    struct rte_mbuf *pkt = NULL;

    switch (queue->state) {
        case RX_STATE_NORMAL:
            /** ACK 不重发 */
            if(queue->cur_ack != queue->pre_sent_ack){
                queue->pre_sent_ack = queue->cur_ack;
                pkt = rte_pktmbuf_alloc(pool);
                assert(pkt != NULL);
                toe_channel_frame_prepend(queue->channel, pkt);
                toe_channel_frame_set_ack(queue->channel, pkt);
            }
            break;

        /** 恢复正常时发送ACK */
        case RX_STATE_NACK_TO_NORMAL:
            queue->state = RX_STATE_NORMAL;
            queue->pre_sent_ack = queue->cur_ack;
            pkt = rte_pktmbuf_alloc(pool);
            assert(pkt != NULL);
            toe_channel_frame_prepend(queue->channel, pkt);
            toe_channel_frame_set_ack(queue->channel, pkt);
            break;

        /** 失序时发送NACK */
        case RX_STATE_NORMAL_TO_NACK:
            queue->state = RX_STATE_NACK;
            pkt = rte_pktmbuf_alloc(pool);
            assert(pkt != NULL);
            toe_channel_frame_prepend(queue->channel, pkt);
            toe_channel_frame_set_nack(queue->channel, pkt);

        /** NACK状态不发送ACK，也不发送 NACK*/
        default:
            break;
    }
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

//    RTE_LOG(INFO, EAL, "%s free_tx_queue[%u:%u)\n", queue->channel->name,  queue->head, ack);
    for(uint32_t i = queue->head; i != ack; i++){
        struct rte_mbuf *pkt;
        struct frame_hdr *hdr;

        uint32_t index;
        index = i % RX_TX_QUEUE_SIZE;

        pkt = queue->queue[index];
        hdr = frame_hdr_mtod(pkt);

        if (pkt != NULL){
            uint32_t seq = be32toh(hdr->frame_seq);
            if((seq % RX_TX_QUEUE_SIZE) !=  index){
                RTE_LOG(ERR, EAL, "%s free seq not match:%d, expected:%d\n", queue->channel->name,  i, seq % RX_TX_QUEUE_SIZE);
            }
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

    if(likely(queue->state == TX_STATE_NORMAL)){
        if(likely(queue->sent != queue->tail)){
            index = queue->sent % RX_TX_QUEUE_SIZE;
            pkt = queue->queue[index];
            queue->sent += 1;
            queue->len -= 1;
            ret = rte_pktmbuf_clone(pkt, pkt->pool);
            return ret;
        }
        return NULL;
    }

    /** nack state : 重复发送 cur_ack 到 cur_nack 之间的数据 */
    if(queue->nack_sent == queue->nack){
        queue->nack_sent = queue->cur_ack;
    }

    index = queue->nack_sent % RX_TX_QUEUE_SIZE;
    pkt = queue->queue[index];
    queue->nack_sent += 1;
    queue->len -= 1;
    ret = rte_pktmbuf_clone(pkt, pkt->pool);
    return ret;
}


void
tx_queue_enqueue(struct tx_queue *queue, struct rte_mbuf *pkt)
{
    uint32_t index;

    index = queue->tail % RX_TX_QUEUE_SIZE;
    if(queue->queue[index] != NULL){
        RTE_LOG(ERR, EAL, "tx_queue enqueue not empty location:%d, index:%d\n",
                queue->tail, index);
        rte_pktmbuf_free(queue->queue[index]);
    }
//    RTE_LOG(INFO, EAL, "%s set tx_queue[%d]\n", queue->channel->name,  index);

    queue->queue[index] = pkt;
    queue->tail += 1;
    queue->len += 1;
}

void
tx_queue_recv_ack(struct tx_queue *queue, struct rte_mbuf *pkt)
{
    struct frame_hdr *hdr;
    uint32_t ack;

    hdr = frame_hdr_mtod(pkt);
    ack = be32toh(hdr->frame_ack);

    if(queue->cur_ack == ack)
        return;

    if(uint32_greater_than(ack, queue->tail)){
        RTE_LOG(ERR, USER1, "get incorrect ack:%d cur_ack:%d cur_tail:%d\n",
                ack, queue->cur_ack, queue->tail);
        return;
    }

    if(uint32_less_than(ack, queue->head)){
        RTE_LOG(ERR, USER1, "get incorrect ack:%d cur_ack:%d cur_tail:%d\n",
                ack, queue->cur_ack, queue->tail);
        return;
    }

    queue->state = TX_STATE_NORMAL;
    tx_queue_free_ack(queue, ack);
    queue->cur_ack = ack;
}

void
tx_queue_recv_nack(struct tx_queue *queue, struct rte_mbuf *pkt)
{
    struct frame_hdr *hdr;
    uint32_t nack;

    hdr = frame_hdr_mtod(pkt);
    nack = be32toh(hdr->frame_ack);

    if(queue->state == TX_STATE_NACK)
        return;

    if(uint32_greater_than(nack, queue->tail)){
        RTE_LOG(ERR, USER1, "get incorrect nack:%d cur_ack:%d cur_tail:%d\n",
                nack, queue->cur_ack, queue->tail);
        return;
    }

    if(uint32_less_than(nack, queue->head)){
        RTE_LOG(ERR, USER1, "get incorrect nack:%d cur_ack:%d cur_tail:%d\n",
                nack, queue->cur_ack, queue->tail);
        return;
    }

    queue->state = TX_STATE_NACK;
    queue->nack_sent = queue->cur_ack;
    queue->nack = nack;
}

uint32_t
tx_queue_capacity(struct tx_queue *queue)
{
    uint32_t capacity;

    if(unlikely(queue->state == TX_STATE_NACK)){
//        RTE_LOG(ERR, EAL, "%s capacity is 0 on nack state\n", queue->channel->name);
        return 0;
    }

    capacity = RX_TX_QUEUE_SIZE - queue->len;
    if(capacity > FRAME_ACK_SIZE)
        return  FRAME_ACK_SIZE;
    return capacity;
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

int
toe_channel_do_tx_pkt(struct toe_channel *channel, struct rte_mbuf *pkt)
{
    int ret;

    toe_channel_frame_fill_id(channel, pkt);
    ret = rte_eth_tx_burst(channel->port_id, 0, &pkt, 1);
    if(ret != 1){
        char msg[64];
        format_frame_hdr(msg, 64, frame_hdr_mtod(pkt));
        RTE_LOG(ERR, EAL, "tx packet failure:FRAME :%s\n", msg);
    }else{
        channel->stats.tx_bytes += rte_pktmbuf_pkt_len(pkt);
        channel->stats.tx_ether += 1;
//        char msg[64];
//        format_frame_hdr(msg, 64, frame_hdr_mtod(pkt));
//        RTE_LOG(INFO, EAL, "%s TX packet success %d  FRAME:%s %p\n", channel->name, pkt->pkt_len,msg, pkt);
    }
    return 0;
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
        RTE_LOG(ERR, USER1, "pkt in rx_queue can not adj\n") ;
        rte_pktmbuf_free(pkt);
        pkt = NULL;
    }

    return pkt;
}

toe_err_t
toe_channel_tx_queue_enqueue(struct toe_channel *channel, struct rte_mbuf *pkt)
{
    uint32_t capacity;
    toe_err_t err;

    capacity = tx_queue_capacity(channel->tx_queue);
    if(capacity == 0){
        RTE_LOG(ERR, USER1, "channel tx queue is full, drop the packet.\n");
        rte_pktmbuf_free(pkt);
        return 1;
    }
    tx_queue_enqueue(channel->tx_queue, pkt);

    return 0;
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
    hdr->ether_hdr.ether_type = RTE_ETHER_TYPE_IPV4;
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
