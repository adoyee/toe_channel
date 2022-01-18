#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_ip.h>
#include <rte_byteorder.h>
#include <rte_ether.h>

#include "toe_channel.h"
#include "toe_queue.h"

static char *master_channel = "MASTER-CH";
static char *slave_channel = "SLAVE-CH";

static uint64_t tx_seq_n = 0;
static uint64_t rx_seq_n = 0;

struct toe_master *app_master;
struct toe_slave *app_slave;

struct toe_channel *m_channel;
struct toe_channel *s_channel;


static struct rte_mempool *gen_pool;
static struct rte_mbuf *
pkt_gen() {
    struct rte_mbuf *pkt;
    if(!gen_pool){
        gen_pool = rte_pktmbuf_pool_create("gen-pool", 512, 256, 0, 4096, (int)rte_socket_id());
    }
    tx_seq_n += 1;
    pkt = rte_pktmbuf_alloc(gen_pool);
    rte_pktmbuf_prepend(pkt, 4096);
    return pkt;
}

#define DEV_MTU (1024 * 9)

int slave_loop(void *ctx){
    rte_delay_ms(10);
    struct channel_option *opt = ctx;
    struct toe_channel *slave;

    slave = toe_channel_create(opt);
    assert(slave);
    s_channel = slave;
    toe_channel_connect(slave);
    rte_delay_ms(5);

    struct rte_mbuf *rq, *cq;

    rte_delay_ms(10);
    for(;;){
        int capacity = 0;
        capacity = toe_channel_tx_capacity(slave);
        if(capacity == 0){
//            RTE_LOG(ERR, EAL, "SLAVE tx_queue is full\n");
            continue;
        }
        struct rte_mbuf *pkt  = pkt_gen();
        toe_channel_tx(slave, pkt);
        toe_channel_rx(slave);


//        rq = toe_master_get_rq(app_master);
//        toe_channel_tx(slave, rq);
//        cq = toe_channel_rx(slave);
//        if(!cq)
//            continue;
//        toe_master_put_cq(app_master, cq);
    }
    return 0;
}

 int master_loop(void *ctx){
    struct channel_option *opt = ctx;
    struct toe_channel *master;
    master = toe_channel_create(opt);
    assert(master);
    m_channel = master;


     struct rte_mbuf *pkt;
     for(;;){
         pkt = toe_channel_rx(master);
         if(!pkt)
             continue;
//         toe_slave_put_rq(app_slave, pkt);
//         pkt = toe_slave_get_cq(app_slave);
//         if(!pkt)
//             continue;
//         toe_channel_tx(master, pkt);
        rx_seq_n += 1;
         rte_pktmbuf_free(pkt);
     }
     printf("exit master loop\n");
     return 0;
}

int
main(int argc, char **argv)
{
    uint16_t port_n;

    int ret = rte_eal_init(argc, argv);
    if(ret < 0){
        RTE_LOG(ERR, EAL, " Can not init eal\n");
        return 1;
    }

    port_n = rte_eth_dev_count_avail();
    if(port_n < 2){
        rte_panic("not enough Ethernet port\n");
    }

    uint16_t  lcore, master_lcore, slave_lcore, lcore_n;
    lcore_n = rte_lcore_count();
    if(lcore_n < 3){
        rte_panic("not enough lcore\n");
    }

    lcore = rte_lcore_id();
    master_lcore = rte_get_next_lcore(lcore, 1, 0);
    slave_lcore = rte_get_next_lcore(master_lcore, 1, 0);
    printf("main-core:%d, master channel core:%d, slave channel core:%d\n", lcore, master_lcore, slave_lcore);

    toe_mbuf_pool_init();
    app_master =   toe_master_create(0);
    app_slave = toe_slave_create(0);

    rte_be32_t master_ip = RTE_IPV4(192, 168, 0, 1);
    rte_be32_t slave_ip = RTE_IPV4(192, 168, 0, 2);
    struct rte_ether_addr master_ether, slave_ether;
    rte_eth_random_addr(master_ether.addr_bytes);
    rte_eth_random_addr(slave_ether.addr_bytes);

    struct channel_option master_opt, slave_opt;

    master_opt.remote_ip = slave_ip;
    master_opt.local_ip = master_ip;
    master_opt.remote_ether = slave_ether;
    master_opt.local_ether = master_ether;
    master_opt.port_id = 2;
    master_opt.name = master_channel;

    slave_opt.remote_ip = master_ip;
    slave_opt.local_ip = slave_ip;
    slave_opt.remote_ether = master_ether;
    slave_opt.local_ether = slave_ether;
    slave_opt.port_id = 3;
    slave_opt.name = slave_channel;

    char dev_master[256];
    rte_eth_dev_get_name_by_port(2, dev_master);
    char dev_slave[256];
    rte_eth_dev_get_name_by_port(3, dev_slave);
    printf("master in port [%s], slave in port [%s]\n", dev_master, dev_slave);


    rte_eal_remote_launch(master_loop, &master_opt, master_lcore);
    rte_eal_remote_launch(slave_loop, &slave_opt, slave_lcore);

    for(;;){
        static uint64_t m_tx_packet_last;
        static uint64_t m_rx_packet_last;
        static uint64_t m_tx_bytes_last;
        static uint64_t m_rx_bytes_last;

        static uint64_t s_tx_packet_last;
        static uint64_t s_rx_packet_last;
        static uint64_t s_tx_bytes_last;
        static uint64_t s_rx_bytes_last;
        rte_delay_ms(1000);

        if (!m_channel || !s_channel){
            printf("Waiting channel initialize\n");

            continue;
        }

        const struct channel_stats *m_stats, *s_stats;
        m_stats = toe_channel_stats(m_channel);
        s_stats = toe_channel_stats(s_channel);

//        const char clr[] = { 27, '[', '2', 'J', '\0' };
//        const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };
//
//        /* Clear screen and move to top left */
//        printf("%s%s", clr, topLeft);

        printf("==== Master side ====\n");
        printf("tx packets:%lu, rx packets:%lu\n", m_stats->tx_ether, m_stats->rx_ether);
        printf("tx pps:%lu bps:%lu, rx pps:%lu bps:%lu\n",
               m_stats->tx_ether - m_tx_packet_last,
               (m_stats->tx_bytes - m_tx_bytes_last) * 8,
               m_stats->rx_ether - m_rx_packet_last,
               (m_stats->rx_bytes - m_rx_bytes_last) * 8);

        m_tx_bytes_last = m_stats->tx_bytes;
        m_tx_packet_last = m_stats->tx_ether;
        m_rx_bytes_last = m_stats->rx_bytes;
        m_rx_packet_last = m_stats->rx_ether;

        printf("==== Slave side ====\n");
        printf("tx packets:%lu, rx packets:%lu\n", s_stats->tx_ether, s_stats->rx_ether);
        printf("tx pps:%lu bps:%lu, rx pps:%lu bps:%lu\n",
               s_stats->tx_ether - s_tx_packet_last,
               (s_stats->tx_bytes - s_tx_bytes_last) * 8,
               s_stats->rx_ether - s_rx_packet_last,
               (s_stats->rx_bytes - s_rx_bytes_last) * 8);

        s_tx_bytes_last = s_stats->tx_bytes;
        s_tx_packet_last = s_stats->tx_ether;
        s_rx_bytes_last = s_stats->rx_bytes;
        s_rx_packet_last = s_stats->rx_ether;

    }
    rte_eal_mp_wait_lcore();
    rte_eal_cleanup();

    return 0;
}
