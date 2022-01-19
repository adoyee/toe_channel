#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_ip.h>
#include <rte_byteorder.h>
#include <rte_ether.h>

#include "toe_channel.h"

static char *master_channel = "MASTER-CH";
static char *slave_channel = "SLAVE-CH";

struct toe_channel *m_channel;
struct toe_channel *s_channel;

struct rte_mbuf *
pkt_gen() {
    static struct rte_mempool *gen_pool = NULL;
    struct rte_mbuf *pkt;
    if(!gen_pool){
        gen_pool = rte_pktmbuf_pool_create("gen-pool", 2048, 256, 0, 1024 * 5, (int)rte_socket_id());
    }
    pkt = rte_pktmbuf_alloc(gen_pool);
    if(!pkt){
        return NULL;
    }
    rte_pktmbuf_append(pkt, 512);
    return pkt;
}

int slave_loop(void *ctx){
    rte_delay_ms(10);
    struct channel_option *opt = ctx;
    struct toe_channel *slave;

    slave = toe_channel_create(opt);
    assert(slave);
    s_channel = slave;
    toe_channel_connect(slave);

    for(;;){
        struct rte_mbuf *pkt;
        uint32_t  capacity;

        pkt = toe_channel_rx(slave);
        if(pkt){
            rte_pktmbuf_free(pkt);
        }

        capacity = toe_channel_tx_capacity(slave);
        if(capacity == 0){
            continue;
        }

        pkt = pkt_gen();
        if(!pkt){
            RTE_LOG(ERR, EAL, "gen pkt failed\n");
            continue;
        }
        toe_channel_tx(slave, pkt);
    }
    return 0;
}

int
master_loop(void *ctx){
    struct channel_option *opt = ctx;
    struct toe_channel *master;
    master = toe_channel_create(opt);
    assert(master);
    m_channel = master;

    for(;;){
        struct rte_mbuf  *pkt;
        pkt = toe_channel_rx(master);
        if(!pkt)
            continue;
        rte_pktmbuf_free(pkt);
    }
    printf("exit master loop\n");
    return 0;
}

void print_stats(const struct channel_stats *cur, struct channel_stats *last)
{
    printf("TX pps:%lu  bps:%.4f Gib Total %lu packets\n",
           cur->tx_ether - last->tx_ether,
           (double )(cur->tx_bytes - last->tx_bytes) * 8.0 / (1024.0 * 1024.0 * 1024.0),
           cur->tx_ether);

    printf("RX pps:%lu  bps:%.4f Gib Total %lu packets\n",
           cur->rx_ether - last->rx_ether,
           (double )(cur->rx_bytes - last->rx_bytes) * 8.0 / (1024.0 * 1024.0 * 1024.0),
           cur->rx_ether);

    memcpy(last, cur, sizeof (struct channel_stats));
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

    struct channel_stats master_stats;
    struct channel_stats slave_stats;
    memset(&master_stats, 0, sizeof (struct channel_stats));
    memset(&slave_stats, 0, sizeof (struct channel_stats));

    for(;;){
        rte_delay_ms(1000);
        if(!m_channel  || !s_channel)
            continue;
//        continue;
        const struct channel_stats *m_stats, *s_stats;
        m_stats = toe_channel_stats(m_channel);
        s_stats = toe_channel_stats(s_channel);
        printf("==== Master Side =====\n");
        print_stats(m_stats, &master_stats);
        printf("==== Slave Side =====\n");
        print_stats(s_stats, &slave_stats);
        printf("\n");
    }

    rte_eal_mp_wait_lcore();
    rte_eal_cleanup();
    return 0;
}
