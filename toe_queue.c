#include <rte_lcore.h>
#include <rte_mempool.h>
#include <rte_malloc.h>

#include "toe_queue.h"

#define LCORE_MAX   16

static struct rte_mempool *pkt_pool;
static struct toe_master *masters[LCORE_MAX];
static struct toe_slave *slaves[LCORE_MAX];

__rte_unused void
toe_master_init()
{
    uint32_t  lcore_n = rte_lcore_count();
    toe_mbuf_pool_init();

    for(uint32_t i = 0; i < lcore_n; i++){
        struct toe_master *master = toe_master_create((uint16_t)i);
        masters[i] = master;
    }
}

__rte_unused void
toe_slave_init()
{
    uint32_t  lcore_n = rte_lcore_count();

    for(uint32_t i = 0; i < lcore_n; i++){
        struct toe_slave *slave= toe_slave_create((uint16_t)i);
        slaves[i] = slave;
    }
}

__rte_unused struct rte_mbuf *
master_get_rq()
{
    struct toe_master *master;
    uint32_t lcore;

    lcore = rte_lcore_id();
    master = masters[lcore];

    return toe_master_get_rq(master);
}

__rte_unused void
master_put_cq(struct rte_mbuf *pkt)
{
    struct toe_master *master;
    uint32_t lcore;

    lcore = rte_lcore_id();
    master = masters[lcore];

    toe_master_put_cq(master, pkt);
}

__rte_unused void
master_reset()
{
    uint32_t  lcore_n = rte_lcore_count();
    for(int i = 0; i < lcore_n; i++){
        struct toe_master *master= masters[i];
        if(master!= NULL)
            toe_master_reset(master);
    }
}

__rte_unused struct rte_mbuf *
slave_get_cq()
{
    struct toe_slave *slave;
    uint32_t lcore = rte_lcore_id();
    slave = slaves[lcore];

    return toe_slave_get_cq(slave);
}

__rte_unused void
slave_put_rq(struct rte_mbuf *pkt)
{
    struct toe_slave *slave;
    uint32_t lcore = rte_lcore_id();
    slave = slaves[lcore];
    toe_slave_put_rq(slave, pkt);
}

__rte_unused void
slave_reset()
{
    uint32_t  lcore_n = rte_lcore_count();
    for(int i = 0; i < lcore_n; i++){
        struct toe_slave *slave = slaves[i];
        if(slave != NULL)
            toe_slave_reset(slave);
    }
}

void
toe_mbuf_pool_init()
{
    pkt_pool = rte_pktmbuf_pool_create("toe-pkt-pool",
        512,
        256,
        0,
        TOE_DATA_SIZE + 1024,
        (int)rte_socket_id());

    if (!pkt_pool)
        rte_panic("create toe pktmbuf pool failure\n");
}

struct toe_master *
toe_master_create(uint16_t core_id)
{
    struct toe_master *master = rte_malloc("malloc toe_master", sizeof (struct toe_master), 0);
    if (!master)
        rte_panic("malloc toe master failure\n");
    memset(master, 0, sizeof (struct toe_master));
    master->core_id = core_id;
    master->seq = 1;

    return master;
}

static void
master_free_record(struct master_entry *records)
{
    for(int i = 0; i < MASTER_QUEUE_SIZE; i++){
        struct master_entry *record = records + i;
        if(record->ts != 0 && record->pkt != NULL){
            rte_mbuf_raw_free(record->pkt);
            record->ts = 0;
            record->pkt = NULL;
        }
    }
}

__rte_unused void
toe_master_free(struct toe_master *master)
{
    master_free_record(master->records);
    rte_free(master);
}

void
toe_master_reset(struct toe_master *master)
{
    master->flag_resend = 1;
    for(int i = 0; i < MASTER_QUEUE_SIZE; i++){
        struct master_entry *record = master->records + i;
        if (record->seq != 0)
            record->resend = 1;
    }
    RTE_LOG(WARNING, EAL, "channel reset\n");
}

struct rte_mbuf *
toe_master_create_rq(struct toe_master *master, uint16_t index)
{
    struct rte_mbuf *pkt;
    pkt = rte_pktmbuf_alloc(pkt_pool);
    if (!pkt) {
        rte_panic("create toe pkt failure\n");
    }


    uint64_t  id = master->seq++;
    struct toe_request *request;
    request = rte_pktmbuf_mtod(pkt, struct toe_request*);
    request->magic = TOE_DATA_MAGIC;
    request->seq = id;
    request->core_id = master->core_id;
    request->index = index;

    return pkt;
}

struct rte_mbuf *
toe_master_get_resend(struct toe_master *master)
{
    for(int i = 0; i < MASTER_QUEUE_SIZE; i++){
        struct master_entry *record = master->records + i;
        if (record->resend != 1){
            continue;
        }

        record->ts = rte_get_timer_cycles();
        record->resend = 0;
        struct rte_mbuf* pkt = rte_pktmbuf_clone(record->pkt, pkt_pool);
        return pkt;
    }

    master->flag_resend = 0;
    return NULL;
}

struct rte_mbuf *
toe_master_get_rq(struct toe_master *master)
{
    if(unlikely(master->flag_resend))
        return toe_master_get_resend(master);

    for(int i = 0; i < MASTER_QUEUE_SIZE; i++){
        struct master_entry *record = master->records + i;
        if (record->seq != 0)
            continue;

        struct rte_mbuf *ret;
        struct rte_mbuf *pkt = toe_master_create_rq(master, (uint16_t)i);
        struct toe_request *rq;
        rq = rte_pktmbuf_mtod(pkt, struct toe_request*);
        record->ts = rte_get_timer_cycles();
        record->pkt = pkt;
        record->seq = rq->seq;
        record->resend = 0;
        rte_pktmbuf_append(pkt, TOE_DATA_SIZE);
        ret = rte_pktmbuf_clone(pkt, pkt_pool);

        RTE_LOG(WARNING, EAL, "GET-RQ: seq = %ld, index = %d, lcore = %d\n", rq->seq, rq->index, rte_lcore_id());
        return ret;
    }

    RTE_LOG(WARNING, EAL, "GET-RQ: NULL\n");

    return NULL;
}

void
toe_master_put_cq(struct toe_master *master, struct rte_mbuf *pkt)
{
    uint64_t ts = rte_get_timer_cycles();
    struct toe_request * request;
    request = rte_pktmbuf_mtod(pkt, struct toe_request*);

    char dump[256];
    memset(dump, 0, sizeof (dump));
    snprintf(dump, 256, "CQ: seq=%ld index=%d lcore=%d", request->seq, request->index, rte_lcore_id());

    if(request->magic != TOE_DATA_MAGIC){
        rte_pktmbuf_free(pkt);
        RTE_LOG(WARNING, EAL, "magic wrong %Xd, expect %Xd %s\n", request->magic, TOE_DATA_MAGIC, dump);
        return;
    }


    if(request->core_id != master->core_id){
        RTE_LOG(WARNING, EAL, "wrong core_id, expect %d %s\n", master->core_id, dump);
        rte_pktmbuf_free(pkt);
        return;
    }

    if(request->index >= MASTER_QUEUE_SIZE){
        RTE_LOG(WARNING, EAL, "wrong index:%d %s\n", request->index, dump);
        rte_pktmbuf_free(pkt);
        return;
    }

    struct master_entry *record = master->records + request->index;
    if(request->seq != record->seq){
        RTE_LOG(WARNING, EAL, "seq:%lu do not match %lu %s\n", request->seq, record->seq, dump);
        rte_pktmbuf_free(pkt);
        return;
    }

    uint64_t time_usage = ts - record->ts;
    rte_atomic64_add(&master->time_usage, (int64_t)time_usage);
    rte_atomic64_add(&master->cq_n, 1);

    record->ts = 0;
    record->seq = 0;
    record->resend = 0;

    rte_pktmbuf_free(pkt);
    rte_pktmbuf_free(record->pkt);
}

struct toe_slave *
toe_slave_create(__attribute__((unused)) uint16_t core_id)
{
    struct toe_slave *slave;
    struct rte_ring *stage;

    char msg[32];
    memset(msg, 0, 32);
    snprintf(msg, 32, "slave-queue-core:%d", core_id);

    stage = rte_ring_create(msg, SLAVE_QUEUE_SIZE, 0, 0);
    if(!stage){
        rte_panic("create slave ring failure\n");
    }

    slave = rte_malloc("slave", sizeof (struct toe_slave), 0);
    if(!slave)
        rte_panic("malloc slave failure\n");

    memset(slave, 0, sizeof (struct toe_slave));
    slave->entries = stage;

    return slave;
}

__rte_unused void
toe_slave_free(struct toe_slave *slave)
{
    rte_ring_free(slave->entries);
    rte_free(slave);
}

void
toe_slave_reset(__rte_unused struct toe_slave *slave)
{
    // TODO
}

struct rte_mbuf *
toe_slave_get_cq(struct toe_slave *slave)
{
    struct rte_mbuf *pkt;
    int err;

    err = rte_ring_dequeue(slave->entries, (void **)&pkt);

    if(err)
        return NULL;
    return pkt;
}

void
toe_slave_put_rq(struct toe_slave *slave, struct rte_mbuf *pkt)
{
    struct toe_request *req;
    req = rte_pktmbuf_mtod(pkt, struct toe_request*);
    if(req->index >= MASTER_QUEUE_SIZE || req->core_id > 16){
        RTE_LOG(WARNING, EAL, "SLAVE: maybe incorrect rq(seq:%lu, core_id:%d, index:%d)\n",
            req->seq, req->core_id, req->index);
    }

    rte_ring_enqueue(slave->entries, pkt);
}
