#ifndef _TOE_QUEUE_H_
#define _TOE_QUEUE_H_

#include <rte_ring.h>
#include <rte_mbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TOE_DATA_SIZE               (1024 * 4)
#define TOE_DATA_MAGIC              0x1234ABCD
#define MASTER_QUEUE_SIZE           32
#define SLAVE_QUEUE_SIZE            64

__rte_unused void
toe_master_init();

__rte_unused void
toe_slave_init();

__rte_unused struct rte_mbuf *
master_get_rq();

__rte_unused void
master_put_cq(struct rte_mbuf *pkt);

__rte_unused void
master_reset();

__rte_unused struct rte_mbuf *
slave_get_cq();

__rte_unused void
slave_put_rq(struct rte_mbuf *pkt);

__rte_unused void
slave_reset();

void toe_mbuf_pool_init();

struct toe_request {
    uint32_t magic;
    uint64_t seq;
    uint16_t core_id;
    uint16_t index;
};

struct master_entry {
    uint64_t ts;
    uint64_t seq;
    struct rte_mbuf *pkt;
    uint16_t resend;
};

struct toe_master {
    uint16_t core_id;
    uint16_t flag_resend;
    uint64_t seq;
    rte_atomic64_t cq_n;
    rte_atomic64_t time_usage;
    struct master_entry records[MASTER_QUEUE_SIZE];
};

struct toe_master *toe_master_create(uint16_t core_id);
__rte_unused void toe_master_free(struct toe_master *master);
void toe_master_reset(struct toe_master *master);
struct rte_mbuf *toe_master_get_rq(struct toe_master *master);
void toe_master_put_cq(struct toe_master *master, struct rte_mbuf *data);

struct toe_slave {
    struct rte_ring *entries;
};

struct toe_slave *toe_slave_create(__attribute__((unused)) uint16_t core_id);
__rte_unused void toe_slave_free(struct toe_slave *slave);
void toe_slave_reset(__attribute__((unused)) struct toe_slave *slave);
struct rte_mbuf *toe_slave_get_cq(struct toe_slave *slave);
void toe_slave_put_rq(struct toe_slave *slave, struct rte_mbuf *pkt);

#ifdef __cplusplus
}
#endif

#endif // _TOE_QUEUE_H_
