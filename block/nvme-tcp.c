/*
 * NVMe/TCP block driver
 *
 * Copyright (c) 2025 TU Ilmenau
 *
 * Authors:
 *  Philipp Schock <philipp.schock@tu-ilmenau.de>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include <asm-generic/errno-base.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "qemu/cutils.h"
#include "qemu/bswap.h"
#include "qapi/error.h"
#include "block/qdict.h"
#include "qemu/option.h"
#include "qemu/typedefs.h"
#include "io/channel.h"
#include "glib.h"
#include "qapi-types-sockets.h"
#include "qapi-visit-block-core.h"
#include "qobject/qdict.h"
#include "io/channel-socket.h"
#include "qemu/uuid.h"
#include "qemu/coroutine-core.h"
#include "system/block-backend.h"
#include "block/block_int.h"
#include <time.h>
#include "system/iothread.h"
#include "trace.h"
#include "qemu/coroutine_int.h"

#include "block/nvme.h"
#include "block/nvme-fabrics.h"
#include "block/nvme-tcp.h"

/**
 * general TODO:
 * - alignment other than 0
 * - fix indents, wrap long lines, sort includes,...
 * - correctly free everything on (early) exit
 * - don't error_abort outside of startup
 * - improve tracing (less with every cmd, more with config and state changes)
 * - make iothread-ioqueue-mapping a less hacky startup thing, like iothread-vq-mapping
 * - make ioq iothread mapping cache friendlier
 * - finally figure out why the sgl flag is 0x40 instead of 0x80
 * - everything indicated with // comments
 */

typedef struct NvmeTcpQueue NvmeTcpQueue;

typedef struct BDRVNVMeTCPState {
    NvmeTcpQueue *admin_queue;

    QemuMutex thread_ioq_mapping_wlock; /* reads should be disjoint */
    NvmeTcpQueue **io_queues;
    unsigned next_unused_io_q; /* protected by thread_ioq_mapping_wlock */
    unsigned max_num_io_queues;

    QEMUTimer *ka_timer;

    uint16_t cntlid;
    bool write_cache_supported;
    size_t page_size; /* in bytes */
    uint64_t max_transfer; /* max bytes per io cmd */
    uint32_t nsid;
    uint64_t nsze; /* namespace size in blocks */
    int blkshift;
    unsigned ioccsz; /* max in-capsule data in bytes */
    unsigned sqsize; // TODO

    bool supports_write_zeroes;
    int64_t max_write_zeroes; /* in bytes */

    bool supports_discard;
    uint8_t dmrl;
    uint32_t dmrsl;
    uint64_t dmsl;

    /*
     * needed for refresh_filename()
     * and to reestablish connection if lost
     */
    QemuUUID hostid;
    SocketAddress tgtsock;
    char *subsysnqn;
    unsigned num_io_threads;
} BDRVNVMeTCPState;

typedef struct NvmeTcpReadInfo {
    QEMUIOVector *qiov;
    uint32_t bytes_received;
    bool last;
} NvmeTcpReadInfo;

typedef struct NvmeTcpR2tInfo {
    uint32_t r2to;
    uint32_t r2tl;
    uint16_t ttag;
} NvmeTcpR2tInfo;

// TODO: put qiov and r2t shit in a union
typedef struct NvmeTcpResponseCtx {
    Coroutine *co;
    union {
        NvmeTcpReadInfo *readinfo;
        NvmeTcpR2tInfo *r2tinfo;
    } u;
    bool exists; /* to prevent having to allocate and delete this all the time */
    bool io_done;
    bool missing_read_data; /* data buffer fragmentation */
    bool co_waiting;
    uint8_t expected_type;
} NvmeTcpResponseCtx;

#define RCTXRBUF_SIZE 512

struct NvmeTcpQueue {
    QIOChannelSocket *sioc;
    QemuThread thread;

    CoMutex wlock;
    CoMutex rlock;

    NvmeTcpResponseCtx rctxrbuf[RCTXRBUF_SIZE];
    unsigned rctxrbuf_tail_idx;
    uint16_t rctxrbuf_tail_cid;

    uint16_t qid;
    uint16_t next_cid;

    unsigned sqsize; // TODO

    uint8_t controller_alignment_bytes;
    uint32_t maxh2cdata;
};

#define NVME_TCP_BLOCK_OPT_IP "tgtsock.host"
#define NVME_TCP_BLOCK_OPT_PORT "tgtsock.port"
#define NVME_TCP_BLOCK_OPT_SUBSYSNQN "subsysnqn"

/**
 * Parse a filename in the format of nvme-tcp://ipv4:port/subsysnqn
 * Example:
 *
 *     nvme-tcp://127.0.0.1:4420/nqn.2014-08.org.nvmexpress:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6
 *
 * where the "nvme-tcp://" is a fixed form of the protocol prefix, the middle part
 * is the target's socket address (IPv4), and the last part is the nqn of the subsystem.
 *
 * TODO: support IPv6
 */
static void nvme_tcp_parse_filename(const char *filename, QDict *options,
                                Error **errp)
{
    int pref = strlen("nvme-tcp://");

    if (strlen(filename) > pref && !strncmp(filename, "nvme-tcp://", pref)) {
       /* parse ip */
        const char *ip_ptr = filename + pref;
        const char *colon_ptr = strchr(ip_ptr, ':');
        if (!colon_ptr) {
            error_setg(errp, "Invalid filename: missing character ':'");
            return;
        }
        char *ip = g_strndup(ip_ptr, colon_ptr - ip_ptr);
        qdict_put_str(options, NVME_TCP_BLOCK_OPT_IP, ip);
        g_free(ip);

        /* parse port */
        const char *port_ptr = colon_ptr + 1;
        const char *slash_ptr = strchr(port_ptr, '/');
        if (!slash_ptr) {
            error_setg(errp, "Invalid filename: missing character '/'");
            return;
        }
        unsigned port;
        if (qemu_strtoui(port_ptr, &slash_ptr, 10, &port)) {
            error_setg(errp, "Invalid filename: invalid port");
            return;
        }
        qdict_put_int(options, NVME_TCP_BLOCK_OPT_PORT, port);

        /* parse subsysnqn */
        const char *subsysnqn_ptr = slash_ptr + 1;
        const char *null_ptr = strchr(ip_ptr, '\0');
        if (!null_ptr) {
            error_setg(errp, "Invalid filename: not null-terminated");
            return;
        }
        char *subsysnqn = g_strndup(subsysnqn_ptr, null_ptr - subsysnqn_ptr);
        qdict_put_str(options, NVME_TCP_BLOCK_OPT_SUBSYSNQN, subsysnqn);
        g_free(subsysnqn);
    }
}

#define NVME_TCP_HOST_DATA_ALIGNMENT 0
#define NVME_TCP_HOST_DATA_ALIGNMENT_BYTES ((NVME_TCP_HOST_DATA_ALIGNMENT + 1) * 4)
#define NVME_TCP_MAX_R2T 0 /* 0-based, important to conserve 1-1 ratio of cmds and responses */

static size_t nvme_tcp_calculate_padding(const size_t len, const size_t alignment)
{
    return ((alignment - (len % alignment)) % alignment);
}

// TODO
// if specific error, reconnect
// (split the __nvme_tcp_open function for (re)connect function)
// (maybe rename it to connect_to_disk/target or establish_initial_connections)
// (or reconnect or whatever or just nvme_tcp_connect)
// see chapter 9.6 in the base spec!!!!!!
/**
 * Place an entire entry into the submission queue of @q.
 * DO NOT split entries over multiple iovecs in a coroutine context!
 * Locks and unlocks @q->wlock appropiately if in coroutine.
 */
static coroutine_mixed_fn int nvme_tcp_sendv(NvmeTcpQueue *q, const struct iovec *iov, size_t niov, Error **errp)
{
    ERRP_GUARD();
    int rc;

    if (qemu_in_coroutine()) {
        qemu_co_mutex_lock(&q->wlock);
    }
    rc = qio_channel_writev_all(QIO_CHANNEL(q->sioc), iov, niov, errp);
    if (qemu_in_coroutine()) {
        qemu_co_mutex_unlock(&q->wlock);
    }
    if (rc) {
        error_prepend(errp, "Write error: ");
        return -rc;
    }

    return 0;
}

/**
 * Convenience wrapper for nvme_tcp_sendv()
 */
static coroutine_mixed_fn int nvme_tcp_send(NvmeTcpQueue *q, const void *buf, size_t len, Error **errp)
{
    struct iovec iov = { .iov_base = (void *) buf, .iov_len = len};
    return nvme_tcp_sendv(q, &iov, 1, errp);
}

/**
 * Read from the completion queue of @q
 * Does NOT take @q->rlock, so this can be used to read pieces
 * of a cq entry one at a time (especially for parsing headers).
 * In a coroutine context, all calls of this associated with one sq entry
 * MUST be between a lock and unlock of @q->rlock
 */
static coroutine_mixed_fn int nvme_tcp_recv(NvmeTcpQueue *q, void *buf, size_t len, Error **errp) {
    ERRP_GUARD();
    int rc;

    rc = qio_channel_read_all(QIO_CHANNEL(q->sioc), buf, len, errp);
    if (rc) {
        error_prepend(errp, "Recv error: ");
    }

    return rc;
}

/**
 * Set up NVMe/TCP transport association for @q.
 * Partially initialize @q, set up TCP-connection,
 * send and receive ICReq, ICResp.
 */
static int nvme_tcp_queue_transport_connect(BDRVNVMeTCPState *s, NvmeTcpQueue *q, uint16_t qid, Error **errp)
{
    ERRP_GUARD();
    int rc;

    // TODO: keep alive timer config? -> higher than kato
    q->sioc = qio_channel_socket_new();
    q->qid = qid;

    rc = qio_channel_socket_connect_sync(q->sioc, &s->tgtsock, errp);
    if (rc) {
        error_prepend(errp, "Could not establish TCP connection with target: ");
        return rc;
    }

    NvmeTcpHdr req_hdr = {
        .type = NVME_TCP_PDUTYPE_ICREQ,
        .hlen = NVME_TCP_HLEN_ICREQ,
        .plen = 0x80,
    };
    NvmeTcpIcreqPdu icreq = {
        .hdr = req_hdr,
        .hpda = NVME_TCP_HOST_DATA_ALIGNMENT,
        .maxr2t = cpu_to_le32(NVME_TCP_MAX_R2T),
    };

    rc = nvme_tcp_send(q, &icreq, sizeof(icreq), errp);
    if (rc) {
        error_prepend(errp, "Failed sending icreq: ");
        return rc;
    }
    rc = qio_channel_flush(QIO_CHANNEL(q->sioc), errp);
    if (rc) {
        return rc;
    }

    NvmeTcpIcrespPdu icresp;
    rc = nvme_tcp_recv(q, &icresp, sizeof(icresp), errp);
    if (rc) {
        error_prepend(errp, "Failed receiving icresp: ");
        return rc;
    }

    /**
     * TODO: should probably assert some icresp fields
     * (and check the following are within bounds)
     */
    q->controller_alignment_bytes = (icresp.cpda + 1) * 4;
    q->maxh2cdata = le32_to_cpu(icresp.maxdata);

    trace_nvmf_tcp_transport_connect(NVME_TCP_HOST_DATA_ALIGNMENT_BYTES, q->controller_alignment_bytes, q->maxh2cdata);

    /*
     * - admin queue is set blocking, as performance isn't very relevant during
     *   set-up and keep alive
     * - first io queue (the one of the main io thread) also set to blocking for
     *   now because the first read (probing) doesn't re-enter after yielding
     *   as long as there are more io threads this doesn't impact performance,
     *   as the only thing this queue does later is flushing
     *   TODO: change this later on if it is the only io queue of the only io thread
     */
    qio_channel_set_blocking(QIO_CHANNEL(q->sioc), qid <= 1, errp);
    qio_channel_set_follow_coroutine_ctx(QIO_CHANNEL(q->sioc), true);

    return 0;
}

// TOOD:
static inline coroutine_mixed_fn uint16_t nvme_tcp_queue_size(NvmeTcpQueue *q)
{
    return q->next_cid - q->rctxrbuf_tail_cid;
}

/**
 * Submits a command to the submission queue of @q
 * Optional @data @data_niov carry in-capsule data.
 * @flush MUST be true for admin/setup commands and false for i/o.
 * Coroutine-safe, takes @q->wlock
 */
static coroutine_mixed_fn int nvme_tcp_submit_commandv(NvmeTcpQueue *q, NvmeCmd *cmd, const struct iovec *data, const size_t data_niov, size_t data_len, bool flush, Error **errp)
{
    ERRP_GUARD();
    g_autofree struct iovec *iov;
    size_t niov;
    NvmeTcpHdr hdr = {
        .type = NVME_TCP_PDUTYPE_CAPSULE_CMD,
        .hlen = NVME_TCP_HLEN_CAPSULE_CMD,
    };
    size_t pad_len;
    int rc;

    if (data) {
        assert(cmd->dptr.sgl.type == NVME_TCP_SGL_TYPE_DATA_BLOCK);
        pad_len = nvme_tcp_calculate_padding(hdr.hlen, q->controller_alignment_bytes);
        assert(pad_len == 0); // not yet supported
        hdr.pdo = sizeof(hdr) + sizeof(NvmeCmd) + pad_len;
        hdr.plen = hdr.pdo + data_len; // note: this differs if a digest is used

        niov = data_niov + 2;
    } else {
        pad_len = 0;
        hdr.pdo = 0;
        hdr.plen = hdr.hlen;

        niov = 2;
    }
    iov = g_new(struct iovec, niov);

    iov[0].iov_base = &hdr;
    iov[0].iov_len = sizeof(hdr);


    iov[1].iov_base = cmd;
    iov[1].iov_len = sizeof(NvmeCmd);

    // TODO: optimize to memcpy
    for (unsigned i = 0; i < data_niov; i++) {
        iov[2 + i].iov_base = data[i].iov_base;
        iov[2 + i].iov_len = data[i].iov_len;
    }

    // FIXME
    // we're never re-entering if we yield here i think
    // while (qemu_in_coroutine() && nvme_tcp_queue_size(queue) > queue->sqsize - 1) {
    //     qemu_coroutine_yield();
    // }

    cmd->cid = cpu_to_le16(q->next_cid++);
    trace_nvmf_tcp_submit_command(q->qid, cmd->opcode, cmd->cid, data_len, pad_len);

    rc = nvme_tcp_sendv(q, iov, niov, errp);
    if (rc) {
        error_prepend(errp, "Submitting %s command (opcode 0x%02x) failed: ", q->qid == 0 ? "admin" : "io", cmd->opcode);
        return rc;
    }

    if (flush) {
        rc = qio_channel_flush(QIO_CHANNEL(q->sioc), errp);
        if (rc) {
            return rc;
        }
    }

    return 0;
}

/**
 * Convenience wrapper of nvme_tcp_submit_commandv()
 */
static inline int coroutine_mixed_fn nvme_tcp_submit_command(NvmeTcpQueue *queue, NvmeCmd *cmd, void *data, size_t data_len, bool flush, Error **errp)
{
    if (data) {
        struct iovec iov = { .iov_base = data, .iov_len = data_len };
        return nvme_tcp_submit_commandv(queue, cmd, &iov, 1, data_len, flush, errp);
    } else {
        return nvme_tcp_submit_commandv(queue, cmd, NULL, 0, 0, flush, errp);
    }
}

// TODO:
// here (and in await_data) we also may have to reconnect
// this will be more complicated, as we have to do the handshake and then receive the expected thingy
// they may come out of order, so we absolutely should restructure the entire receiving process
// to sort packets into the appropriate handlers based on header type and cid
// (luckily traffic remains separated by queues per definition, so it's enough to "register"
// expected packets within a queue)
// see chapter 9.6 in the base spec!!!!!!
static int nvme_tcp_await_completion(NvmeTcpQueue *q, NvmfCompletion *completion, Error **errp)
{
    ERRP_GUARD();
    NvmeTcpHdr hdr;
    int rc = 0;

    rc = nvme_tcp_recv(q, &hdr, sizeof(hdr), errp);
    if (rc) {
        error_prepend(errp, "Failed recv hdr for cqe: ");
        return rc;
    }
    if (hdr.type != NVME_TCP_PDUTYPE_CAPSULE_RESP) {
        error_setg(errp, "Recv wrong hdr type (0x%02x instead of 0x%02x)", hdr.type, NVME_TCP_PDUTYPE_CAPSULE_RESP);
        return -EIO;
    }

    rc = nvme_tcp_recv(q, completion, sizeof(NvmfCompletion), errp);
    if (rc) {
        error_prepend(errp, "Failed to recv cqe: ");
        return rc;
    }

    // FIXME: this doesn't init *errp, segfault
    return nvmf_translate_error(completion, trace_nvmf_tcp_error);
}

/**
 * Helper function for setup commands where blocking is desired
 */
static int nvme_tcp_submit_command_and_await_completion(NvmeTcpQueue *queue, NvmeCmd *cmd, void *data, size_t data_len, NvmfCompletion *completion, Error **errp)
{
    int rc;

    rc = nvme_tcp_submit_command(queue, cmd, data, data_len, true, errp);
    if (rc) {
        return rc;
    }

    rc = nvme_tcp_await_completion(queue, completion, errp);
    if (rc) {
        return rc;
    }
    if (completion->cid != cmd->cid) {
        error_setg(errp, "Received reply to wrong command!");
        rc = -EIO;
    }

    return rc;
}

static int __nvme_tcp_await_datav(NvmeTcpQueue *queue, struct iovec *iov, size_t niov, size_t len, uint16_t cid, Error **errp)
{
    ERRP_GUARD();
    int rc;

    NvmeTcpDataPdu data_pdu;
    rc = nvme_tcp_recv(queue, &data_pdu, sizeof(data_pdu), errp);
    if (rc != 0) {
        error_prepend(errp, "Failed to recv data pdu: ");
        return rc;
    }
    if (data_pdu.hdr.type != NVME_TCP_PDUTYPE_C2HDATA) {
        error_setg(errp, "Received header type %d instead of %d!", data_pdu.hdr.type, NVME_TCP_PDUTYPE_C2HDATA);
        return -EIO; // TODO
    }
    if (data_pdu.hdr.hlen != data_pdu.hdr.pdo) {
        // TODO
        error_setg(errp, "Received padding or digest, unsupported.");
        return -ENOTSUP; // TODO
        }
    if (le32_to_cpu(data_pdu.datal) != len) {
        error_setg(errp, "Hdr length field %d instead of %ld!", data_pdu.datal, len);
        return -EIO; // TODO
    }
    if (le32_to_cpu(data_pdu.datao) != 0) {
        // TODO
        error_setg(errp, "Received data with offset, unsupported.");
        return -ENOTSUP; // TODO
    }
    if (data_pdu.hdr.flags != 0x0c) {
        // TODO
        error_setg(errp, "Received data with unsupported flags.");
        return -ENOTSUP; // TODO
    }
    if (le16_to_cpu(data_pdu.cid) != cid) {
        error_setg(errp, "Received data for wrong command (0x%04x instead of 0x%04x)", data_pdu.cid, cid);
        return -EIO;
    }

    rc = qio_channel_readv_all(QIO_CHANNEL(queue->sioc), iov, niov, errp);
    if (rc) {
        error_prepend(errp, "Failed to recv data: ");
        return rc;
    }

    trace_nvmf_tcp_recv_data(len);

    return 0;
}

static inline int nvme_tcp_await_data(NvmeTcpQueue *queue, void *buf, size_t len, uint16_t cid, Error **errp)
{
    struct iovec iov = {.iov_base = buf, .iov_len = len};
    return __nvme_tcp_await_datav(queue, &iov, 1, len, cid, errp);
}

/**
 * Helper function for setup commands where blocking is desired
 */
static int nvme_tcp_submit_command_and_await_data(NvmeTcpQueue *q, NvmeCmd *cmd, void *recvbuf, size_t recvlen, Error **errp)
{
    ERRP_GUARD();
    int rc;

    rc = nvme_tcp_submit_command(q, cmd, NULL, 0, true, errp);
    if (rc) {
        error_prepend(errp, "Failed to submit cmd: ");
        return rc;
    }
    rc = nvme_tcp_await_data(q, recvbuf, recvlen, le16_to_cpu(cmd->cid), errp);
    if (rc) {
        error_prepend(errp, "Failed to recv data: ");
        return rc;
    }

    return 0;
}

/**
 * Call this after nvme_tcp_transport_connect() to fully establish a queue pair
 * Pass @cntlid 0xffff for establishing the admin queue.
 * Sets @s->cntlid on setup of the admin queue.
 */
static int nvme_tcp_queue_connect(BDRVNVMeTCPState *s, NvmeTcpQueue *q, uint16_t cntlid, Error **errp)
{
    ERRP_GUARD();
    NvmeSglDescriptor sgl = {
        .type = NVME_TCP_SGL_TYPE_DATA_BLOCK,
        .len = cpu_to_le32(1024),
    };
    NvmfConnectCommand cmd = {
        .opcode = NVME_ADM_CMD_FABRICS,
        .flags = 0x40,
        .fctype = NVME_FCTYPE_CONNECT,
        .dptr.sgl = sgl,
        .qid = cpu_to_le16(q->qid),
        .sqsize = cpu_to_le16(31), // TODO what is this
        .recfmt = 0, // TODO what is this
        .cattr = 0x00, // TODO what is this
        .kato = cpu_to_le32(NVME_TCP_KATO),
    };
    NvmfConnectData data = {
        .hostid = s->hostid, // TODO: may not convey the right uuid bc of endianness
        .cntlid = cpu_to_le16(cntlid),
    };
    NvmfCompletion completion;
    int rc;

    assert(q->sioc);

    pstrcpy(data.subsysnqn, 256, s->subsysnqn);
    snprintf(data.hostnqn, 256, "nqn.2014-08.org.nvmexpress:uuid:");
    qemu_uuid_unparse(&s->hostid, data.hostnqn + strlen("nqn.2014-08.org.nvmexpress:uuid:"));

    rc = nvme_tcp_submit_command_and_await_completion(q, (NvmeCmd *) &cmd, &data, sizeof(NvmfConnectData), &completion, errp);
    if (rc) {
        error_prepend(errp, "Could not create queue %d! ", q->qid);
        return rc;
    }
    /* save cntlid on first connect (admin queue) */
    if (cntlid == 0xffff && q->qid == 0) {
        s->cntlid = le16_to_cpu(completion.result.u16);
    }

    trace_nvmf_tcp_queue_created(q->qid);

    return rc;
}

/**
 * Get uint32_t property from controller
 */
static int nvme_tcp_property_get32(NvmeTcpQueue *q, uint32_t offset, uint32_t *result, Error **errp)
{
    NvmfPropertyGetCmd cmd = {
        .opcode = NVME_ADM_CMD_FABRICS,
        .resv1 = 0x00,
        .fctype = NVME_FCTYPE_PROPERTY_GET,
        .attrib = 0x00, /* 4 byte result */
        .offset = cpu_to_le32(offset),
    };
    NvmfCompletion completion;

    int rc = nvme_tcp_submit_command_and_await_completion(q, (NvmeCmd *) &cmd, NULL, 0, &completion, errp);
    *result = le32_to_cpu(completion.result.u32);

    return rc;
}

/**
 * Get uint64_t property from controller
 */
static int nvme_tcp_property_get64(NvmeTcpQueue *q, uint32_t offset, uint64_t *result, Error **errp)
{
    NvmfPropertyGetCmd cmd = {
        .opcode = NVME_ADM_CMD_FABRICS,
        .resv1 = 0x00,
        .fctype = NVME_FCTYPE_PROPERTY_GET,
        .attrib = 0x01, /* 8 byte result */
        .offset = cpu_to_le32(offset),
    };
    NvmfCompletion completion;

    int rc = nvme_tcp_submit_command_and_await_completion(q, (NvmeCmd *) &cmd, NULL, 0, &completion, errp);
    *result = le64_to_cpu(completion.result.u64);

    return rc;
}

/**
 * Set uint32_t property on controller
 */
static int nvme_tcp_property_set32(NvmeTcpQueue *q, uint32_t offset, uint32_t value, Error **errp)
{
    NvmfPropertySetCmd cmd = {
        .opcode = NVME_ADM_CMD_FABRICS,
        .resv1 = 0x00,
        .fctype = NVME_FCTYPE_PROPERTY_SET,
        .attrib = 0x00, /* 4 bytes value */
        .offset = cpu_to_le32(offset),
        .value = cpu_to_le32(value),
    };
    NvmfCompletion completion;

    return nvme_tcp_submit_command_and_await_completion(q, (NvmeCmd *) &cmd, NULL, 0, &completion, errp);
}

/**
 * Callback for keep alive timer
 */
static void nvme_tcp_ka_cb(void *opaque)
{
    BDRVNVMeTCPState *s = opaque;
    Error *err = NULL;
    NvmeCmd cmd = {
        .opcode = 0x18,
    };
    NvmfCompletion cqe;
    int rc;

    // theoretically, we should lock this, tho the admin queue isn't used for anything other than setup in the current state
    // and we'd need a different lock type
    rc = nvme_tcp_submit_command_and_await_completion(s->admin_queue, &cmd, NULL, 0, &cqe, &err);
    if (rc) {
        error_propagate_prepend(&error_abort, err, "Keep-alive cmd failed: ");
    }
    timer_mod(s->ka_timer, qemu_clock_get_ms(QEMU_CLOCK_REALTIME) + NVME_TCP_KATO/2);
}

/**
 * Setup phase executed in nvme_tcp_open()
 * Gets certain properties from controller to initialize @s
 * and configures controller
 */
static int nvme_tcp_setup_configuration(BDRVNVMeTCPState *s, Error **errp)
{
    uint64_t cap;
    uint32_t cc = 0;
    uint32_t cc1;
    uint32_t status;
    uint32_t version;
    int rc;

    /*
     * controller capabilities
     * offset 0x00
     */
    rc = nvme_tcp_property_get64(s->admin_queue, 0, &cap, errp);
    if (rc != 0) {
        error_prepend(errp, "Failed to get cap! ");
        return rc;
    }
    s->page_size = 1u << (12 + NVME_CAP_MPSMIN(cap));

    /*
     * controller config
     * offset 0x14
     */
    NVME_SET_CC_MPS(cc, NVME_CAP_MPSMIN(cap));
    NVME_SET_CC_IOSQES(cc, 6); /* submission queue entry size 64bytes */
    NVME_SET_CC_IOCQES(cc, 4); /* completion queue entry size 16bytes */
    NVME_SET_CC_EN(cc, 1);     /* enable controller */
    rc = nvme_tcp_property_set32(s->admin_queue, 0x14, cc, errp);
    if (rc != 0) {
        error_prepend(errp, "Failed to set cc! ");
        return rc;
    }
    rc = nvme_tcp_property_get32(s->admin_queue, 0x14, &cc1, errp);
    if (rc != 0) {
        error_prepend(errp, "Failed to get cc! ");
        return rc;
    }
    if (cc != cc1) {
        error_setg(errp, "Controller configuration not set correctly!");
        return -EIO;
    }

    /*
     * controller status
     * offset 0x1c
     */
    rc = nvme_tcp_property_get32(s->admin_queue, 0x1c, &status, errp);
    if (rc != 0) {
        error_prepend(errp, "Failed to get status! ");
        return rc;
    }
    if ((status & 0x1) != 0x1) {
        error_setg(errp, "Controller not ready!");
        return -EIO;
    }

    /*
     * version
     * offset 0x08
     */
    rc = nvme_tcp_property_get32(s->admin_queue, 0x08, &version, errp);
    if (rc != 0) {
        error_prepend(errp, "Failed to get version! ");
        return rc;
    }
    trace_nvmf_tcp_version(version >> 16, (version >> 8) & 0xff, version & 0xff);

    return 0;
}

/**
 * Setup phase executed in nvme_tcp_open()
 * Gets certain properties from controller to initialize @s
 */
static int nvme_tcp_setup_identify(BDRVNVMeTCPState *s, Error **errp)
{
    ERRP_GUARD();
    NvmeSglDescriptor sgl = {
        .type = NVME_TCP_SGL_TYPE_DATA_BUFFER,
        .len = cpu_to_le32(sizeof(NvmeIdCtrl)),
    };
    NvmfIdentify cmd = {
        .opcode = NVME_ADM_CMD_IDENTIFY,
        .flags = 0x40, /* use of SGL for reply */
        .dptr.sgl = sgl,
        .cns = 0x1, /* identify controller */
    };
    union {
        NvmeIdCtrl ctrl;
        NvmeIdNs ns;
        NvmeIdCtrlNvm nvmcs;
    } id;
    uint16_t oncs;
    bool nvmwzsv;
    bool nvmdsmsv;
    NvmeLBAF *lbaf;
    int rc;

    /*
     * identify controller
     * CNS = 0x01
     */
    rc = nvme_tcp_submit_command_and_await_data(s->admin_queue, (NvmeCmd *) &cmd, &id.ctrl, sizeof(id.ctrl), errp);
    if (rc) {
        error_prepend(errp, "Failed to identify controller: ");
        return rc;
    }
    // TODO: copy more of these from nvme.c
    s->write_cache_supported = !!(le32_to_cpu(id.ctrl.vwc) & 0x1);
    s->max_transfer = (id.ctrl.mdts ? 1 << id.ctrl.mdts : 0) * s->page_size;
    s->ioccsz = le32_to_cpu(id.ctrl.ioccsz) * 16;
    oncs = le16_to_cpu(id.ctrl.oncs);
    nvmwzsv = !!(oncs & NVME_ONCS_WRITE_ZEROES);
    nvmdsmsv = !!(oncs & NVME_ONCS_DSM);
    s->sqsize = le16_to_cpu(id.ctrl.maxcmd);

    /*
     * identify namespace
     * CNS = 0x00
     */
    cmd.cns = 0x0;
    cmd.nsid = cpu_to_le32(s->nsid);
    rc = nvme_tcp_submit_command_and_await_data(s->admin_queue, (NvmeCmd *) &cmd, &id.ns, sizeof(id.ns), errp);
    if (rc) {
        error_prepend(errp, "Failed to identify ns: ");
        return rc;
    }
    s->nsze = le64_to_cpu(id.ns.nsze);
    lbaf = &id.ns.lbaf[NVME_ID_NS_FLBAS_INDEX(id.ns.flbas)];
    s->blkshift = lbaf->ds;

    /*
     * identify controller NVM command set
     * CNS = 0x06, CNI = 0x00
     */
    cmd.cns = 0x6;
    cmd.csi = 0x0;
    rc = nvme_tcp_submit_command_and_await_data(s->admin_queue, (NvmeCmd *) &cmd, &id.nvmcs, sizeof(id.nvmcs), errp);
    if (rc) {
        error_prepend(errp, "Failed to identify controller command set: ");
        return rc;
    }
    if (!nvmwzsv) {
        if (!id.nvmcs.wzsl) {
            s->supports_write_zeroes = false;
        } else {
            s->supports_write_zeroes = true;
            s->max_write_zeroes = (1U << id.nvmcs.wzsl) * s->page_size;
        }
    } else {
        /* technically, the limit still applies, but only for performance */
        s->supports_write_zeroes = true;
        s->max_write_zeroes = INT64_MAX;
    }
    if (!nvmdsmsv) {
        if (!id.nvmcs.dmrl && !id.nvmcs.dmrsl && !id.nvmcs.dmsl) {
            s->supports_discard = false;
        } else {
            assert(id.nvmcs.dmrl && id.nvmcs.dmrsl && id.nvmcs.dmsl);
            s->supports_discard = true;
            s->dmrl = id.nvmcs.dmrl;
            s->dmrsl = le32_to_cpu(id.nvmcs.dmrsl);
            s->dmsl = le64_to_cpu(id.nvmcs.dmsl);
        }
    } else {
        /* technically, the limit still applies, but only for performance */
        s->supports_discard = true;
        s->dmrl = INT8_MAX;
        s->dmrsl = INT32_MAX;
        s->dmsl = INT64_MAX;
    }

    return 0;
}

/**
 * Setup phase executed in nvme_tcp_open()
 * Allocates io queues with the controller, initializes them in @s
 * and performs protocol handshakes to set them up
 */
static int nvme_tcp_setup_create_ioqueues(BDRVNVMeTCPState *s, Error **errp)
{
    ERRP_GUARD();
    NvmeCmd cmd = {
        .opcode = NVME_ADM_CMD_SET_FEATURES,
        .cdw10 = cpu_to_le32(0x7),
        .cdw11 = (cpu_to_le16(s->num_io_threads) << 16) /* 0-based + main iothread*/
               | (cpu_to_le16(s->num_io_threads) & 0xffff), // TODO
    };
    NvmfCompletion completion;
    unsigned num_io_queues_allocated;
    int rc;

    rc = nvme_tcp_submit_command_and_await_completion(s->admin_queue, &cmd, NULL, 0, &completion, errp);
    if (rc) {
        error_prepend(errp, "Failed to allocate io queues with controller: ");
        return rc;
    }

    num_io_queues_allocated = le16_to_cpu(completion.result.u32 & 0xffff);
    if (s->num_io_threads + 1 > num_io_queues_allocated) {
        error_setg(errp, "Controller only allows %u IO-Queues", num_io_queues_allocated);
        error_append_hint(errp, "%u IO-Queues were requested: %u IOThreads + 1 main IO-thread", s->num_io_threads + 1, s->num_io_threads);
        return -EINVAL;
    }
    s->max_num_io_queues = s->num_io_threads + 1;

    s->io_queues = g_new0(NvmeTcpQueue *, s->max_num_io_queues);
    for (size_t i = 0; i < s->max_num_io_queues; i++) {
        s->io_queues[i] = g_new0(NvmeTcpQueue, 1);
        s->io_queues[i]->sqsize = s->sqsize;
        s->io_queues[i]->next_cid = 0;
        rc = nvme_tcp_queue_transport_connect(s, s->io_queues[i], i + 1, errp);
        if (rc) {
            return rc;
        }
        rc = nvme_tcp_queue_connect(s, s->io_queues[i], s->cntlid, errp);
        if (rc) {
            return rc;
        }
        qemu_co_mutex_init(&s->io_queues[i]->wlock);
        qemu_co_mutex_init(&s->io_queues[i]->rlock);
    }

    return 0;
}

static int nvme_tcp_enable_disable_write_cache(BDRVNVMeTCPState *s,
    bool enable, Error **errp)
{
    ERRP_GUARD();
    NvmeCmd cmd = {
        .opcode = NVME_ADM_CMD_SET_FEATURES,
        .cdw10 = cpu_to_le32(0x6),
        .cdw11 = cpu_to_le32(enable ? 0x1 : 0x0),
    };
    NvmfCompletion completion;
    int rc;

    rc = nvme_tcp_submit_command_and_await_completion(s->admin_queue, &cmd, NULL, 0, &completion, errp);
    if (rc) {
        error_prepend(errp, "Failed to %sable write cache: ", enable ? "en" : "dis");
        return rc;
    }

    return 0;
}

/**
 * Exists to increase legibility of nvme_tcp_open()
 */
static int __nvme_tcp_open(BlockDriverState *bs, Error **errp)
{
    ERRP_GUARD();
    BDRVNVMeTCPState *s = bs->opaque;
    int rc;

    /* for admin queues, cntlid and qid are fixed at 0xffff and 0 */
    s->admin_queue = g_new0(NvmeTcpQueue, 1);
    rc = nvme_tcp_queue_transport_connect(s, s->admin_queue, 0, errp);
    if (rc != 0) {
        return rc;
    }
    rc = nvme_tcp_queue_connect(s, s->admin_queue, 0xffff, errp);
    if (rc != 0) {
        return rc;
    }
    qemu_co_mutex_init(&s->admin_queue->wlock);
    qemu_co_mutex_init(&s->admin_queue->rlock);

    s->ka_timer = timer_new_ms(QEMU_CLOCK_REALTIME, nvme_tcp_ka_cb, s);
    timer_mod(s->ka_timer, qemu_clock_get_ms(QEMU_CLOCK_REALTIME) + NVME_TCP_KATO/2);

    rc = nvme_tcp_setup_configuration(s, errp);
    if (rc) {
        error_prepend(errp, "Failed to setup configuration: ");
        return rc;
    }

    rc = nvme_tcp_setup_identify(s, errp);
    if (rc) {
        error_prepend(errp, "Failed to identify: ");
        return rc;
    }

    rc = nvme_tcp_setup_create_ioqueues(s, errp);
    if (rc) {
        error_prepend(errp, "Failed to create io queues: ");
        return rc;
    }

    trace_nvmf_tcp_setup_complete(s->page_size, 1U << s->blkshift);

    return 0;
}

/**
 * Part of BlockDriver definition.
 */
static void nvme_tcp_close(BlockDriverState *bs)
{
    BDRVNVMeTCPState *s = bs->opaque;
    Error *err = NULL;
    int rc;

    g_free(s->subsysnqn);

    if (s->admin_queue) {
        rc = qio_channel_shutdown(QIO_CHANNEL(s->admin_queue->sioc), QIO_CHANNEL_SHUTDOWN_BOTH, &err);
        if (rc) {
            error_propagate_prepend(&error_abort, err, "Failed to shutdown TCP connection: ");
            err = NULL;
        }
        g_free(s->admin_queue);
    }

    if (s->ka_timer) {
        timer_free(s->ka_timer);
    }

    if (s->io_queues) {
        for (unsigned i = 0; i < s->max_num_io_queues; i++) {
            rc = qio_channel_shutdown(QIO_CHANNEL(s->io_queues[i]->sioc), QIO_CHANNEL_SHUTDOWN_BOTH, &err);
            if (rc) {
                error_propagate_prepend(&error_abort, err, "Failed to shutdown TCP connection: ");
                err = NULL;
            }
            g_free(s->io_queues[i]);
        }
        g_free(s->io_queues);
    }
}

/**
 * Parse cli options for nvme_tcp_open()
 */
static BlockdevOptionsNvmeTcp *nvme_tcp_parse_options(QDict *options, Error **errp)
{
    BlockdevOptionsNvmeTcp *result;
    const QDictEntry *e;
    Visitor *v;

    /* Create the QAPI object */
    v = qobject_input_visitor_new_flat_confused(options, errp);
    if (!v) {
        return NULL;
    }

    visit_type_BlockdevOptionsNvmeTcp(v, NULL, &result, errp);
    visit_free(v);
    if (!result) {
        return NULL;
    }

    /* Remove the processed options from the QDict (the visitor processes
     * _all_ options in the QDict) */
    while ((e = qdict_first(options))) {
        qdict_del(options, e->key);
    }

    return result;
}

/**
 * Part of BlockDriver definition.
 */
static int nvme_tcp_open(BlockDriverState *bs, QDict *options, int flags,
    Error **errp)
{
    ERRP_GUARD();
    BDRVNVMeTCPState *s = bs->opaque;
    BlockdevOptionsNvmeTcp *opts;
    int rc;

    qemu_mutex_init(&s->thread_ioq_mapping_wlock);

    opts = nvme_tcp_parse_options(options, errp);
    if (!opts) {
        return -EINVAL;
    }
    s->tgtsock.type = SOCKET_ADDRESS_TYPE_INET;
    s->tgtsock.u.inet = *opts->tgtsock;
    s->subsysnqn = g_strdup(opts->subsysnqn);
    s->nsid = opts->has_nsid ? opts->nsid : 1;
    s->num_io_threads = opts->has_num_io_threads ? opts->num_io_threads : 0;

    /* in case setup succeeds only partially, see nvme_tcp_close() */
    s->admin_queue = NULL;
    s->ka_timer = NULL;
    s->io_queues = NULL;

    qemu_uuid_generate(&s->hostid);
    s->next_unused_io_q = 0;

    rc = __nvme_tcp_open(bs, errp);
    if (rc) {
        error_prepend(errp, "Failed to connect to NVMe drive: ");
        goto fail;
    }

    if (flags & BDRV_O_NOCACHE) {
        if (!s->write_cache_supported) {
            error_setg(errp,
                       "NVMe controller doesn't support write cache configuration");
            rc = -EINVAL;
        } else {
            rc = nvme_tcp_enable_disable_write_cache(s, !(flags & BDRV_O_NOCACHE),
                                                     errp);
        }
        if (rc) {
            goto fail;
        }
    }

    return 0;

fail:
    nvme_tcp_close(bs);
    return rc;
}

/**
 * Helper function used in nvme_tcp_get_io_queue_for_current_thread()
 */
static coroutine_fn NvmeTcpQueue *nvme_tcp_thread_ioq_mapping_get(BDRVNVMeTCPState *s)
{
    for (unsigned i = 0; i < s->next_unused_io_q; i++) {
        if (qemu_thread_is_self(&s->io_queues[i]->thread)) {
            return s->io_queues[i];
        }
    }

    return NULL;
}

/**
 * Call this from i/o coroutines to get NvmeTcpQueue
 * If thread has not yet been encountered previously, adds it to mapping,
 * so no previous registration is necessary.
 */
static coroutine_fn NvmeTcpQueue *nvme_tcp_get_io_queue_for_current_thread(BDRVNVMeTCPState *s)
{
    NvmeTcpQueue *q;
    Error *err;

    q = nvme_tcp_thread_ioq_mapping_get(s);

    if (!q) {
        if (s->next_unused_io_q >= s->max_num_io_queues) { /* full */
            error_setg(&err, "dict size reached max io queue count %u", s->max_num_io_queues);
            error_propagate(&error_abort, err);
            return NULL;
        }

        qemu_mutex_lock(&s->thread_ioq_mapping_wlock);
        q = nvme_tcp_thread_ioq_mapping_get(s); /* check again after locking */
        if (!q) {
            qemu_thread_get_self(&s->io_queues[s->next_unused_io_q++]->thread);
            q = nvme_tcp_thread_ioq_mapping_get(s);
            assert(q);
        }
        qemu_mutex_unlock(&s->thread_ioq_mapping_wlock);
    }

    return q;
}

/**
 * Get previously registered response context from the ring buffer.
 * Call from i/o coroutine to help appropriately handle a CQE for a given cid
 */
static coroutine_fn NvmeTcpResponseCtx *nvme_tcp_rctxrbuf_get(NvmeTcpQueue *q, uint16_t cid)
{
    uint16_t cid_off = cid - q->rctxrbuf_tail_cid; /* accurately handle cid wrap-around */
    NvmeTcpResponseCtx *entry = &q->rctxrbuf[(q->rctxrbuf_tail_idx + cid_off) % RCTXRBUF_SIZE];
    return entry;
}

/**
 * Register response context in ring buffer.
 * Call from i/o coroutine directly after submitting first entry
 * associated with @cid
 * Registered response contexts need to be deregistered later.
 */
static coroutine_fn void nvme_tcp_rctxrbuf_register(NvmeTcpQueue *q, uint16_t cid, NvmeTcpReadInfo *readinfo, NvmeTcpR2tInfo *r2tinfo, uint8_t expected_type)
{
    NvmeTcpResponseCtx *rctx = nvme_tcp_rctxrbuf_get(q, cid);
    rctx->exists = true;
    rctx->co = qemu_coroutine_self();
    if (readinfo) {
        assert(!r2tinfo);
        rctx->u.readinfo = readinfo;
    }
    if (r2tinfo) {
        assert(!readinfo);
        rctx->u.r2tinfo = r2tinfo;
    }
    rctx->missing_read_data = false;
    rctx->io_done = false;
    rctx->co_waiting = false;
    rctx->expected_type = expected_type;
}

/**
 * Refresh response context for handling additional CQEs.
 * Call this from i/o coroutine after submitting a further entry
 * associated with @cid
 */
static coroutine_fn void nvme_tcp_rctxrbuf_refresh(NvmeTcpQueue *q, uint16_t cid, uint8_t expected_type)
{
    NvmeTcpResponseCtx *rctx = nvme_tcp_rctxrbuf_get(q, cid);
    assert(rctx->exists);
    rctx->io_done = false;
    rctx->co_waiting = false;
    rctx->expected_type = expected_type;
}

/**
 * Deregister response context.
 * Call this from i/o coroutine after having handled the last CQE
 * associated with @cid
 */
static coroutine_fn void nvme_tcp_rctxrbuf_deregister(NvmeTcpQueue *q, uint16_t cid)
{
    NvmeTcpResponseCtx *rctx = nvme_tcp_rctxrbuf_get(q, cid);
    assert(rctx->exists);
    rctx->exists = false;
    while (q->rctxrbuf[q->rctxrbuf_tail_idx].exists == false) {
        q->rctxrbuf_tail_idx++;
        q->rctxrbuf_tail_cid++;
    }
}

/**
 * Receive and handle CQE associated with @our_cid
 * @our_cid needs to have a response context registered in the
 * ring buffer of @q before calling this
 * Automatically handles @q->rlock, reordering of CQEs, and coroutine yield
 * Writes relevant return information in associated response context
 */
static coroutine_fn int nvme_tcp_co_await_io_resp(NvmeTcpQueue *q, uint16_t our_cid, Error **errp)
{
    ERRP_GUARD();
    NvmfCompletion cqe;
    union {
        NvmeTcpDataPdu data;
        NvmeTcpR2tPdu r2t;
    } pdu;
    NvmeTcpResponseCtx *our_rctx = nvme_tcp_rctxrbuf_get(q, our_cid);
    NvmeTcpResponseCtx *their_rctx;
    QEMUIOVector slice;
    uint16_t their_cid;
    uint8_t received_type;
    int rc;

    WITH_QEMU_LOCK_GUARD(&q->rlock) {
        rc = nvme_tcp_recv(q, &pdu.data.hdr, sizeof(NvmeTcpHdr), errp);
        if (rc) {
            error_prepend(errp, "Failed to recv hdr: ");
            return rc;
        }
        received_type = pdu.data.hdr.type;

        switch (received_type) {
            case NVME_TCP_PDUTYPE_CAPSULE_RESP:
                rc = nvme_tcp_recv(q, &cqe, sizeof(cqe), errp);
                if (rc) {
                    error_prepend(errp, "Failed to recv cqe: ");
                    return rc;
                }
                if ((le16_to_cpu(cqe.status) >> 1) & 0xff) {
                    error_setg(errp, "Write/flush unsuccessful");
                    return -EIO;
                }
                their_cid = le16_to_cpu(cqe.cid);
                their_rctx = nvme_tcp_rctxrbuf_get(q, their_cid);
                break;

            case NVME_TCP_PDUTYPE_C2HDATA:
                rc = nvme_tcp_recv(q, ((uint8_t *) &pdu.data) + sizeof(NvmeTcpHdr), sizeof(pdu.data) - sizeof(NvmeTcpHdr), errp);
                if (rc) {
                    error_prepend(errp, "Failed to recv data pdu: ");
                    return rc;
                }
                if (!(pdu.data.hdr.flags & 0x08)) {
                    error_setg(errp, "Read unsuccessful");
                    return -EIO;
                }
                if (pdu.data.hdr.hlen != pdu.data.hdr.pdo) {
                    // TODO
                    error_setg(errp, "Received padding or digest, unsupported.");
                    return -EIO;
                }

                their_cid = le16_to_cpu(pdu.data.cid);
                their_rctx = nvme_tcp_rctxrbuf_get(q, their_cid);

                their_rctx->u.readinfo->last = !!(pdu.data.hdr.flags & 0x04);
                their_rctx->u.readinfo->bytes_received += le32_to_cpu(pdu.data.datal);

                qemu_iovec_init_slice(&slice, their_rctx->u.readinfo->qiov, le32_to_cpu(pdu.data.datao), le32_to_cpu(pdu.data.datal));

                rc = qio_channel_readv_all(QIO_CHANNEL(q->sioc), slice.iov, slice.niov, errp);
                if (rc) {
                    error_prepend(errp, "Failed to recv data: ");
                    return rc;
                }

                qemu_iovec_destroy(&slice);
                break;

            case NVME_TCP_PDUTYPE_R2T:
                rc = nvme_tcp_recv(q, ((uint8_t *) &pdu.r2t) + sizeof(NvmeTcpHdr), sizeof(pdu.r2t) - sizeof(NvmeTcpHdr), errp);
                if (rc) {
                    error_prepend(errp, "Failed to recv r2t pdu: ");
                    return rc;
                }

                their_cid = le16_to_cpu(pdu.r2t.cid);
                their_rctx = nvme_tcp_rctxrbuf_get(q, their_cid);

                their_rctx->u.r2tinfo->ttag = le16_to_cpu(pdu.r2t.ttag);
                their_rctx->u.r2tinfo->r2to = le32_to_cpu(pdu.r2t.r2to);
                their_rctx->u.r2tinfo->r2tl = le32_to_cpu(pdu.r2t.r2tl);
                break;

            default:
                abort(); // TODO
        }
    }

    if (their_rctx->expected_type != received_type) {
        error_setg(errp, "Received wrong io response type");
        return -EIO;
    }

    /* we received our own response, done */
    if (their_cid == our_cid) {
        return 0;
    }

    our_rctx->co_waiting = true;
    their_rctx->io_done = true;

    /* notify them that their i/o has been completed */
    if (their_rctx->co_waiting) {
        qemu_coroutine_enter(their_rctx->co);
    }

    /* our i/o has already been completed by a different coroutine, done */
    if (our_rctx->io_done) {
        return 0;
    }

    /* wait for our i/o to be completed by a different coroutine */
    qemu_coroutine_yield();
    assert(our_rctx->io_done);
    return 0;
}

/**
 * Helper function to create and send SQEs for various i/o commands
 */
static coroutine_fn int nvme_tcp_co_submit_rwcmd(uint8_t opcode, BDRVNVMeTCPState *s,
    NvmeTcpQueue *q, int64_t offset, int64_t bytes, QEMUIOVector *qiov,
    uint16_t *cid, Error **errp)
{
    bool capsule_data = opcode == NVME_CMD_WRITE && bytes <= s->ioccsz;
    NvmeSglDescriptor sgld = {
        .type = capsule_data ? NVME_TCP_SGL_TYPE_DATA_BLOCK : NVME_TCP_SGL_TYPE_DATA_BUFFER,
        .len = (opcode != NVME_CMD_WRITE_ZEROES) ? cpu_to_le32(bytes) : 0,
    };
    NvmeRwCmd cmd = {
        .opcode = opcode,
        .flags = 0x40,
        .nsid = cpu_to_le32(s->nsid),
        .dptr.sgl = sgld,
        .slba = cpu_to_le64(offset >> s->blkshift),
        .nlb = cpu_to_le16((bytes >> s->blkshift) - 1), /* 0-based */
    };
    int rc;

    assert(offset >= 0);
    assert(bytes >= 0);
    assert(QEMU_IS_ALIGNED(offset, 1ULL << s->blkshift));
    assert(QEMU_IS_ALIGNED(bytes, 1ULL << s->blkshift));

    rc = nvme_tcp_submit_commandv(
        q,
        (NvmeCmd *) &cmd,
        capsule_data ? qiov->iov : NULL,
        capsule_data ? qiov->niov : 0,
        capsule_data ? bytes : 0,
        false,
        errp);
    if (rc) {
        error_prepend(errp, "Failed to submit rw cmd: ");
        return rc;
    }

    *cid = le16_to_cpu(cmd.cid);
    return 0;
}

/**
 * Part of BlockDriver definition.
 */
static coroutine_fn int nvme_tcp_co_preadv(BlockDriverState *bs,
    int64_t offset, int64_t bytes, QEMUIOVector *qiov,
    BdrvRequestFlags flags)
{
    BDRVNVMeTCPState *s = bs->opaque;
    NvmeTcpQueue *q = nvme_tcp_get_io_queue_for_current_thread(s);
    Error *err = NULL;
    NvmeTcpReadInfo readinfo = {
        .qiov = qiov,
        .bytes_received = 0,
        .last = false,
    };
    uint16_t cid;
    int rc;

    rc = nvme_tcp_co_submit_rwcmd(NVME_CMD_READ, s, q, offset, bytes, qiov, &cid, &err);
    if (rc) {
        error_propagate(&error_abort, err);
        return rc;
    }

    nvme_tcp_rctxrbuf_register(q, cid, &readinfo, NULL, NVME_TCP_PDUTYPE_C2HDATA);

    while (!readinfo.last) {
        nvme_tcp_rctxrbuf_refresh(q, cid, NVME_TCP_PDUTYPE_C2HDATA);

        rc = nvme_tcp_co_await_io_resp(q, cid, &err);
        if (rc) {
            error_propagate_prepend(&error_abort, err, "Failed to recv io resp: ");
            return rc;
        }
    }
    if (readinfo.bytes_received != qiov->size) {
        error_setg(&err, "Received unexpected data length to read cmd");
        error_propagate(&error_abort, err);
    }

    nvme_tcp_rctxrbuf_deregister(q, cid);
    return 0;
}

/**
 * Part of BlockDriver definition.
 */
static coroutine_fn int nvme_tcp_co_pwritev(
    BlockDriverState *bs, int64_t offset, int64_t bytes, QEMUIOVector *qiov,
    BdrvRequestFlags flags)
{
    BDRVNVMeTCPState *s = bs->opaque;
    NvmeTcpQueue *q = nvme_tcp_get_io_queue_for_current_thread(s);
    Error *err = NULL;
    NvmeTcpR2tInfo r2tinfo;
    uint64_t bytes_sent = 0;
    bool capsule_data = bytes <= s->ioccsz;
    uint16_t cid;
    int rc;

    rc = nvme_tcp_co_submit_rwcmd(NVME_CMD_WRITE, s, q, offset, bytes, capsule_data ? qiov : NULL, &cid, &err);
    if (rc) {
        error_propagate(&error_abort, err);
        return rc;
    }

    nvme_tcp_rctxrbuf_register(q, cid, NULL, capsule_data ? NULL : &r2tinfo,
        capsule_data ? NVME_TCP_PDUTYPE_CAPSULE_RESP : NVME_TCP_PDUTYPE_R2T);
    rc = nvme_tcp_co_await_io_resp(q, cid, &err);
    if (rc) {
        error_propagate_prepend(&error_abort, err, "Failed to recv io resp: ");
        return rc;
    }

    if (!capsule_data) {
        NvmeTcpDataPdu data_pdu = {
            .hdr = {
                .type = NVME_TCP_PDUTYPE_H2CDATA,
                .hlen = NVME_TCP_HLEN_H2CDATA,
                .pdo = NVME_TCP_HLEN_H2CDATA,
            },
            .cid = cpu_to_le16(cid),
            .ttag = cpu_to_le16(r2tinfo.ttag),
        };
        QEMUIOVector h2cdatavec;
        uint32_t datal;
        bool last = false;

        while (bytes_sent < bytes) {
            while (r2tinfo.r2tl) {
                assert(r2tinfo.r2tl <= bytes - bytes_sent);
                datal = MIN(r2tinfo.r2tl, q->maxh2cdata);
                last = (bytes_sent + datal) >= bytes;

                data_pdu.hdr.flags = last ? 0x04 : 0;
                data_pdu.hdr.plen = cpu_to_le32(data_pdu.hdr.pdo + datal);
                data_pdu.datao = cpu_to_le32(bytes_sent);
                data_pdu.datal = cpu_to_le32(datal);

                qemu_iovec_init(&h2cdatavec, qiov->niov);
                qemu_iovec_add(&h2cdatavec, &data_pdu, sizeof(data_pdu));
                qemu_iovec_concat(&h2cdatavec, qiov, bytes_sent, datal);

                nvme_tcp_rctxrbuf_refresh(q, cid,
                    last ? NVME_TCP_PDUTYPE_CAPSULE_RESP : NVME_TCP_PDUTYPE_R2T);

                rc = nvme_tcp_sendv(q, h2cdatavec.iov, h2cdatavec.niov, &err);
                if (rc) {
                    error_propagate_prepend(&error_abort, err, "Failed to send h2cdata: ");
                    return rc;
                }

                bytes_sent += datal;
                r2tinfo.r2tl -= datal;
                qemu_iovec_destroy(&h2cdatavec);
            }

            rc = nvme_tcp_co_await_io_resp(q, cid, &err);
            if (rc) {
                error_propagate_prepend(&error_abort, err, "Failed to recv io resp: ");
                return rc;
            }
        }
    }

    nvme_tcp_rctxrbuf_deregister(q, cid);
    return 0;
}

/**
 * Part of BlockDriver definition.
 */
static coroutine_fn int nvme_tcp_co_pwrite_zeroes(BlockDriverState *bs,
    int64_t offset, int64_t bytes, BdrvRequestFlags flags)
{
    BDRVNVMeTCPState *s = bs->opaque;
    NvmeTcpQueue *q = nvme_tcp_get_io_queue_for_current_thread(s);
    Error *err = NULL;
    uint16_t cid;
    int rc;

    if (!s->supports_write_zeroes) {
        return -ENOTSUP;
    }
    if (!bytes) {
        return 0;
    }

    rc = nvme_tcp_co_submit_rwcmd(NVME_CMD_WRITE_ZEROES, s, q, offset, bytes, NULL, &cid, &err);
    if (rc) {
        error_propagate(&error_abort, err);
        return rc;
    }

    nvme_tcp_rctxrbuf_register(q, cid, NULL, NULL, NVME_TCP_PDUTYPE_CAPSULE_RESP);
    rc = nvme_tcp_co_await_io_resp(q, cid, &err);
    if (rc) {
        error_propagate_prepend(&error_abort, err, "Failed to recv io resp: ");
        return rc;
    }

    nvme_tcp_rctxrbuf_deregister(q, cid);
    return 0;
}

/**
 * Part of BlockDriver definition.
 */
static coroutine_fn int nvme_tcp_co_pdiscard(BlockDriverState *bs,
    int64_t offset, int64_t bytes)
{
    BDRVNVMeTCPState *s = bs->opaque;
    NvmeTcpQueue *q = nvme_tcp_get_io_queue_for_current_thread(s);
    Error *err = NULL;
    uint64_t slba = (offset >> s->blkshift);
    uint32_t nlb = (bytes >> s->blkshift);
    uint32_t nlb_round;
    uint8_t nr = nlb / s->dmrsl + ((nlb % s->dmrsl == 0) ? 0 : 1);
    // TODO: technically, this could surpass ioccsz
    //       to address this, make the data buffer send loop from
    //       co_pwrite a helper function, so we can call it here
    NvmeSglDescriptor sgl = {
        .type = NVME_TCP_SGL_TYPE_DATA_BLOCK,
        .len = cpu_to_le32(nr * sizeof(NvmeDsmRange)),
    };
    NvmeDsmCmd cmd = {
        .opcode = NVME_CMD_DSM,
        .nsid = cpu_to_le32(s->nsid),
        .dptr.sgl = sgl,
        .nr = cpu_to_le32(nr - 1), /* 0-based */
        .attributes = cpu_to_le32(1 << 2), /* deallocate */
    };
    g_autofree NvmeDsmRange *ranges = g_new0(NvmeDsmRange, nr);
    uint16_t cid;
    int rc;

    if (!s->supports_discard) {
        return -ENOTSUP;
    }
    if (!bytes) {
        return 0;
    }

    assert(offset >= 0);
    assert(bytes >= 0);
    assert(QEMU_IS_ALIGNED(offset, 1ULL << s->blkshift));
    assert(QEMU_IS_ALIGNED(bytes, 1ULL << s->blkshift));

    for (uint8_t i = 0; i < nr; i++) {
        nlb_round = MIN(nlb, s->dmrsl);
        ranges[i].slba = cpu_to_le64(slba);
        ranges[i].nlb = cpu_to_le32(nlb_round);

        slba += nlb_round;
        nlb -= nlb_round;
    }

    rc = nvme_tcp_submit_command(q, (NvmeCmd *) &cmd, ranges, nr * sizeof(NvmeDsmRange), false, &err);
    if (rc) {
        error_propagate_prepend(&error_abort, err, "Failed to submit discard cmd: ");
        return rc;
    }

    cid = le16_to_cpu(cmd.cid);
    nvme_tcp_rctxrbuf_register(q, cid, NULL, NULL, NVME_TCP_PDUTYPE_CAPSULE_RESP);
    rc = nvme_tcp_co_await_io_resp(q, cid, &err);
    if (rc) {
        error_propagate_prepend(&error_abort, err, "Failed to recv io resp: ");
        return rc;
    }

    nvme_tcp_rctxrbuf_deregister(q, cid);
    return 0;
}

/**
 * Helper function for nvme_tcp_co_flush()
 */
static coroutine_fn int __nvme_tcp_co_flush(BDRVNVMeTCPState *s, NvmeTcpQueue *q, BlockDriverState *bs, Error **errp)
{
    ERRP_GUARD();
    QEMU_LOCK_GUARD(&s->thread_ioq_mapping_wlock); /* no new queues during this */
    Error *err;
    NvmeCmd cmd = {
        .opcode = NVME_CMD_FLUSH,
        .nsid = cpu_to_le32(s->nsid),
    };
    uint16_t cid;
    unsigned i;
    int rc;

    for (i = 0; i < s->num_io_threads + 1; i++) {
        if (s->io_queues[i] == q) {
            continue;
        }

        rc = qio_channel_flush(QIO_CHANNEL(s->io_queues[i]->sioc), &err);
        if (rc) {
            error_prepend(errp, "Socket flush error: ");
            return rc;
        }
    }

    rc = nvme_tcp_submit_command(q, &cmd, NULL, 0, true, &err);
    if (rc) {
        error_prepend(errp, "Failed to submit NVMe flush command: ");
        return rc;
    }

    cid = le16_to_cpu(cmd.cid);
    nvme_tcp_rctxrbuf_register(q, cid, NULL, NULL, NVME_TCP_PDUTYPE_CAPSULE_RESP);
    rc = nvme_tcp_co_await_io_resp(q, cid, &err);
    if (rc) {
        error_prepend(errp, "No flush cmd cqe: ");
        return rc;
    }
    nvme_tcp_rctxrbuf_deregister(q, cid);

    return 0;
}

/**
 * Part of BlockDriver definition.
 */
static coroutine_fn int nvme_tcp_co_flush(BlockDriverState *bs)
{
    BDRVNVMeTCPState *s = bs->opaque;
    NvmeTcpQueue *q = nvme_tcp_get_io_queue_for_current_thread(s);
    Error *err;
    int rc;

    rc = __nvme_tcp_co_flush(s, q, bs, &err);
    if (rc) {
        error_propagate(&error_abort, err);
    }

    return rc;
}

/**
 * Part of BlockDriver definition.
 */
static void nvme_tcp_refresh_filename(BlockDriverState *bs)
{
    BDRVNVMeTCPState *s = bs->opaque;

    snprintf(bs->exact_filename, sizeof(bs->exact_filename), "nvme-tcp://%s:%s/%s",
             s->tgtsock.u.inet.host, s->tgtsock.u.inet.port, s->subsysnqn);
}

/**
 * Part of BlockDriver definition

 * Assumes that s->page_size >= (1U << s->blkshift)
 */
static void nvme_tcp_refresh_limits(BlockDriverState *bs, Error **errp)
{
    BDRVNVMeTCPState *s = bs->opaque;

    bs->bl.opt_mem_alignment = s->page_size;
    bs->bl.request_alignment = s->page_size;
    bs->bl.max_transfer = s->max_transfer;

    bs->bl.max_pwrite_zeroes = s->max_write_zeroes;
    bs->bl.pwrite_zeroes_alignment = s->page_size;

    bs->bl.max_pdiscard = MIN(s->dmrl * s->dmrsl, s->dmsl);
    bs->bl.pdiscard_alignment = bs->bl.request_alignment;
}

/**
 * Part of BlockDriver definition.
 */
static coroutine_fn int64_t nvme_tcp_co_getlength(BlockDriverState *bs)
{
    BDRVNVMeTCPState *s = bs->opaque;
    return s->nsze << s->blkshift;
}

/**
 * Part of BlockDriver definition
 *
 * QEMU won't let me set a different logical block size from 512 byte,
 * and SunBIOS doesn't like bigger block sizes either, so this is what we do.
 * Request alignment is at least 4096 byte anyway (NVMe page size).
 * Internally, we only use the "physical" block size.
 */
static int nvme_tcp_probe_blocksizes(BlockDriverState *bs, BlockSizes *bsz)
{
    BDRVNVMeTCPState *s = bs->opaque;
    assert(s->blkshift >= BDRV_SECTOR_BITS && s->blkshift <= 12);
    uint32_t blocksize = UINT32_C(1) << s->blkshift;
    bsz->phys = blocksize;
    bsz->log = 512;
    return 0;
}

/**
 * Part of BlockDriver definition.
 *
 * Does nothing, but is mandatory.
 */
static int nvme_tcp_reopen_prepare(BDRVReopenState *reopen_state,
    BlockReopenQueue *queue, Error **errp)
{
    return 0;
}

/**
 * Part of BlockDriver definition.
 *
 * Does nothing. (But does return success on non-exact shrinking)
 */
static coroutine_fn int nvme_tcp_co_truncate(BlockDriverState *bs, int64_t offset,
    bool exact, PreallocMode prealloc, BdrvRequestFlags flags, Error **errp)
{
    int64_t cur_length;

    if (prealloc != PREALLOC_MODE_OFF) {
        error_setg(errp, "Unsupported preallocation mode '%s'",
                   PreallocMode_str(prealloc));
        return -ENOTSUP;
    }

    cur_length = nvme_tcp_co_getlength(bs);
    if (offset != cur_length && exact) {
        error_setg(errp, "Cannot resize NVMe devices");
        return -ENOTSUP;
    } else if (offset > cur_length) {
        error_setg(errp, "Cannot grow NVMe devices");
        return -EINVAL;
    }

    return 0;
}

/**
 * Part of BlockDriver definition.
 *
 * Options that change drive data.
 */
static const char *const nvme_tcp_strong_runtime_opts[] = {
    NVME_TCP_BLOCK_OPT_IP,
    NVME_TCP_BLOCK_OPT_PORT,
    NVME_TCP_BLOCK_OPT_SUBSYSNQN,

    NULL
};

static BlockDriver bdrv_nvme_tcp = {
    .format_name              = "nvme-tcp",
    .protocol_name            = "nvme-tcp",
    .instance_size            = sizeof(BDRVNVMeTCPState),

    .bdrv_co_create_opts      = bdrv_co_create_opts_simple,
    .create_opts              = &bdrv_create_opts_simple,

    .bdrv_parse_filename      = nvme_tcp_parse_filename,
    .bdrv_open                = nvme_tcp_open,
    .bdrv_close               = nvme_tcp_close,
    .bdrv_co_getlength        = nvme_tcp_co_getlength,
    .bdrv_probe_blocksizes    = nvme_tcp_probe_blocksizes,
    .bdrv_co_truncate         = nvme_tcp_co_truncate,
    .bdrv_reopen_prepare      = nvme_tcp_reopen_prepare,

    .bdrv_co_preadv           = nvme_tcp_co_preadv,
    .bdrv_co_pwritev          = nvme_tcp_co_pwritev,
    .bdrv_co_pwrite_zeroes    = nvme_tcp_co_pwrite_zeroes,
    .bdrv_co_pdiscard         = nvme_tcp_co_pdiscard,

    .bdrv_co_flush_to_disk    = nvme_tcp_co_flush,

    .bdrv_refresh_filename    = nvme_tcp_refresh_filename,
    .bdrv_refresh_limits      = nvme_tcp_refresh_limits,
    .strong_runtime_opts      = nvme_tcp_strong_runtime_opts,
};

static void bdrv_nvme_tcp_init(void)
{
    bdrv_register(&bdrv_nvme_tcp);
}

block_init(bdrv_nvme_tcp_init);
