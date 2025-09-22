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
 * - everything indicated with // comments
 */

#define RCTXRBUF_SIZE 512

typedef struct NvmeTcpResponseCtx {
    QEMUIOVector *qiov;
    Coroutine *co;
    bool exists; /* to prevent having to allocate and delete this all the time */
    bool io_done;
    bool co_waiting;
} NvmeTcpResponseCtx;

typedef struct NvmeTcpQueue {
    QIOChannelSocket *sock;
    QemuThread thread;

    /*
     * as long as we don't yield in between releasing
     * the wlock and locking the rlock, we should still
     * be recieving the correct responses to our commands
     */
    CoMutex wlock;
    CoMutex rlock;

    NvmeTcpResponseCtx rctxrbuf[RCTXRBUF_SIZE];
    unsigned rctxrbuf_tail_idx;
    uint16_t rctxrbuf_tail_cid;

    uint16_t qid;
    uint16_t next_cid;

    unsigned sqsize;

    uint8_t controller_alignment_bytes;
    uint32_t maxh2cdata;
} NvmeTcpQueue;

typedef struct BDRVNVMeTCPState {
    // TODO: think about if we need global mutexes like in nvme.c

    NvmeTcpQueue *admin_queue;

    QemuMutex thread_ioq_mapping_wlock; /* reads should be disjoint enough to not need locking i think */
    NvmeTcpQueue **io_queues;
    unsigned next_unused_io_q;
    unsigned max_num_io_queues;

    QEMUTimer *ka_timer;

    uint16_t cntlid;
    bool write_cache_supported;
    size_t page_size;
    uint64_t max_transfer;
    int nsid;
    uint64_t nsze; /* Namespace size reported by identify command */
    int blkshift;

    /*
     * needed for refresh_filename()
     * and to reestablish connection if lost
     */
    QemuUUID hostid;
    SocketAddress tgtsock;
    char *subsysnqn;
    unsigned num_io_threads;
} BDRVNVMeTCPState;

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
#define NVME_TCP_MAX_R2T 0 // 7 for 8 r2t max TODO XXX

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
static int coroutine_mixed_fn nvme_tcp_sendv(NvmeTcpQueue *queue, const struct iovec *iov, size_t niov, size_t len, Error **errp)
{
    ERRP_GUARD();
    int rc;

    if (qemu_in_coroutine()) {
        qemu_co_mutex_lock(&queue->wlock);
    }
    rc = qio_channel_writev_all(QIO_CHANNEL(queue->sock), iov, niov, errp);
    if (qemu_in_coroutine()) {
        qemu_co_mutex_unlock(&queue->wlock);
    }
    if (rc) {
        error_prepend(errp, "Write error: ");
        return -rc;
    }

    return 0;
}

static int coroutine_mixed_fn nvme_tcp_send(NvmeTcpQueue *queue, const void *buf, size_t len, Error **errp)
{
    struct iovec iov = { .iov_base = (void *) buf, .iov_len = len};
    return nvme_tcp_sendv(queue, &iov, 1, len, errp);
}

static int coroutine_mixed_fn nvme_tcp_recv(NvmeTcpQueue *queue, void *buf, size_t len, Error **errp) {
    ERRP_GUARD();
    int rc = qio_channel_read_all(QIO_CHANNEL(queue->sock), buf, len, errp);

    if (rc) {
        error_prepend(errp, "Recv error: ");
    }

    return rc;
}

/**
 * Set up NVMe/TCP transport association for @queue.
 * Partially initialize @queue, set up TCP-connection,
 * send and receive icreq, icresp.
 */
static int nvme_tcp_queue_transport_connect(BDRVNVMeTCPState *s, NvmeTcpQueue *queue, uint16_t qid, Error **errp)
{
    ERRP_GUARD();
    int rc;

    // TODO: keep alive timer config? -> higher than kato
    queue->sock = qio_channel_socket_new();
    queue->qid = qid;

    rc = qio_channel_socket_connect_sync(queue->sock, &s->tgtsock, errp);
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

    rc = nvme_tcp_send(queue, &icreq, sizeof(icreq), errp);
    if (rc) {
        error_prepend(errp, "Failed sending icreq: ");
        return rc;
    }
    rc = qio_channel_flush(QIO_CHANNEL(queue->sock), errp);
    if (rc) {
        return rc;
    }

    NvmeTcpIcrespPdu icresp;
    rc = nvme_tcp_recv(queue, &icresp, sizeof(icresp), errp);
    if (rc) {
        error_prepend(errp, "Failed receiving icresp: ");
        return rc;
    }

    /**
     * TODO: should probably assert some icresp fields
     * (and check the following are within bounds)
     */
    queue->controller_alignment_bytes = (icresp.cpda + 1) * 4;
    queue->maxh2cdata = le32_to_cpu(icresp.maxdata);

    trace_nvmf_tcp_transport_connect(NVME_TCP_HOST_DATA_ALIGNMENT_BYTES, queue->controller_alignment_bytes, queue->maxh2cdata);

    /*
     * - admin queue is set blocking, as performance isn't very relevant during
     *   set-up and keep alive
     * - first io queue (the one of the main io thread) also set to blocking for
     *   now because the first read (probing) doesn't re-enter after yielding
     *   as long as there are more io threads this doesn't impact performance,
     *   as the only thing this queue does later is flushing
     *   TODO: change this later on if it is the only io queue of the only io thread
     */
    qio_channel_set_blocking(QIO_CHANNEL(queue->sock), qid <= 1, errp);
    qio_channel_set_follow_coroutine_ctx(QIO_CHANNEL(queue->sock), true);

    return 0;
}

static inline uint16_t coroutine_mixed_fn nvme_tcp_queue_size(NvmeTcpQueue *q)
{
    return q->next_cid - q->rctxrbuf_tail_cid;
}

static int coroutine_mixed_fn nvme_tcp_submit_commandv(NvmeTcpQueue *queue, NvmeCmd *cmd, const struct iovec *data, const size_t data_niov, size_t data_len, bool flush, Error **errp)
{
    ERRP_GUARD();
    g_autofree struct iovec *iov;
    size_t pad_len;
    size_t niov;
    int rc;

    NvmeTcpHdr hdr = {
        .type = NVME_TCP_PDUTYPE_CAPSULE_CMD,
        .hlen = NVME_TCP_HLEN_CAPSULE_CMD,
    };

    if (data) {
        pad_len = nvme_tcp_calculate_padding(hdr.hlen, queue->controller_alignment_bytes);
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
    iov = g_malloc(sizeof(struct iovec) * niov);

    iov[0].iov_base = &hdr;
    iov[0].iov_len = sizeof(hdr);

    iov[1].iov_base = cmd;
    iov[1].iov_len = sizeof(NvmeCmd);

    // TODO: optimize to memcpy
    for (unsigned i = 0; i < data_niov; i++) {
        iov[2 + i].iov_base = data[i].iov_base;
        iov[2 + i].iov_len = data[i].iov_len;
    }

    // TODO
    // what we absolutely need to do here is take queue->maxh2cdata into account
    // and probably split cmd and data and wait for r2t in between for bigger writes
    // (this requires a different SGL descriptor!!!)
    // should be enough to check if big, if no send normally, if yes, loop
    // wait for r2t, send, track bytes_sent

    // FIXME
    // we're never re-entering if we yield here i think
    // while (qemu_in_coroutine() && nvme_tcp_queue_size(queue) > queue->sqsize - 1) {
    //     qemu_coroutine_yield();
    // }

    cmd->cid = cpu_to_le16(queue->next_cid++);
    trace_nvmf_tcp_submit_command(queue->qid, cmd->opcode, cmd->cid, data_len, pad_len);

    rc = nvme_tcp_sendv(queue, iov, niov, sizeof(NvmeTcpHdr) + sizeof(NvmeCmd) + data_len, errp);
    if (rc) {
        error_prepend(errp, "Submitting %s command (opcode 0x%02x) failed: ", queue->qid == 0 ? "admin" : "io", cmd->opcode);
    }

    if (flush) {
        rc = qio_channel_flush(QIO_CHANNEL(queue->sock), errp);
        if (rc) {
            return rc;
        }
    }

    return rc;
}

static inline int coroutine_mixed_fn nvme_tcp_submit_command(NvmeTcpQueue *queue, NvmeCmd *cmd, const char *data, size_t data_len, bool flush, Error **errp)
{
    if (data) {
        struct iovec iov = { .iov_base = (char *) data, .iov_len = data_len };
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
static int coroutine_mixed_fn __nvme_tcp_await_completion(NvmeTcpQueue *queue, NvmfCompletion *completion, Error **errp)
{
    ERRP_GUARD();
    NvmeTcpHdr hdr;
    int rc = 0;

    rc = nvme_tcp_recv(queue, &hdr, sizeof(hdr), errp);
    if (rc) {
        error_prepend(errp, "Failed recv hdr for cqe: ");
        return rc;
    }
    if (hdr.type != NVME_TCP_PDUTYPE_CAPSULE_RESP) {
        error_setg(errp, "Recv wrong hdr type (0x%02x instead of 0x%02x)", hdr.type, NVME_TCP_PDUTYPE_CAPSULE_RESP);
        return -EIO;
    }

    rc = nvme_tcp_recv(queue, completion, sizeof(NvmfCompletion), errp);
    if (rc) {
        error_prepend(errp, "Failed to recv cqe: ");
        return rc;
    }

    // FIXME: this doesn't init *errp, segfault
    return nvmf_translate_error(completion, trace_nvmf_tcp_error);
}

static int nvme_tcp_await_completion(NvmeTcpQueue *queue, NvmfCompletion *completion, Error **errp)
{
    return __nvme_tcp_await_completion(queue, completion, errp);
}

static int nvme_tcp_submit_command_and_await_completion(NvmeTcpQueue *queue, NvmeCmd *cmd, const char *data, size_t data_len, bool flush, NvmfCompletion *completion, Error **errp)
{
    int rc;

    rc = nvme_tcp_submit_command(queue, cmd, data, data_len, flush, errp);
    if (rc) {
        return rc;
    }

    rc = nvme_tcp_await_completion(queue, completion, errp);
    if (rc) {
        return rc;
    }
    if (completion->command_id != cmd->cid) {
        error_setg(errp, "Received reply to wrong command!");
        rc = -EIO; // TODO: better error code
    }

    return rc;
}

static int coroutine_mixed_fn __nvme_tcp_await_datav(NvmeTcpQueue *queue, struct iovec *iov, size_t niov, size_t len, uint16_t cid, Error **errp)
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
    if (le32_to_cpu(data_pdu.data_length) != len) {
        error_setg(errp, "Hdr length field %d instead of %ld!", data_pdu.data_length, len);
        return -EIO; // TODO
    }
    if (le32_to_cpu(data_pdu.data_offset) != 0) {
        // TODO
        error_setg(errp, "Received data with offset, unsupported.");
        return -ENOTSUP; // TODO
    }
    if (data_pdu.hdr.flags != 0x0c) {
        // TODO
        error_setg(errp, "Received data with unsupported flags.");
        return -ENOTSUP; // TODO
    }
    if (le16_to_cpu(data_pdu.command_id) != cid) {
        error_setg(errp, "Received data for wrong command (0x%04x instead of 0x%04x)", data_pdu.command_id, cid);
        return -EIO;
    }

    rc = qio_channel_readv_all(QIO_CHANNEL(queue->sock), iov, niov, errp);
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

static int nvme_tcp_queue_connect(BDRVNVMeTCPState *s, NvmeTcpQueue *queue, uint16_t cntlid, Error **errp)
{
    ERRP_GUARD();
    assert(queue->sock);

    NvmfConnectCommand cmd = {0};
    NvmfConnectData data = {0};
    int rc;

    cmd.opcode = NVME_ADM_CMD_FABRICS;
    /*
     * Why 0x40? The standard says reserved. Well, I can't tell you either,
     * but when I wireshark the kernel driver this flag is set.
     */
    cmd.resv1 = 0x40; // 0x80 for SGL flag??
    cmd.fctype = NVME_FCTYPE_CONNECT;
    NvmeSglDescriptor sgl = {
        .type = NVME_TCP_SGL_TYPE_DATA_BLOCK,
        .len = cpu_to_le32(1024),
    };
    cmd.dptr.sgl = sgl;
    cmd.qid = cpu_to_le16(queue->qid);
    cmd.sqsize = cpu_to_le16(31);
    cmd.recfmt = 0;
    // TODO FIXME somehow the connect response still gives an SQHD
    // we might have to adhere to flow control anyway...
    cmd.cattr = 0x00; // 0x04 to disable flow control (DISSQFC), else 0x00
    cmd.kato = cpu_to_le32(NVME_TCP_KATO);

    data.hostid = s->hostid; // TODO: may not convey the right uuid bc of endianness
    data.cntlid = cntlid;

    pstrcpy(data.subsysnqn, 256, s->subsysnqn);
    snprintf(data.hostnqn, 256, "nqn.2014-08.org.nvmexpress:uuid:");
    qemu_uuid_unparse(&s->hostid, data.hostnqn + strlen("nqn.2014-08.org.nvmexpress:uuid:"));

    NvmfCompletion completion = {};
    rc = nvme_tcp_submit_command_and_await_completion(queue, (NvmeCmd *) &cmd, (const char *) &data, sizeof(NvmfConnectData), true, &completion, errp);
    if (rc != 0) {
        error_prepend(errp, "Could not create queue %d! ", queue->qid);
        return rc;
    }
    /* save cntlid on first connect (admin queue) */
    if (cntlid == 0xffff && queue->qid == 0) {
        s->cntlid = le16_to_cpu(completion.result.u16);
    }

    trace_nvmf_tcp_queue_created(queue->qid);

    return rc;
}

static int nvme_tcp_property_get32(NvmeTcpQueue *queue, uint32_t offset, uint32_t *result, Error **errp)
{
    NvmfPropertyGetCmd cmd = {
        .opcode = NVME_ADM_CMD_FABRICS,
        .resv1 = 0x00,
        .fctype = NVME_FCTYPE_PROPERTY_GET,
        .attrib = 0x00, /* 4 byte result */
        .offset = cpu_to_le32(offset),
    };
    NvmfCompletion completion;

    int rc = nvme_tcp_submit_command_and_await_completion(queue, (NvmeCmd *) &cmd, NULL, 0, true, &completion, errp);
    *result = le32_to_cpu(completion.result.u32);

    return rc;
}

static int nvme_tcp_property_get64(NvmeTcpQueue *queue, uint32_t offset, uint64_t *result, Error **errp)
{
    NvmfPropertyGetCmd cmd = {
        .opcode = NVME_ADM_CMD_FABRICS,
        .resv1 = 0x00,
        .fctype = NVME_FCTYPE_PROPERTY_GET,
        .attrib = 0x01, /* 8 byte result */
        .offset = cpu_to_le32(offset),
    };
    NvmfCompletion completion;

    int rc = nvme_tcp_submit_command_and_await_completion(queue, (NvmeCmd *) &cmd, NULL, 0, true, &completion, errp);
    *result = le64_to_cpu(completion.result.u64);

    return rc;
}

static int nvme_tcp_property_set32(NvmeTcpQueue *queue, uint32_t offset, uint32_t value, Error **errp)
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

    return nvme_tcp_submit_command_and_await_completion(queue, (NvmeCmd *) &cmd, NULL, 0, true, &completion, errp);
}

// static int nvme_tcp_property_set64(NvmfTcpQueue *queue, uint32_t offset, uint64_t value, Error **errp)
// {
//     NvmfPropertySetCmd cmd = {
//         .opcode = NVME_ADM_CMD_FABRICS,
//         .resv1 = 0x00,
//         .command_id = cpu_to_le16(queue->next_command_id++),
//         .fctype = NVME_FCTYPE_PROPERTY_SET,
//         .attrib = 0x01, /* 8 bytes value */
//         .offset = cpu_to_le32(offset),
//         .value = cpu_to_le64(value),
//     };
//     NvmfCompletion completion = {0};

//     return nvmf_tcp_submit_command_and_await_completion(queue, (NvmeCmd *) &cmd, NULL, 0, &completion, errp);
// }

static void nvme_tcp_ka_cb(void *opaque)
{
    BDRVNVMeTCPState *s = opaque;
    Error *err = NULL;
    int rc;

    NvmeCmd cmd = {
        .opcode = 0x18,
    };
    NvmfCompletion cqe;

    // theoretically, we should lock this, tho the admin queue isn't used for anything other than setup in the current state
    // and we'd need a different lock type
    rc = nvme_tcp_submit_command_and_await_completion(s->admin_queue, &cmd, NULL, 0, true, &cqe, &err);
    if (rc) {
        error_propagate_prepend(&error_abort, err, "Keep-alive cmd failed: ");
    }
    timer_mod(s->ka_timer, qemu_clock_get_ms(QEMU_CLOCK_REALTIME) + NVME_TCP_KATO/2);
}

/**
 * Exclusively exists to increase legibility of nvme_tcp_open()
 */
static int __nvme_tcp_open(BlockDriverState *bs, Error **errp)
{
    ERRP_GUARD();
    BDRVNVMeTCPState *s = bs->opaque;
    int rc;

    QemuUUID hostid;
    qemu_uuid_generate(&hostid);
    s->hostid = hostid;

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

    uint64_t cap;
    rc = nvme_tcp_property_get64(s->admin_queue, 0, &cap, errp);
    if (rc != 0) {
        error_prepend(errp, "Failed to get cap! ");
        return rc;
    }
    s->page_size = 1u << (12 + NVME_CAP_MPSMIN(cap));

    uint32_t cc = 0;
    NVME_SET_CC_MPS(cc, NVME_CAP_MPSMIN(cap));
    NVME_SET_CC_IOSQES(cc, 6); /* submission queue entry size 64bytes */
    NVME_SET_CC_IOCQES(cc, 4); /* completion queue entry size 16bytes */
    NVME_SET_CC_EN(cc, 1);     /* enable controller */
    rc = nvme_tcp_property_set32(s->admin_queue, 0x14, cc, errp);
    if (rc != 0) {
        error_prepend(errp, "Failed to set cc! ");
        return rc;
    }
    uint32_t cc1 = 0;
    rc = nvme_tcp_property_get32(s->admin_queue, 0x14, &cc1, errp);
    if (rc != 0) {
        error_prepend(errp, "Failed to get cc! ");
        return rc;
    }
    if (cc != cc1) {
        error_setg(errp, "Controller configuration not set correctly!");
        return -EIO;
    }
    uint32_t status;
    rc = nvme_tcp_property_get32(s->admin_queue, 0x1c, &status, errp);
    if (rc != 0) {
        error_prepend(errp, "Failed to get status! ");
        return rc;
    }
    if ((status & 0x1) != 0x1) {
        error_setg(errp, "Controller not ready!");
        return -EIO;
    }
    uint32_t version;
    rc = nvme_tcp_property_get32(s->admin_queue, 0x08, &version, errp);
    if (rc != 0) {
        error_prepend(errp, "Failed to get version! ");
        return rc;
    }
    trace_nvmf_tcp_version(version >> 16, (version >> 8) & 0xff, version & 0xff);

    NvmeSglDescriptor identify_cmd_sgl = {
        .type = NVME_SGL_DESCR_ENCODE_TYPE(NVME_SGL_DESCR_TYPE_TRANSPORT_DATA_BLOCK, NVME_TCP_SGL_DESCR_SUBTYPE_DATA_BUFFER),
        .len = cpu_to_le32(sizeof(NvmeIdCtrl)),
    };
    NvmfIdentify identify_cmd = {
        .opcode = NVME_ADM_CMD_IDENTIFY,
        .flags = 0x40, /* use of SGL for reply */
        .dptr.sgl = identify_cmd_sgl,
        .cns = 0x1, /* identify controller */
    };
    rc = nvme_tcp_submit_command(s->admin_queue, (NvmeCmd *) &identify_cmd, NULL, 0, true, errp);
    if (rc != 0) {
        return rc;
    }
    NvmeIdCtrl id_ctrl;
    rc = nvme_tcp_await_data(s->admin_queue, &id_ctrl, sizeof(id_ctrl), le16_to_cpu(identify_cmd.command_id), errp);
    if (rc != 0) {
        error_prepend(errp, "Failed to identify controller! ");
        return rc;
    }
    // TODO: copy more of these from nvme.c
    s->write_cache_supported = le32_to_cpu(id_ctrl.vwc) & 0x1;
    // TODO FIXME XXX
    s->max_transfer = s->page_size;
    // s->max_transfer = (id_ctrl.mdts ? 1 << id_ctrl.mdts : 0) * s->page_size;
    // /* For now the page list buffer per command is one page, to hold at most
    //  * s->page_size / sizeof(uint64_t) entries. */
    // s->max_transfer = MIN_NON_ZERO(s->max_transfer,
    //                       s->page_size / sizeof(uint64_t) * s->page_size);

    // TODO: add more handshaky config exchange from kernel driver for fun

    NvmeSglDescriptor identify_ns_cmd_sgl = {
        .type = NVME_SGL_DESCR_ENCODE_TYPE(NVME_SGL_DESCR_TYPE_TRANSPORT_DATA_BLOCK, NVME_TCP_SGL_DESCR_SUBTYPE_DATA_BUFFER),
        .len = cpu_to_le32(sizeof(NvmeIdNs)),
    };
    s->nsid = 1; // TODO: don't hardcode this, get list of active ns (or take as parameter)
    NvmfIdentify identify_ns_cmd = {
        .opcode = NVME_ADM_CMD_IDENTIFY,
        .flags = 0x40, /* use of SGL for reply */
        .dptr.sgl = identify_ns_cmd_sgl,
        .cns = 0x0, /* identify namespace */
        .nsid = cpu_to_le32(s->nsid),
    };
    rc = nvme_tcp_submit_command(s->admin_queue, (NvmeCmd *) &identify_ns_cmd, NULL, 0, true, errp);
    if (rc != 0) {
        return rc;
    }
    NvmeIdNs id_ns;
    rc = nvme_tcp_await_data(s->admin_queue, &id_ns, sizeof(id_ns), le16_to_cpu(identify_ns_cmd.command_id), errp);
    if (rc != 0) {
        error_prepend(errp, "Failed to identify ns: ");
        return rc;
    }
    s->nsze = le64_to_cpu(id_ns.nsze);
    NvmeLBAF *lbaf = &id_ns.lbaf[NVME_ID_NS_FLBAS_INDEX(id_ns.flbas)];
    s->blkshift = lbaf->ds;

    NvmeSglDescriptor set_features_sgl = {
        .type = NVME_TCP_SGL_TYPE_DATA_BUFFER,
    };
    NvmeCmd request_num_io_queues = {
        .opcode = NVME_ADM_CMD_SET_FEATURES,
        .dptr.sgl = set_features_sgl,
        .cdw10 = cpu_to_le32(0x7),
        .cdw11 = (cpu_to_le16(s->num_io_threads) << 16) /* 0-based + main iothread*/
               | (cpu_to_le16(s->num_io_threads) & 0xffff), // TODO
    };
    NvmfCompletion completion_num_io_queues;
    rc = nvme_tcp_submit_command_and_await_completion(s->admin_queue, &request_num_io_queues, NULL, 0, true, &completion_num_io_queues, errp);
    if (rc) {
        return rc;
    }
    unsigned num_io_queues_allocated = le16_to_cpu(completion_num_io_queues.result.u32 & 0xffff);
    if (s->num_io_threads + 1 > num_io_queues_allocated) {
        error_setg(errp, "Target only allows %u IO-Queues", num_io_queues_allocated);
        error_append_hint(errp, "%u IO-Queues were requested: %u IOThreads + 1 main IO-thread", s->num_io_threads + 1, s->num_io_threads);
        return -EINVAL;
    }
    s->max_num_io_queues = s->num_io_threads + 1;

    s->io_queues = g_malloc(sizeof(NvmeTcpQueue *) * s->max_num_io_queues);
    for (size_t i = 0; i < s->max_num_io_queues; i++) {
        s->io_queues[i] = g_new0(NvmeTcpQueue, 1);
        s->io_queues[i]->sqsize = le16_to_cpu(id_ctrl.maxcmd);
        s->io_queues[i]->next_cid = 0;
        rc = nvme_tcp_queue_transport_connect(s, s->io_queues[i], i + 1, errp);
        if (rc != 0) {
            return rc;
        }
        rc = nvme_tcp_queue_connect(s, s->io_queues[i], s->cntlid, errp);
        if (rc != 0) {
            return rc;
        }
        qemu_co_mutex_init(&s->io_queues[i]->wlock);
        qemu_co_mutex_init(&s->io_queues[i]->rlock);
    }

    trace_nvmf_tcp_setup_complete(s->page_size, 1U << s->blkshift);

    return 0;
}

static void nvme_tcp_close(BlockDriverState *bs)
{
    // TODO: free queues or something
    BDRVNVMeTCPState *s = bs->opaque;
    g_free(s->subsysnqn);
    timer_free(s->ka_timer);
}

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
 * TODO: go over this completely, c/p from nvme.c
 */
static int nvme_tcp_open(BlockDriverState *bs, QDict *options, int flags,
                     Error **errp)
{
    BDRVNVMeTCPState *s = bs->opaque;
    qemu_mutex_init(&s->thread_ioq_mapping_wlock);

    bs->supported_write_flags = BDRV_REQ_FUA;

    BlockdevOptionsNvmeTcp *opts = nvme_tcp_parse_options(options, errp);
    if (!opts) {
        return -EINVAL;
    }
    s->tgtsock.type = SOCKET_ADDRESS_TYPE_INET;
    s->tgtsock.u.inet = *opts->tgtsock;
    s->subsysnqn = g_strdup(opts->subsysnqn);
    s->num_io_threads = opts->has_num_io_threads ? opts->num_io_threads : 0;
    s->next_unused_io_q = 0;

    int ret = __nvme_tcp_open(bs, errp);

    if (ret) {
        goto fail;
    }
    if (flags & BDRV_O_NOCACHE) {
        // if (!s->write_cache_supported) {
            error_setg(errp,
                       "NVMe controller doesn't support write cache configuration");
            ret = -EINVAL;
        // } else {
        //     ret = nvmf_enable_disable_write_cache(bs, !(flags & BDRV_O_NOCACHE),
        //                                           errp);
        // }
        // if (ret) {
            goto fail;
        // }
    }
    return 0;
fail:
    nvme_tcp_close(bs);
    return ret;
}

static coroutine_fn NvmeTcpQueue *nvme_tcp_thread_ioq_mapping_get(BDRVNVMeTCPState *s)
{
    for (unsigned i = 0; i < s->next_unused_io_q; i++) {
        if (qemu_thread_is_self(&s->io_queues[i]->thread)) {
            return s->io_queues[i];
        }
    }

    return NULL;
}

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

static NvmeTcpResponseCtx coroutine_fn *nvme_tcp_rctxrbuf_get(NvmeTcpQueue *q, uint16_t cid)
{
    uint16_t cid_off = cid - q->rctxrbuf_tail_cid; /* accurately handle cid wrap-around */
    NvmeTcpResponseCtx *entry = &q->rctxrbuf[(q->rctxrbuf_tail_idx + cid_off) % RCTXRBUF_SIZE];
    return entry;
}

static void coroutine_fn nvme_tcp_rctxrbuf_register(NvmeTcpQueue *q, uint16_t cid, QEMUIOVector *qiov)
{
    NvmeTcpResponseCtx *rctx = nvme_tcp_rctxrbuf_get(q, cid);
    rctx->exists = true;
    rctx->qiov = qiov;
    rctx->co = qemu_coroutine_self();
    rctx->io_done = false;
    rctx->co_waiting = false;
}

static void coroutine_fn nvme_tcp_cbrbuf_deregister(NvmeTcpQueue *q, uint16_t cid)
{
    assert(nvme_tcp_rctxrbuf_get(q, cid)->exists);
    nvme_tcp_rctxrbuf_get(q, cid)->exists = false;
    while (q->rctxrbuf[q->rctxrbuf_tail_idx].exists == false) {
        q->rctxrbuf_tail_idx++;
        q->rctxrbuf_tail_cid++;
    }
}

static int coroutine_fn nvme_tcp_co_await_io_resp(NvmeTcpQueue *q, uint16_t our_cid, Error **errp)
{
    ERRP_GUARD();
    NvmfCompletion cqe;
    NvmeTcpDataPdu data_pdu;
    NvmeTcpResponseCtx *our_rctx = nvme_tcp_rctxrbuf_get(q, our_cid);
    NvmeTcpResponseCtx *their_rctx;
    uint16_t their_cid;
    int rc;

    WITH_QEMU_LOCK_GUARD(&q->rlock) {
        rc = nvme_tcp_recv(q, &data_pdu.hdr, sizeof(NvmeTcpHdr), errp);
        if (rc) {
            error_prepend(errp, "Failed to recv hdr: ");
            return rc;
        }

        switch (data_pdu.hdr.type) {
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
                their_cid = le16_to_cpu(cqe.command_id);
                their_rctx = nvme_tcp_rctxrbuf_get(q, their_cid);
                break;

            case NVME_TCP_PDUTYPE_C2HDATA:
                rc = nvme_tcp_recv(q, ((uint8_t *) &data_pdu) + sizeof(NvmeTcpHdr), sizeof(data_pdu) - sizeof(NvmeTcpHdr), errp);
                if (rc) {
                    error_prepend(errp, "Failed to recv data pdu: ");
                    return rc;
                }
                if (!(data_pdu.hdr.flags & 0x08)) {
                    error_setg(errp, "Read unsuccessful");
                    return -EIO;
                }
                if (!(data_pdu.hdr.flags & 0x04)) {
                    error_setg(errp, "Read fragmented, not yet supported"); // TODO
                    return -EIO;
                }
                if (data_pdu.hdr.hlen != data_pdu.hdr.pdo) {
                    // TODO
                    error_setg(errp, "Received padding or digest, unsupported.");
                    return -EIO;
                }
                if (le32_to_cpu(data_pdu.data_offset) != 0) {
                    // TODO
                    error_setg(errp, "Received data with offset, unsupported.");
                    return -EIO;
                }

                their_cid = le16_to_cpu(data_pdu.command_id);
                their_rctx = nvme_tcp_rctxrbuf_get(q, their_cid);
                if (le32_to_cpu(data_pdu.data_length) != iov_size(their_rctx->qiov->iov, their_rctx->qiov->niov)) {
                    error_setg(errp, "Received data pdu with unexpected length");
                    return -EIO;
                }

                rc = qio_channel_readv_all(QIO_CHANNEL(q->sock), their_rctx->qiov->iov, their_rctx->qiov->niov, errp);
                if (rc) {
                    error_prepend(errp, "Failed to recv data: ");
                    return rc;
                }
                break;

            default:
                abort(); // TODO
        }
    }

    /* we received our own response, done */
    if (their_cid == our_cid) {
        goto done;
    }

    our_rctx->co_waiting = true;
    their_rctx->io_done = true;

    /* notify them that their i/o has been completed */
    if (their_rctx->co_waiting) {
        qemu_coroutine_enter(their_rctx->co);
    }

    /* our i/o has already been completed by a different coroutine, done */
    if (our_rctx->io_done) {
        goto done;
    }

    /* wait for our i/o to be completed by a different coroutine */
    qemu_coroutine_yield();
    assert(our_rctx->io_done);

done:
    nvme_tcp_cbrbuf_deregister(q, our_cid);
    return 0;
}

static int coroutine_fn nvme_tcp_co_prwv(bool write, BlockDriverState *bs,
    int64_t offset, int64_t bytes, QEMUIOVector *qiov)
{
    BDRVNVMeTCPState *s = bs->opaque;
    NvmeTcpQueue *q = nvme_tcp_get_io_queue_for_current_thread(s);
    Error *err;
    NvmeSglDescriptor sgld = {
        .type = write ? NVME_TCP_SGL_TYPE_DATA_BLOCK : NVME_TCP_SGL_TYPE_DATA_BUFFER,
        .len = cpu_to_le32(bytes),
    };
    NvmeRwCmd cmd = {
        .opcode = write ? NVME_CMD_WRITE : NVME_CMD_READ,
        .flags = 0x40,
        .nsid = cpu_to_le32(s->nsid),
        .dptr.sgl = sgld,
        .slba = cpu_to_le64(offset >> s->blkshift),
        .nlb = cpu_to_le16((bytes >> s->blkshift) - 1), /* 0-based */
    };
    uint16_t cid;
    int rc;

    assert(QEMU_IS_ALIGNED(offset, 1ULL << s->blkshift));
    assert(QEMU_IS_ALIGNED(bytes, 1ULL << s->blkshift));

    rc = nvme_tcp_submit_commandv(
        q,
        (NvmeCmd *) &cmd,
        write ? qiov->iov : NULL,
        write ? qiov->niov : 0,
        write ? bytes : 0,
        false,
        &err);
    if (rc) {
        error_propagate_prepend(&error_abort, err, "Failed to submit rw cmd: ");
        return rc;
    }

    cid = le16_to_cpu(cmd.cid);
    nvme_tcp_rctxrbuf_register(q, cid, write ? NULL : qiov);

    rc = nvme_tcp_co_await_io_resp(q, cid, &err);
    if (rc) {
        error_propagate_prepend(&error_abort, err, "Failed to recv io resp: ");
        return rc;
    }

    return 0;
}

static int coroutine_fn nvme_tcp_co_preadv(BlockDriverState *bs,
    int64_t offset, int64_t bytes, QEMUIOVector *qiov,
    BdrvRequestFlags flags)
{
    return nvme_tcp_co_prwv(false, bs, offset, bytes, qiov);
}

static int coroutine_fn nvme_tcp_co_pwritev(
    BlockDriverState *bs, int64_t offset, int64_t bytes, QEMUIOVector *qiov,
    BdrvRequestFlags flags)
{
    return nvme_tcp_co_prwv(true, bs, offset, bytes, qiov);
}

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

        rc = qio_channel_flush(QIO_CHANNEL(s->io_queues[i]->sock), &err);
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
    nvme_tcp_rctxrbuf_register(q, cid, NULL);

    rc = nvme_tcp_co_await_io_resp(q, cid, &err);
    if (rc) {
        error_prepend(errp, "No flush cmd cqe: ");
        return rc;
    }

    return 0;
}

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

static void nvmf_refresh_filename(BlockDriverState *bs)
{
    BDRVNVMeTCPState *s = bs->opaque;

    snprintf(bs->exact_filename, sizeof(bs->exact_filename), "nvme-tcp://%s:%s/%s",
             s->tgtsock.u.inet.host, s->tgtsock.u.inet.port, s->subsysnqn);
}

static void nvme_tcp_refresh_limits(BlockDriverState *bs, Error **errp)
{
    BDRVNVMeTCPState *s = bs->opaque;

    bs->bl.opt_mem_alignment = s->page_size;
    bs->bl.request_alignment = s->page_size;
    bs->bl.max_transfer = s->max_transfer;

    // /*
    //  * Look at nvme_co_pwrite_zeroes: after shift and decrement we should get
    //  * at most 0xFFFF
    //  */
    // bs->bl.max_pwrite_zeroes = 1ULL << (s->blkshift + 16);
    // bs->bl.pwrite_zeroes_alignment = MAX(bs->bl.request_alignment,
    //                                      1UL << s->blkshift);

    bs->bl.max_pdiscard = (uint64_t)UINT32_MAX << s->blkshift;
    // bs->bl.pdiscard_alignment = MAX(bs->bl.request_alignment,
    //                                 1UL << s->blkshift);
    bs->bl.pdiscard_alignment = 0;
}

static int64_t coroutine_fn nvme_tcp_co_getlength(BlockDriverState *bs)
{
    BDRVNVMeTCPState *s = bs->opaque;
    return s->nsze << s->blkshift;
}

/**
 * Part of BlockDriver definition
 *
 * This includes a workaround for discard granularity errors
 * and other potential incompatibilities:
 * QEMU is told that blocks are 512 byte, while request alignment
 * is at least 4096 byte anyway. We convert internally,
 * see nvme_tcp_blk_conv_shift()
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

static int coroutine_fn nvme_tcp_co_truncate(BlockDriverState *bs, int64_t offset,
                                         bool exact, PreallocMode prealloc,
                                         BdrvRequestFlags flags, Error **errp)
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
 * part of BlockDriver definition
 *
 * options that change drive data
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

    .bdrv_co_preadv           = nvme_tcp_co_preadv,
    .bdrv_co_pwritev          = nvme_tcp_co_pwritev,

    .bdrv_co_flush_to_disk    = nvme_tcp_co_flush,

    .bdrv_refresh_filename    = nvmf_refresh_filename,
    .bdrv_refresh_limits      = nvme_tcp_refresh_limits,
    .strong_runtime_opts      = nvme_tcp_strong_runtime_opts,

    // .bdrv_reopen_prepare      = nvme_reopen_prepare,
    // .bdrv_co_pwrite_zeroes    = nvme_co_pwrite_zeroes,
    // .bdrv_co_pdiscard         = nvme_co_pdiscard,
    // .bdrv_co_preadv           = nvme_co_preadv,
    // .bdrv_co_pwritev          = nvme_co_pwritev,
    // .bdrv_detach_aio_context  = nvme_detach_aio_context,
    // .bdrv_attach_aio_context  = nvme_attach_aio_context,
    // .bdrv_get_specific_stats  = nvme_get_specific_stats,
    // .bdrv_register_buf        = nvme_register_buf,
    // .bdrv_unregister_buf      = nvme_unregister_buf,
};

static void bdrv_nvme_tcp_init(void)
{
    bdrv_register(&bdrv_nvme_tcp);
}

block_init(bdrv_nvme_tcp_init);
