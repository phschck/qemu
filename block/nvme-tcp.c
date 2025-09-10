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

#include "block/nvme.h"
#include "block/nvme-fabrics.h"
#include "block/nvme-tcp.h"

/**
 * general TODO:
 * - rewrite read/write/flush to make async, allow multiple requests
 *   on same queue and ideally use multiple queues on multiple threads
 * - alignment other than 0
 * - fix indents, wrap long lines, sort includes,...
 * - correctly free everything on (early) exit
 * - don't error_abort outside of startup
 * - improve tracing (less with every cmd, more with config and state changes)
 * - everything indicated with // comments
 */

typedef struct NvmeTcpQueue {
    QIOChannelSocket *sock;
    CoMutex lock;

    uint16_t qid;
    uint16_t next_cid;

    uint8_t controller_alignment_bytes;
    uint32_t maxh2cdata;
} NvmeTcpQueue;

typedef struct BDRVNVMeTCPState {
    // TODO: think about if we need global mutexes like in nvme.c

    NvmeTcpQueue *admin_queue;

    QemuMutex thread_ioq_mapping_wlock; /* reads should be disjoint enough to not need locking i think */
    QDict *thread_ioq_mapping;
    NvmeTcpQueue **io_queues;
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
static int nvme_tcp_sendv(NvmeTcpQueue *queue, const struct iovec *iov, size_t niov, size_t len, Error **errp)
{
    ERRP_GUARD();
    assert(queue->sock);
    ssize_t bytes_written = qio_channel_writev(QIO_CHANNEL(queue->sock), iov, niov, errp);

    if (bytes_written < 0) {
        error_prepend(errp, "Write error: ");
        return -EIO;
    }
    if (bytes_written != len) {
        error_setg(errp, "Tried to write %ld bytes, but wrote %ld!", len, bytes_written);
        return -EIO;
    }

    int rc = qio_channel_flush(QIO_CHANNEL(queue->sock), errp);
    if (rc) {
        error_prepend(errp, "Flush error: ");
        return rc;
    }

    return 0;
}

static int nvme_tcp_send(NvmeTcpQueue *queue, const void *buf, size_t len, Error **errp)
{
    struct iovec iov = { .iov_base = (void *) buf, .iov_len = len};
    return nvme_tcp_sendv(queue, &iov, 1, len, errp);
}

static int nvme_tcp_recv(NvmeTcpQueue *queue, void *buf, size_t len, Error **errp) {
    ssize_t bytes_read = qio_channel_read(QIO_CHANNEL(queue->sock), buf, len, errp);

    if (bytes_read < 0) {
        return -EIO;
    }
    if (bytes_read != len) {
        error_setg(errp, "Expected size %ld, but received %ld!", len, bytes_read);
        return -EIO;
    }

    return 0;
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

    // TODO FIXME
    // IO CHANNELS HAVE BLOCKING AND NON-BLOCKING MODE
    // CONFIGURE!!!!
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
        .maxr2t = cpu_to_be32(NVME_TCP_MAX_R2T),
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
    queue->maxh2cdata = icresp.maxdata;

    trace_nvmf_tcp_transport_connect(NVME_TCP_HOST_DATA_ALIGNMENT_BYTES, queue->controller_alignment_bytes, queue->maxh2cdata);

    return 0;
}

static int nvme_tcp_submit_commandv(NvmeTcpQueue *queue, const NvmeCmd *cmd, const struct iovec *data, const size_t data_niov, size_t data_len, Error **errp)
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

    trace_nvmf_tcp_submit_command(queue->qid, cmd->opcode, cmd->cid, data_len, pad_len);

    iov[0].iov_base = &hdr;
    iov[0].iov_len = sizeof(hdr);

    iov[1].iov_base = (void *) cmd;
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

    rc = nvme_tcp_sendv(queue, iov, niov, sizeof(NvmeTcpHdr) + sizeof(NvmeCmd) + data_len, errp);
    if (rc) {
        error_prepend(errp, "Submitting %s command (opcode 0x%02x) failed: ", queue->qid == 0 ? "admin" : "io", cmd->opcode);
    }

    return 0;
}

static inline int nvme_tcp_submit_command(NvmeTcpQueue *queue, const NvmeCmd *cmd, const char *data, size_t data_len, Error **errp)
{
    struct iovec iov = { .iov_base = (char *) data, .iov_len = data_len };
    return nvme_tcp_submit_commandv(queue, cmd, &iov, 1, data_len, errp);
}

// TODO:
// here (and in await_data) we also may have to reconnect
// this will be more complicated, as we have to do the handshake and then receive the expected thingy
// they may come out of order, so we absolutely should restructure the entire receiving process
// to sort packets into the appropriate handlers based on header type and cid
// (luckily traffic remains separated by queues per definition, so it's enough to "register"
// expected packets within a queue)
// see chapter 9.6 in the base spec!!!!!!
static int nvme_tcp_await_completion(NvmeTcpQueue *queue, NvmfCompletion *completion, Error **errp)
{
    ERRP_GUARD();
    int rc = 0;

    NvmeTcpHdr hdr;
    rc = nvme_tcp_recv(queue, &hdr, sizeof(hdr), errp);
    if (rc) {
        error_prepend(errp, "Failed recv hdr for cqe: ");
        return rc;
    }
    if (hdr.type != NVME_TCP_PDUTYPE_CAPSULE_RESP) {
        error_setg(errp, "Recv wrong hdr type (0x%02x instead of 0x%02x)", hdr.type, NVME_TCP_PDUTYPE_CAPSULE_RESP);
        return rc;
    }

    rc = nvme_tcp_recv(queue, completion, sizeof(NvmfCompletion), errp);
    if (rc) {
        error_prepend(errp, "Failed to recv cqe: ");
        return rc;
    }

    return nvmf_translate_error(completion, trace_nvmf_tcp_error);
}

static int nvme_tcp_submit_command_and_await_completion(NvmeTcpQueue *queue, const NvmeCmd *cmd, const char *data, size_t data_len, NvmfCompletion *completion, Error **errp)
{
    int rc;

    rc = nvme_tcp_submit_command(queue, cmd, data, data_len, errp);
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

static int nvme_tcp_await_datav(NvmeTcpQueue *queue, struct iovec *iov, size_t niov, size_t len, Error **errp)
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
    if (data_pdu.data_length != len) {
        error_setg(errp, "Hdr length field %d instead of %ld!", data_pdu.data_length, len);
        return -EIO; // TODO
    }
    if (data_pdu.data_offset != 0) {
        // TODO
        error_setg(errp, "Received data with offset, unsupported.");
        return -ENOTSUP; // TODO
    }
    if (data_pdu.hdr.flags != 0x0c) {
        // TODO
        error_setg(errp, "Received data with unsupported flags.");
        return -ENOTSUP; // TODO
    }

    // FIXME everything breaks when data is fragmented by tcp
    // (sadly I can't just repeat because it has to continue writing to the correct pos
    // in the iovec... maybe we do have to allocate a buffer here)
    ssize_t bytes_read = qio_channel_readv(QIO_CHANNEL(queue->sock), iov, niov, errp);
    if (bytes_read < 0) {
        error_prepend(errp, "Failed to recv data: ");
        return -EIO;
    }
    if (bytes_read != len) {
        error_setg(errp, "Expected data size %ld, but received %ld!", len, bytes_read);
        return -EIO;
    }

    trace_nvmf_tcp_recv_data(len);

    return 0;
}

static int nvme_tcp_await_data(NvmeTcpQueue *queue, void *buf, size_t len, Error **errp)
{
    struct iovec iov = {.iov_base = buf, .iov_len = len};
    return nvme_tcp_await_datav(queue, &iov, 1, len, errp);
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
    queue->next_cid = 1;
    cmd.command_id = queue->next_cid++;
    cmd.fctype = NVME_FCTYPE_CONNECT;
    NvmeSglDescriptor sgl = {
        .type = NVME_TCP_SGL_TYPE_DATA_BLOCK,
        .addr = 0,
        .len = cpu_to_le32(1024),
        .rsvd = {0},
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
    rc = nvme_tcp_submit_command_and_await_completion(queue, (const NvmeCmd *) &cmd, (const char *) &data, sizeof(NvmfConnectData), &completion, errp);
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

static int nvme_tcp_property_get32(NvmeTcpQueue *queue, uint32_t offset, uint32_t *result, Error **errp) {
    NvmfPropertyGetCmd cmd = {
        .opcode = NVME_ADM_CMD_FABRICS,
        .resv1 = 0x00,
        .command_id = cpu_to_le16(queue->next_cid++),
        .fctype = NVME_FCTYPE_PROPERTY_GET,
        .attrib = 0x00, /* 4 byte result */
        .offset = cpu_to_le32(offset),
    };
    NvmfCompletion completion;

    int rc = nvme_tcp_submit_command_and_await_completion(queue, (const NvmeCmd *) &cmd, NULL, 0, &completion, errp);
    *result = le32_to_cpu(completion.result.u32);

    return rc;
}

static int nvme_tcp_property_get64(NvmeTcpQueue *queue, uint32_t offset, uint64_t *result, Error **errp) {
    NvmfPropertyGetCmd cmd = {
        .opcode = NVME_ADM_CMD_FABRICS,
        .resv1 = 0x00,
        .command_id = cpu_to_le16(queue->next_cid++),
        .fctype = NVME_FCTYPE_PROPERTY_GET,
        .attrib = 0x01, /* 8 byte result */
        .offset = cpu_to_le32(offset),
    };
    NvmfCompletion completion;

    int rc = nvme_tcp_submit_command_and_await_completion(queue, (const NvmeCmd *) &cmd, NULL, 0, &completion, errp);
    *result = le64_to_cpu(completion.result.u64);

    return rc;
}

static int nvme_tcp_property_set32(NvmeTcpQueue *queue, uint32_t offset, uint32_t value, Error **errp) {
    NvmfPropertySetCmd cmd = {
        .opcode = NVME_ADM_CMD_FABRICS,
        .resv1 = 0x00,
        .command_id = cpu_to_le16(queue->next_cid++),
        .fctype = NVME_FCTYPE_PROPERTY_SET,
        .attrib = 0x00, /* 4 bytes value */
        .offset = cpu_to_le32(offset),
        .value = cpu_to_le32(value),
    };
    NvmfCompletion completion;

    return nvme_tcp_submit_command_and_await_completion(queue, (const NvmeCmd *) &cmd, NULL, 0, &completion, errp);
}

// static int nvme_tcp_property_set64(NvmfTcpQueue *queue, uint32_t offset, uint64_t value, Error **errp) {
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

//     return nvmf_tcp_submit_command_and_await_completion(queue, (const NvmeCmd *) &cmd, NULL, 0, &completion, errp);
// }

static void nvme_tcp_ka_cb(void *opaque) {
    BDRVNVMeTCPState *s = opaque;
    Error *err = NULL;
    int rc;

    NvmeCmd cmd = {
        .opcode = 0x18,
        .cid = cpu_to_le16(s->admin_queue->next_cid++),
    };
    NvmfCompletion cqe;

    // theoretically, we should lock this, tho the admin queue isn't used for anything other than setup in the current state
    // and we'd need a different lock type
    rc = nvme_tcp_submit_command_and_await_completion(s->admin_queue, &cmd, NULL, 0, &cqe, &err);
    if (rc) {
        error_propagate_prepend(&error_abort, err, "Keep-alive cmd failed: ");
    }
    timer_mod(s->ka_timer, qemu_clock_get_ms(QEMU_CLOCK_REALTIME) + NVME_TCP_KATO/2);
}

/**
 * Exclusively exists to increase legibility of nvmf_open()
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
    qemu_co_mutex_init(&s->admin_queue->lock);

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
        return rc;
    }
    uint32_t status;
    rc = nvme_tcp_property_get32(s->admin_queue, 0x1c, &status, errp);
    if (rc != 0) {
        error_prepend(errp, "Failed to get status! ");
        return rc;
    }
    if ((status & 0x1) != 0x1) {
        error_setg(errp, "Controller not ready!");
        return rc;
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
        .command_id = cpu_to_le16(s->admin_queue->next_cid++),
        .dptr.sgl = identify_cmd_sgl,
        .cns = 0x1, /* identify controller */
    };
    rc = nvme_tcp_submit_command(s->admin_queue, (const NvmeCmd *) &identify_cmd, NULL, 0, errp);
    if (rc != 0) {
        return rc;
    }
    NvmeIdCtrl id_ctrl;
    rc = nvme_tcp_await_data(s->admin_queue, &id_ctrl, sizeof(id_ctrl), errp);
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
        .command_id = cpu_to_le16(s->admin_queue->next_cid++),
        .dptr.sgl = identify_ns_cmd_sgl,
        .cns = 0x0, /* identify namespace */
        .nsid = cpu_to_le32(s->nsid),
    };
    rc = nvme_tcp_submit_command(s->admin_queue, (NvmeCmd *) &identify_ns_cmd, NULL, 0, errp);
    if (rc != 0) {
        return rc;
    }
    NvmeIdNs id_ns;
    rc = nvme_tcp_await_data(s->admin_queue, &id_ns, sizeof(id_ns), errp);
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
        .cid = cpu_to_le16(s->admin_queue->next_cid++),
        .dptr.sgl = set_features_sgl,
        .cdw10 = cpu_to_le32(0x7),
        .cdw11 = (cpu_to_le16(s->num_io_threads - 1) << 16)
               | (cpu_to_le16(s->num_io_threads - 1) & 0xffff), // TODO
    };
    NvmfCompletion completion_num_io_queues;
    rc = nvme_tcp_submit_command_and_await_completion(s->admin_queue, &request_num_io_queues, NULL, 0, &completion_num_io_queues, errp);
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
        rc = nvme_tcp_queue_transport_connect(s, s->io_queues[i], i + 1, errp);
        if (rc != 0) {
            return rc;
        }
        rc = nvme_tcp_queue_connect(s, s->io_queues[i], s->cntlid, errp);
        if (rc != 0) {
            return rc;
        }
        qemu_co_mutex_init(&s->io_queues[i]->lock);
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
    s->thread_ioq_mapping = qdict_new();

    bs->supported_write_flags = BDRV_REQ_FUA;

    BlockdevOptionsNvmeTcp *opts = nvme_tcp_parse_options(options, errp);
    if (!opts) {
        return -EINVAL;
    }
    s->tgtsock.type = SOCKET_ADDRESS_TYPE_INET;
    s->tgtsock.u.inet = *opts->tgtsock;
    s->subsysnqn = g_strdup(opts->subsysnqn);
    s->num_io_threads = opts->has_num_io_threads ? opts->num_io_threads : 1;

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

/**
 * This is a workaround for the "discard granularity must
 * be multiple of logical block size" error.
 * Logical block size is fixed to 512, while physical block
 * size is taken from identify namespace.
 * As request alignment >= max physical block size,
 * this should work perfectly.
 */
static size_t nvme_tcp_blk_conv_shift(BDRVNVMeTCPState *s)
{
    return s->blkshift - 9;
}

static coroutine_fn int __nvme_tcp_co_readv(BDRVNVMeTCPState *s, BlockDriverState *bs,
                                 NvmeTcpQueue *queue, int64_t sector_num, int nb_sectors,
                                 QEMUIOVector *qiov)
{
    Error *err;
    int rc;

    NvmeSglDescriptor sgld = {
        .type = NVME_TCP_SGL_TYPE_DATA_BUFFER,
        .len = cpu_to_le32(nb_sectors << s->blkshift),
    };
    NvmeRwCmd cmd = {
        .opcode = NVME_CMD_READ,
        .flags = 0x40,
        .cid = queue->next_cid++,
        .nsid = cpu_to_le32(s->nsid),
        .dptr.sgl = sgld,
        .slba = cpu_to_le64(sector_num),
        .nlb = cpu_to_le16(nb_sectors - 1), /* 0-based */
    };
    rc = nvme_tcp_submit_command(queue, (const NvmeCmd *) &cmd, NULL, 0, &err);
    if (rc) {
        error_propagate_prepend(&error_abort, err, "Failed to submit read (offset 0x%04lx num 0x%04x): ", sector_num, nb_sectors);
        return rc;
    }
    rc = nvme_tcp_await_datav(queue, qiov->iov, qiov->niov, nb_sectors << s->blkshift, &err);
    if (rc) {
        error_propagate_prepend(&error_abort, err, "Failed to recv read data (offset 0x%04lx num 0x%04x): ", sector_num, nb_sectors);
        return rc;
    }

    return 0;
}

static coroutine_fn NvmeTcpQueue *nvme_tcp_get_io_queue_for_current_thread(BDRVNVMeTCPState *s)
{
    QemuThread *thread = g_new(QemuThread, 1);
    Error *err = NULL;

    qemu_thread_get_self(thread);
    char *thread_id = g_strdup_printf("%ld", thread->thread);
    int64_t qindex = qdict_get_try_int(s->thread_ioq_mapping, thread_id, -1);
    if (qindex == -1) {
        if (s->thread_ioq_mapping->size >= s->max_num_io_queues) {
            error_setg(&err, "dict size %ld reached max io queue count %u", s->thread_ioq_mapping->size, s->max_num_io_queues);
            error_append_hint(&err, "Entries:\n");
            for (QDictEntry *e = (QDictEntry *) qdict_first(s->thread_ioq_mapping); e != NULL; e = (QDictEntry *) qdict_next(s->thread_ioq_mapping, e)) {
                error_append_hint(&err, "{%s: %ld}\n", e->key, qdict_get_int(s->thread_ioq_mapping, e->key));
            }
            error_append_hint(&err, "new key: %s", thread_id);
            error_propagate(&error_abort, err);
        }

        qemu_mutex_lock(&s->thread_ioq_mapping_wlock);
        /* recheck after getting the lock */
        qindex = qdict_get_try_int(s->thread_ioq_mapping, thread_id, -1);
        if (qindex == -1) {
            qindex = s->thread_ioq_mapping->size;
            qdict_put_int(s->thread_ioq_mapping, thread_id, qindex);
        }
        qemu_mutex_unlock(&s->thread_ioq_mapping_wlock);
    }
    g_free(thread_id);
    g_free(thread);

    return s->io_queues[qindex];
}

static coroutine_fn int nvme_tcp_co_readv(BlockDriverState *bs,
                                     int64_t sector_num,
                                     int nb_sectors, QEMUIOVector *qiov)
{
    BDRVNVMeTCPState *s = bs->opaque;
    NvmeTcpQueue *q = nvme_tcp_get_io_queue_for_current_thread(s);
    size_t shift = nvme_tcp_blk_conv_shift(s);
    assert(sector_num % (1U << shift) == 0);
    assert(nb_sectors % (1U << shift) == 0);
    int ret;

    qemu_co_mutex_lock(&q->lock);
    ret = __nvme_tcp_co_readv(s, bs, q, sector_num >> shift,
                   nb_sectors >> shift, qiov);
    qemu_co_mutex_unlock(&q->lock);

    return ret;
}

static coroutine_fn int __nvme_tcp_co_writev(BDRVNVMeTCPState *s, BlockDriverState *bs,
                                 NvmeTcpQueue *queue, int64_t sector_num, int nb_sectors,
                                 QEMUIOVector *qiov)
{
    Error *err;
    int rc;

    NvmeSglDescriptor sgld = {
        .type = NVME_TCP_SGL_TYPE_DATA_BLOCK,
        .len = cpu_to_le32(nb_sectors << s->blkshift),
    };
    NvmeRwCmd cmd = {
        .opcode = NVME_CMD_WRITE,
        .flags = 0x40,
        .cid = queue->next_cid++,
        .nsid = cpu_to_le32(s->nsid),
        .dptr.sgl = sgld,
        .slba = cpu_to_le64(sector_num),
        .nlb = cpu_to_le16(nb_sectors - 1), /* 0-based */
    };
    rc = nvme_tcp_submit_commandv(queue, (const NvmeCmd *) &cmd, qiov->iov, qiov->niov, nb_sectors << s->blkshift, &err);
    if (rc) {
        error_propagate_prepend(&error_abort, err, "Failed to submit write cmd: ");
        return rc;
    }
    NvmfCompletion cqe;
    rc = nvme_tcp_await_completion(queue, &cqe, &err);
    if (rc) {
        error_propagate_prepend(&error_abort, err, "Write failed: ");
        return rc;
    }
    if (cqe.command_id != cmd.cid) {
        error_setg(&err, "CQE wrong command id");
        error_propagate(&error_abort, err);
    }

    return rc;
}

static coroutine_fn int nvme_tcp_co_writev(BlockDriverState *bs,
                                     int64_t sector_num,
                                     int nb_sectors, QEMUIOVector *qiov,
                                     int flags)
{
    BDRVNVMeTCPState *s = bs->opaque;
    NvmeTcpQueue *q = nvme_tcp_get_io_queue_for_current_thread(s);
    size_t shift = nvme_tcp_blk_conv_shift(s);
    assert(sector_num % (1U << shift) == 0);
    assert(nb_sectors % (1U << shift) == 0);
    int ret;

    qemu_co_mutex_lock(&q->lock);
    ret = __nvme_tcp_co_writev(s, bs, q, sector_num >> shift,
                   nb_sectors >> shift, qiov);
    qemu_co_mutex_unlock(&q->lock);

    return ret;
}

static coroutine_fn int __nvme_tcp_co_flush(BDRVNVMeTCPState *s, NvmeTcpQueue *queue, BlockDriverState *bs)
{
    Error *err;
    int rc;

    NvmeCmd cmd = {
        .opcode = NVME_CMD_FLUSH,
        .cid = cpu_to_le16(queue->next_cid++),
        .nsid = cpu_to_le32(s->nsid),
    };
    rc = nvme_tcp_submit_command(queue, &cmd, NULL, 0, &err);
    if (rc) {
        error_reportf_err(err, "Failed to submit flush command: ");
        return rc;
    }

    NvmfCompletion completion = {0};
    rc = nvme_tcp_await_completion(queue, &completion, &err);
    if (rc) {
        error_reportf_err(err, "No flush cmd cqe: ");
        return rc;
    }

    return 0;
}

static coroutine_fn int nvme_tcp_co_flush(BlockDriverState *bs)
{
    BDRVNVMeTCPState *s = bs->opaque;
    NvmeTcpQueue *q = nvme_tcp_get_io_queue_for_current_thread(s);
    int rc;

    qemu_co_mutex_lock(&q->lock);
    rc = __nvme_tcp_co_flush(s, q, bs);
    qemu_co_mutex_unlock(&q->lock);

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

    .bdrv_co_readv            = nvme_tcp_co_readv,
    .bdrv_co_writev           = nvme_tcp_co_writev,

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
