#ifndef NVME_FABRICS
#define NVME_FABRICS

// #include "qemu/osdep.h"
// #include "block/nvme.h"
// #include "qemu/uuid.h"

typedef struct QEMU_PACKED NvmfConnectCommand {
    uint8_t     opcode;
    uint8_t     resv1;
    uint16_t    command_id;
    uint8_t     fctype;
    uint8_t     resv2[19];
    NvmeCmdDptr dptr;
    uint16_t    recfmt;
    uint16_t    qid;
    uint16_t    sqsize;
    uint8_t     cattr;
    uint8_t     resv3;
    uint32_t    kato;
    uint8_t     resv4[12];
} NvmfConnectCommand;

typedef struct QEMU_PACKED NvmfConnectData {
    QemuUUID hostid;
    uint16_t cntlid;
    char     resv4[238];
    char     subsysnqn[256];
    char     hostnqn[256];
    char     resv5[256];
} NvmfConnectData;

typedef struct QEMU_PACKED NvmfIdentify {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    command_id;
    uint32_t    nsid;
    uint64_t    rsvd2[2];
    NvmeCmdDptr dptr;
    uint8_t     cns;
    uint8_t     rsvd10;
    uint16_t    ctrlid;
    uint16_t    nvmsetid;
    uint8_t     rsvd11;
    uint8_t     csi;
    uint32_t    rsvd12[4];
} NvmfIdentify;

typedef struct QEMU_PACKED NvmfPropertyGetCmd {
    uint8_t  opcode;
    uint8_t  resv1;
    uint16_t command_id;
    uint8_t  fctype;
    uint8_t  resv2[35];
    uint8_t  attrib;
    uint8_t  resv3[3];
    uint32_t offset;
    uint8_t  resv4[16];
} NvmfPropertyGetCmd;

typedef struct QEMU_PACKED NvmfPropertySetCmd {
    uint8_t  opcode;
    uint8_t  resv1;
    uint16_t command_id;
    uint8_t  fctype;
    uint8_t  resv2[35];
    uint8_t  attrib;
    uint8_t  resv3[3];
    uint32_t offset;
    uint64_t value;
    uint8_t  resv4[8];
} NvmfPropertySetCmd;

typedef struct QEMU_PACKED NvmfCompletion {
    /* Used by Admin and Fabrics commands to return data: */
    union {
        uint16_t u16;
        uint32_t u32;
        uint64_t u64;
    } result;
    uint16_t sq_head;    /* how much of this queue may be reclaimed */
    uint16_t sq_id;      /* submission queue that generated this entry */
    uint16_t command_id; /* of the command which completed */
    uint16_t status;     /* did the command fail, and if so, why? */
} NvmfCompletion;

enum NvmfCommandType {
    NVME_FCTYPE_PROPERTY_SET = 0x00,
    NVME_FCTYPE_CONNECT = 0x01,
    NVME_FCTYPE_PROPERTY_GET = 0x04,
};

static inline int nvmf_translate_error(const NvmfCompletion *c, void (*trace)(uint64_t, uint16_t, uint16_t, uint16_t, uint16_t))
{
    uint16_t status = (le16_to_cpu(c->status) >> 1) & 0xFF;
    if (status) {
        trace(le64_to_cpu(c->result.u64),
              le16_to_cpu(c->sq_head),
              le16_to_cpu(c->sq_id),
              le16_to_cpu(c->command_id),
              le16_to_cpu(status));
    }
    switch (status) {
    case 0:
        return 0;
    case 1:
        return -ENOSYS;
    case 2:
        return -EINVAL;
    default:
        return -EIO;
    }
}

// TODO:
// add _xxx_check_size() and test if it really runs by entering a wrong one
#endif
