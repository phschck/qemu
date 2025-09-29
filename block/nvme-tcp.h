#ifndef NVME_TCP
#define NVME_TCP

enum NvmeTcpPduType {
    NVME_TCP_PDUTYPE_ICREQ = 0x00,
    NVME_TCP_PDUTYPE_ICRESP = 0x01,
    NVME_TCP_PDUTYPE_CAPSULE_CMD = 0x04,
    NVME_TCP_PDUTYPE_CAPSULE_RESP = 0x05,
    NVME_TCP_PDUTYPE_H2CDATA = 0x06,
    NVME_TCP_PDUTYPE_C2HDATA = 0x07,
    NVME_TCP_PDUTYPE_R2T = 0x09,
};

enum NvmeTcpHlen {
    NVME_TCP_HLEN_ICREQ = 0x80,
    NVME_TCP_HLEN_ICRESP = 0x80,
    NVME_TCP_HLEN_CAPSULE_CMD = 0x48,
    NVME_TCP_HLEN_CAPSULE_RESP = 0x18,
    NVME_TCP_HLEN_H2CDATA = 0x18,
};

/**
 * NvmeTcpHdr - nvme tcp pdu common header
 *
 * @type:          pdu type
 * @flags:         pdu specific flags
 * @hlen:          pdu header length
 * @pdo:           pdu data offset
 * @plen:          pdu wire byte length
 */
typedef struct QEMU_PACKED NvmeTcpHdr {
    uint8_t  type;
    uint8_t  flags;
    uint8_t  hlen;
    uint8_t  pdo;
    uint32_t plen;
} NvmeTcpHdr;

/**
 * NvmeTcpIcreqPdu - nvme tcp initialize connection request pdu
 *
 * @hdr:           pdu generic header
 * @pfv:           pdu version format
 * @hpda:          host pdu data alignment (dwords, 0's based)
 * @digest:        digest types enabled
 * @maxr2t:        maximum r2ts per request supported
 */
typedef struct QEMU_PACKED NvmeTcpIcreqPdu {
    NvmeTcpHdr hdr;
    uint16_t   pfv;
    uint8_t    hpda;
    uint8_t    digest;
    uint32_t   maxr2t;
    uint8_t    rsvd2[112];
} NvmeTcpIcreqPdu;

/**
 * NvmeTcpIcrespPdu - nvme tcp initialize connection response pdu
 *
 * @hdr:           pdu common header
 * @pfv:           pdu version format
 * @cpda:          controller pdu data alignment (dowrds, 0's based)
 * @digest:        digest types enabled
 * @maxdata:       maximum data capsules per r2t supported
 */
typedef struct QEMU_PACKED NvmeTcpIcrespPdu {
    NvmeTcpHdr hdr;
    uint16_t   pfv;
    uint8_t    cpda;
    uint8_t    digest;
    uint32_t   maxdata;
    uint8_t    rsvd[112];
} NvmeTcpIcrespPdu;

/**
 * NvmeTcpR2tPdu - nvme tcp ready-to-transfer pdu
 *
 * @hdr:           pdu common header
 * @cid:           nvme command identifier which this relates to
 * @ttag:          transfer tag (controller-generated)
 * @r2to:          offset from the start of the command data
 * @r2tl:          length the host is allowed to send
 */
typedef struct QEMU_PACKED NvmeTcpR2tPdu {
    struct NvmeTcpHdr hdr;
    uint16_t          cid;
    uint16_t          ttag;
    uint32_t          r2to;
    uint32_t          r2tl;
    uint8_t           rsvd[4];
} NvmeTcpR2tPdu;

/**
 * NvmeTcpDataPdu - nvme tcp data pdu
 *
 * @hdr:           pdu common header
 * @cid:           nvme command identifier which this relates to
 * @ttag:          transfer tag (controller generated)
 * @datao:         offset from the start of the command data
 * @datal:         length of the data stream
 */
typedef struct QEMU_PACKED NvmeTcpDataPdu {
    NvmeTcpHdr hdr;
    uint16_t   cid;
    uint16_t   ttag;
    uint32_t   datao;
    uint32_t   datal;
    uint8_t    rsvd[4];
} NvmeTcpDataPdu;

enum NvmeTcpSglDescriptorSubtype {
    NVME_TCP_SGL_DESCR_SUBTYPE_IN_CAPSULE  = 0x1,
    NVME_TCP_SGL_DESCR_SUBTYPE_DATA_BUFFER = 0xa,
};

#define NVME_SGL_DESCR_ENCODE_TYPE(type, subtype) ((type << 4) | (subtype & 0xf))
#define NVME_TCP_SGL_TYPE_DATA_BLOCK NVME_SGL_DESCR_ENCODE_TYPE(NVME_SGL_DESCR_TYPE_DATA_BLOCK, NVME_SGL_DESCR_SUBTYPE_OFFSET)
#define NVME_TCP_SGL_TYPE_IN_CAPSULE NVME_SGL_DESCR_ENCODE_TYPE(NVME_SGL_DESCR_TYPE_TRANSPORT_DATA_BLOCK, NVME_TCP_SGL_DESCR_SUBTYPE_IN_CAPSULE)
#define NVME_TCP_SGL_TYPE_DATA_BUFFER NVME_SGL_DESCR_ENCODE_TYPE(NVME_SGL_DESCR_TYPE_TRANSPORT_DATA_BLOCK, NVME_TCP_SGL_DESCR_SUBTYPE_DATA_BUFFER)

#define NVME_TCP_KATO 0x1D4C0 /* 2mins */

// TODO:
// add _xxx_check_size() and test if it really runs by entering a wrong one
#endif
