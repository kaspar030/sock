#include <stdio.h>
#include <string.h>

#include "nanocoap.h"

ssize_t _test_handler(coap_pkt_t* pkt, uint8_t *buf, size_t len, void *context)
{
    (void)context;

    printf("_test_handler()\n");
    printf("coap pkt parsed. code=%u detail=%u payload_len=%u, len=%u 0x%02x\n",
            coap_get_code_class(pkt),
            coap_get_code_detail(pkt),
            pkt->payload_len, (unsigned)len, pkt->hdr->code);

    const char payload[] = "1234";
    return coap_reply_simple(pkt, COAP_CODE_205, buf, len, COAP_FORMAT_TEXT, (uint8_t*)payload, 4);
}

ssize_t _blockwise_handler(coap_pkt_t* pkt, uint8_t *buf, size_t len, void *context)
{
    (void)context;

    printf("_blockwise_handler()\n");

    uint32_t result = COAP_CODE_204;
    uint32_t blknum;
    uint32_t szx;
    int res = coap_get_blockopt(pkt, COAP_OPT_BLOCK1, &blknum, &szx);
    if (res >= 0) {
        printf("blknum=%u blksize=%u more=%u\n", blknum, coap_szx2size(szx), res);
        size_t offset = blknum << (szx + 4);
        printf("received bytes %u-%u\n", (unsigned)offset, (unsigned)offset+pkt->payload_len);
        if (res) {
            result = COAP_CODE_231;
        }
    }

    ssize_t reply_len = coap_build_reply(pkt, result, buf, len, 0);
    uint8_t *pkt_pos = (uint8_t*)pkt->hdr + reply_len;
    if (res >= 0) {
        pkt_pos += coap_put_option_block1(pkt_pos, 0, blknum, szx, res);
    }
    return pkt_pos - (uint8_t*)pkt->hdr;
}

const coap_resource_t coap_resources[] = {
    COAP_WELL_KNOWN_CORE_DEFAULT_HANDLER,
    { "/blockwise", COAP_GET | COAP_POST | COAP_PUT, _blockwise_handler, NULL },
    { "/test", COAP_GET, _test_handler, NULL },
};

const unsigned coap_resources_numof = sizeof(coap_resources) / sizeof(coap_resources[0]);
