#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "nanocoap.h"

#if NANOCOAP_DEBUG
#define ENABLE_DEBUG (1)
#else
#define ENABLE_DEBUG (0)
#endif
#include "debug.h"

static int _decode_value(unsigned val, uint8_t **pkt_pos_ptr, uint8_t *pkt_end);
static uint32_t _decode_uint(uint8_t *pkt_pos, unsigned nbytes);
static size_t _encode_uint(uint32_t *val);

/* http://tools.ietf.org/html/rfc7252#section-3
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Ver| T |  TKL  |      Code     |          Message ID           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Token (if any, TKL bytes) ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Options (if any) ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |1 1 1 1 1 1 1 1|    Payload (if any) ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
int coap_parse(coap_pkt_t *pkt, uint8_t *buf, size_t len)
{
    coap_hdr_t *hdr = (coap_hdr_t *)buf;
    pkt->hdr = hdr;

    uint8_t *pkt_pos = hdr->data;
    uint8_t *pkt_end = buf + len;

    pkt->payload_len = 0;

    /* token value (tkl bytes) */
    if (coap_get_token_len(pkt)) {
        pkt->token = pkt_pos;
        pkt_pos += coap_get_token_len(pkt);
    } else {
        pkt->token = NULL;
    }

    coap_optpos_t *optpos = pkt->options;
    unsigned option_count = 0;
    unsigned option_nr = 0;

    /* parse options */
    while (pkt_pos != pkt_end) {
        uint8_t *option_start = pkt_pos;
        uint8_t option_byte = *pkt_pos++;
        if (option_byte == 0xff) {
            pkt->payload = pkt_pos;
            pkt->payload_len = buf + len - pkt_pos;
            DEBUG("payload len = %u\n", pkt->payload_len);
            break;
        }
        else {
            int option_delta = _decode_value(option_byte >> 4, &pkt_pos, pkt_end);
            if (option_delta < 0) {
                DEBUG("bad op delta\n");
                return -EBADMSG;
            }
            int option_len = _decode_value(option_byte & 0xf, &pkt_pos, pkt_end);
            if (option_len < 0) {
                DEBUG("bad op len\n");
                return -EBADMSG;
            }
            option_nr += option_delta;
            DEBUG("option count=%u nr=%u len=%i\n", option_count, option_nr, option_len);

            if (option_delta) {
                optpos->opt_num = option_nr;
                optpos->offset = (uintptr_t)option_start - (uintptr_t)hdr;
                DEBUG("optpos option_nr=%u %u\n", (unsigned)option_nr, (unsigned)optpos->offset);
                optpos++;
                option_count++;
            }

            pkt_pos += option_len;

            if (pkt_pos > (buf + len)) {
                DEBUG("nanocoap: bad pkt\n");
                return -EBADMSG;
            }
        }
    }

    pkt->options_len = option_count;
    if (!pkt->payload) {
        pkt->payload = pkt_pos;
    }

#ifdef MODULE_GCOAP
    coap_get_uri(pkt, pkt->url);
    pkt->observe_value = 0;
    pkt->content_type = coap_get_content_type(pkt);
#endif

    DEBUG("coap pkt parsed. code=%u detail=%u payload_len=%u, 0x%02x\n",
            coap_get_code_class(pkt),
            coap_get_code_detail(pkt),
            pkt->payload_len, hdr->code);

    return 0;
}

uint8_t *coap_find_option(coap_pkt_t *pkt, unsigned opt_num)
{
    coap_optpos_t *optpos = pkt->options;
    unsigned opt_count = pkt->options_len;

    while (opt_count--) {
        if (optpos->opt_num == opt_num) {
            return (uint8_t*)pkt->hdr + optpos->offset;
        }
        optpos++;
    }
    return NULL;
}

static uint8_t *_parse_option(coap_pkt_t *pkt, uint8_t *pkt_pos, uint16_t *delta, int *opt_len)
{
    uint8_t *hdr_end = pkt->payload;

    if (pkt_pos == hdr_end) {
        return NULL;
    }

    uint8_t option_byte = *pkt_pos++;

    *delta = _decode_value(option_byte >> 4, &pkt_pos, hdr_end);
    *opt_len = _decode_value(option_byte & 0xf, &pkt_pos, hdr_end);

    return pkt_pos;
}

uint8_t *coap_iterate_option(coap_pkt_t *pkt, uint8_t **optpos, int *opt_len, int first)
{
    uint8_t *data_start;

    uint16_t delta = 0;
    data_start = _parse_option(pkt, *optpos, &delta, opt_len);
    if (data_start && (first || !delta)) {
        *optpos = data_start + *opt_len;
        return data_start;
    }
    else {
        *optpos = NULL;
        return NULL;
    }
}

unsigned coap_get_content_type(coap_pkt_t *pkt)
{
    uint8_t *opt_pos = coap_find_option(pkt, COAP_OPT_CONTENT_FORMAT);
    unsigned content_type = COAP_FORMAT_NONE;
    if (opt_pos) {
        uint16_t delta;
        int option_len = 0;
        uint8_t *pkt_pos = _parse_option(pkt, opt_pos, &delta, &option_len);

        if (option_len == 0) {
            content_type = 0;
        } else if (option_len == 1) {
            content_type = *pkt_pos;
        } else if (option_len == 2) {
            memcpy(&content_type, pkt_pos, 2);
            content_type = ntohs(content_type);
        }
    }

    return content_type;
}

int coap_get_uri(coap_pkt_t *pkt, uint8_t *target)
{
    uint8_t *opt_pos = coap_find_option(pkt, COAP_OPT_URI_PATH);
    if (!opt_pos) {
        DEBUG("nanocoap: no COAP_OPT_URI_PATH option\n");
        return -EBADMSG;
    }

    unsigned left = NANOCOAP_URI_MAX - 1;
    uint8_t *part_start = NULL;
    do {
        int opt_len;
        part_start = coap_iterate_option(pkt, &opt_pos, &opt_len, part_start==NULL);
        if (part_start) {
            if (left < (unsigned)(opt_len + 1)) {
                return -ENOSPC;
            }
            *target++ = '/';
            memcpy(target, part_start, opt_len);
            target += opt_len;
            left -= (opt_len + 1);
        }
    } while(opt_pos);

    *target = '\0';

    return NANOCOAP_URI_MAX - left;
}

int coap_get_blockopt(coap_pkt_t *pkt, uint16_t option, uint32_t *blknum, unsigned *szx)
{
    uint8_t *optpos = coap_find_option(pkt, option);
    if (!optpos) {
        puts("notfound");
        return -1;
    }

    uint8_t option_byte = *optpos++;
    int option_len = _decode_value(option_byte & 0xf, &optpos, pkt->payload);
    DEBUG("nanocoap: blkopt len: %i\n", option_len);
    uint32_t blkopt = _decode_uint(optpos+1, option_len);
    DEBUG("nanocoap: blkopt: 0x%08x\n", (unsigned)blkopt);
    *blknum = blkopt >> COAP_BLOCKWISE_NUM_OFF;
    *szx = blkopt & COAP_BLOCKWISE_SZX_MASK;

    return (blkopt & 0x8) ? 1 : 0;
}

ssize_t coap_handle_req(coap_pkt_t *pkt, uint8_t *resp_buf, unsigned resp_buf_len)
{
    if (coap_get_code_class(pkt) != COAP_REQ) {
        DEBUG("coap_handle_req(): not a request.\n");
        return -EBADMSG;
    }

    if (pkt->hdr->code == 0) {
        return coap_build_reply(pkt, COAP_CODE_EMPTY, resp_buf, resp_buf_len, 0);
    }

    unsigned method_flag = coap_method2flag(coap_get_code_detail(pkt));

#ifdef MODULE_GCOAP
    uint8_t *uri = pkt->url;
    int res;
#else
    uint8_t uri[NANOCOAP_URI_MAX];
    int res = coap_get_uri(pkt, uri);
    if (res <= 0) {
        return -EBADMSG;
    }
#endif
    DEBUG("nanocoap: URI path: \"%s\"\n", uri);

    for (unsigned i = 0; i < coap_resources_numof; i++) {
        if (! (coap_resources[i].methods & method_flag)) {
            continue;
        }

        res = strcmp((char *)uri, coap_resources[i].path);
        if (res > 0) {
            continue;
        }
        else if (res < 0) {
            break;
        }
        else {
            return coap_resources[i].handler(pkt, resp_buf, resp_buf_len);
        }
    }

    return coap_build_reply(pkt, COAP_CODE_404, resp_buf, resp_buf_len, 0);
}

ssize_t coap_reply_simple(coap_pkt_t *pkt,
        unsigned code,
        uint8_t *buf, size_t len,
        unsigned ct,
        const uint8_t *payload, uint8_t payload_len)
{
    uint8_t *payload_start = buf + coap_get_total_hdr_len(pkt);
    uint8_t *bufpos = payload_start;

    if (payload_len) {
        bufpos += coap_put_option_ct(bufpos, 0, ct);
        *bufpos++ = 0xff;

        memcpy(bufpos, payload, payload_len);
        bufpos += payload_len;
    }

    return coap_build_reply(pkt, code, buf, len, bufpos - payload_start);
}

ssize_t coap_build_reply(coap_pkt_t *pkt, unsigned code,
        uint8_t *rbuf, unsigned rlen, unsigned payload_len)
{
    unsigned tkl = coap_get_token_len(pkt);
    unsigned len = sizeof(coap_hdr_t) + tkl;

    if ((len + payload_len + 1) > rlen) {
        return -ENOSPC;
    }

    /* if code is COAP_CODE_EMPTY (zero), use RST as type, else RESP */
    unsigned type = code ? COAP_RESP : COAP_RST;

    coap_build_hdr((coap_hdr_t*)rbuf, type, pkt->token, tkl, code, pkt->hdr->id);
    coap_hdr_set_type((coap_hdr_t*)rbuf, type);
    coap_hdr_set_code((coap_hdr_t*)rbuf, code);

    len += payload_len;

    return len;
}

ssize_t coap_build_hdr(coap_hdr_t *hdr, unsigned type, uint8_t *token, size_t token_len, unsigned code, uint16_t id)
{
    assert(!(type & ~0x3));
    assert(!(token_len & ~0x1f));

    memset(hdr, 0, sizeof(coap_hdr_t));
    hdr->ver_t_tkl = (0x1 << 6) | (type << 4) | token_len;
    hdr->code = code;
    hdr->id = id;

    if (token_len) {
        memcpy(hdr->data, token, token_len);
    }

    return sizeof(coap_hdr_t) + token_len;
}

static int _decode_value(unsigned val, uint8_t **pkt_pos_ptr, uint8_t *pkt_end)
{
    uint8_t *pkt_pos = *pkt_pos_ptr;
    size_t left = pkt_end - pkt_pos;
    int res;
    switch (val) {
        case 13:
            {
            /* An 8-bit unsigned integer follows the initial byte and
               indicates the Option Delta minus 13. */
            if (left < 1) {
                return -ENOSPC;
            }
            uint8_t delta = *pkt_pos++;
            res = delta + 13;
            break;
            }
        case 14:
            {
            /* A 16-bit unsigned integer in network byte order follows
             * the initial byte and indicates the Option Delta minus
             * 269. */
            if (left < 2) {
                return -ENOSPC;
            }
            uint16_t delta;
            uint8_t *_tmp = (uint8_t*)&delta;
            *_tmp++= *pkt_pos++;
            *_tmp++= *pkt_pos++;
            res = ntohs(delta) + 269;
            break;
            }
        case 15:
            /* Reserved for the Payload Marker.  If the field is set to
             * this value but the entire byte is not the payload
             * marker, this MUST be processed as a message format
             * error. */
            return -EBADMSG;
        default:
            res = val;
    }

    *pkt_pos_ptr = pkt_pos;
    return res;
}

static uint32_t _decode_uint(uint8_t *pkt_pos, unsigned nbytes)
{
    assert(nbytes <= 4);

    uint32_t res = 0;
    if (nbytes) {
        memcpy(((uint8_t*)&res) + (4 - nbytes), pkt_pos, nbytes);
    }
    return ntohl(res);
}

static size_t _encode_uint(uint32_t *val)
{
    DEBUG("_encode_uint(): 0x%08x=", *val);
    *val = htonl(*val);
    uint8_t *val8 = (uint8_t *)val;
    for (int i = 0; i < 4; i++) {
        if (!val8[i]) {
            *val >>= i*8;
            DEBUG("0x%0*x\n", (4-i)*2, *val);
            return 4-i;
        }
    }
    return 0;
}

static unsigned _put_delta_optlen(uint8_t *buf, unsigned offset, unsigned shift, unsigned val)
{
    if (val < 13) {
        *buf |= (val << shift);
    }
    else if (val < (256 + 13)) {
        *buf |= (13 << shift);
        buf[offset++] = (val - 13);
    }
    else {
        *buf |= (14 << shift);
        uint16_t tmp = (val - 269);
        tmp = htons(tmp);
        memcpy(buf + offset, &tmp, 2);
        offset += 2;
    }
    return offset;
}

size_t coap_put_option(uint8_t *buf, uint16_t lastonum, uint16_t onum, uint8_t *odata, size_t olen)
{
    assert(lastonum <= onum);

    unsigned delta = (onum - lastonum);
    *buf = 0;

    /* write delta value to option header: 4 upper bits of header (shift 4) +
     * 1 or 2 optional bytes depending on delta value) */
    unsigned n = _put_delta_optlen(buf, 1, 4, delta);
    /* write option length to option header: 4 lower bits of header (shift 0) +
     * 1 or 2 optional bytes depending of the length of the option */
    n = _put_delta_optlen(buf, n, 0, olen);
    if(olen) {
        memcpy(buf + n, odata, olen);
        n += olen;
    }
    return (size_t)n;
}

size_t coap_put_option_ct(uint8_t *buf, uint16_t lastonum, uint16_t content_type)
{
    if (content_type == 0) {
        return coap_put_option(buf, lastonum, COAP_OPT_CONTENT_FORMAT, NULL, 0);
    }
    else if (content_type <= 255) {
        uint8_t tmp = content_type;
        return coap_put_option(buf, lastonum, COAP_OPT_CONTENT_FORMAT, &tmp, sizeof(tmp));
    }
    else {
        return coap_put_option(buf, lastonum, COAP_OPT_CONTENT_FORMAT, (uint8_t*)&content_type, sizeof(content_type));
    }
}

static size_t coap_put_option_block(uint8_t *buf, uint16_t lastonum, unsigned blknum, unsigned szx, int more, uint16_t option)
{
    uint32_t blkopt = (blknum << 4) | szx | (more ? 0x8 : 0);
    size_t olen = _encode_uint(&blkopt);
    return coap_put_option(buf, lastonum, option, (uint8_t*)&blkopt, olen);
}

size_t coap_put_option_block1(uint8_t *buf, uint16_t lastonum, unsigned blknum, unsigned szx, int more)
{
    return coap_put_option_block(buf, lastonum, blknum, szx, more, COAP_OPT_BLOCK1);
}

size_t coap_put_option_uri(uint8_t *buf, uint16_t lastonum, const char *uri, uint16_t optnum)
{
    char separator = (optnum == COAP_OPT_URI_PATH) ? '/' : '&';
    size_t uri_len = strlen(uri);
    if (uri_len == 0) {
        return 0;
    }

    uint8_t *bufpos = buf;
    char *uripos = (char*)uri;

    while(uri_len) {
        size_t part_len;
        uripos++;
        uint8_t *part_start = (uint8_t*)uripos;

        while (uri_len--) {
            if ((*uripos == separator) || (*uripos == '\0')) {
                break;
            }
            uripos++;
        }

        part_len = (uint8_t*)uripos - part_start;

        if (part_len) {
            bufpos += coap_put_option(bufpos, lastonum, optnum, part_start, part_len);
            lastonum = optnum;
        }
    }

    return bufpos - buf;
}

ssize_t coap_well_known_core_default_handler(coap_pkt_t* pkt, uint8_t *buf, \
                                             size_t len)
{
    uint8_t *payload = buf + coap_get_total_hdr_len(pkt);

    uint8_t *bufpos = payload;

    bufpos += coap_put_option_ct(bufpos, 0, COAP_CT_LINK_FORMAT);
    *bufpos++ = 0xff;

    for (unsigned i = 0; i < coap_resources_numof; i++) {
        if (i) {
            *bufpos++ = ',';
        }
        *bufpos++ = '<';
        unsigned url_len = strlen(coap_resources[i].path);
        memcpy(bufpos, coap_resources[i].path, url_len);
        bufpos += url_len;
        *bufpos++ = '>';
    }

    unsigned payload_len = bufpos - payload;

    return coap_build_reply(pkt, COAP_CODE_205, buf, len, payload_len);
}

unsigned coap_get_len(coap_pkt_t *pkt)
{
    unsigned pktlen = sizeof(coap_hdr_t) + coap_get_token_len(pkt);
    if (pkt->payload) {
        pktlen += pkt->payload_len + 1;
    }
    return pktlen;
}
