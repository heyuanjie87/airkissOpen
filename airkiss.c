/*
 * Copyright (c) 2006-2018, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author           Notes
 * 2019-05-16     heyuanjie87      first version
*/

#include "airkiss.h"

#include <string.h>
#include <stdint.h>

#ifdef AIRKISS_LOG_ENABLE
#define AKLOG_D                     \
    if (lc->cfg && lc->cfg->printf) \
    lc->cfg->printf
#else
#define AKLOG_D(...)
#endif

#define AKSTATE_WFG 0
#define AKSTATE_WFM 1
#define AKSTATE_WFP 2
#define AKSTATE_WFD 4
#define AKSTATE_CMP 5

typedef uint16_t akwire_seq_t;

typedef struct
{
    uint16_t val[6];
    uint8_t pos;
    uint8_t scnt; /* 成功计数 */
    uint8_t err;
    uint8_t rcnt; /* 接收计数 */
} akcode_t;

typedef struct
{
    uint8_t id[4];
}akaddr_t;

typedef struct
{
    akwire_seq_t ws;
    uint8_t val[4];
    uint8_t pos : 4;
    uint8_t scnt : 4;
    uint8_t err;
    uint8_t wval;
    uint8_t seqcnt;
    akaddr_t sa;
} akcode_guide_t;

typedef struct
{
    akwire_seq_t ws;
    uint8_t crc;
    uint8_t ind;
}akdatf_seq_t;

typedef struct
{
    union {
        akcode_guide_t code1[3];
        akcode_t code2[1];
    } uc;

    akdatf_seq_t preseq;
    akdatf_seq_t curseq;
    akaddr_t locked;

    uint8_t seqstep;/* 序列增量 */
    uint8_t reclen;
    uint8_t state;
    uint8_t nossid:4;
    uint8_t crcok:4;
    uint8_t seq[16];

    char data[66];
    uint8_t random;
    uint8_t baselen;
    uint8_t prslen;
    uint8_t ssidcrc;
    uint8_t pwdlen;
    const airkiss_config_t *cfg;
} akloc_context_t;

#define AKLOC_CODE1(x, i) ((x)->uc.code1[i])
#define AKLOC_CODE2(x) (&(x)->uc.code2[0])

#define AKLOC_DFSEQ_PREV(lc) ((lc)->preseq)
#define AKLOC_DFSEQ_CUR(lc) ((lc)->curseq)

unsigned char airkiss_crc8(unsigned char *message, unsigned char len)
{
    uint8_t crc = 0;
    uint8_t i;

    while (len--)
    {
        crc ^= *message++;
        for (i = 0; i < 8; i++)
        {
            if (crc & 0x01)
                crc = (crc >> 1) ^ 0x8c;
            else
                crc >>= 1;
        }
    }

    return crc;
}

static akwire_seq_t akwseq_make(uint8_t seq[2])
{
    akwire_seq_t ws = 0;

    ws = (seq[1] << 4) | (seq[0] >> 4);

    return ws;
}

static void akloc_reset(akloc_context_t *lc)
{
    const airkiss_config_t *cfg;

    cfg = lc->cfg;
    memset(lc, 0, sizeof(*lc));
    lc->cfg = cfg;
}

static uint8_t akinfo_getu8(uint16_t v[2])
{
    uint8_t ret = 0;

    ret = ((v[0] & 0xF) << 4) | (v[1] & 0xF);

    return ret;
}

static uint16_t aklen_udp(akloc_context_t *lc, uint16_t len)
{
    return (len - lc->baselen);
}

static int ak_get_magicfield(akloc_context_t *lc, akcode_t *ac)
{
    int ret = 1;

    if (ac->val[0] == 8)
        ac->val[0] = 0;
    lc->prslen = akinfo_getu8(&ac->val[0]);
    lc->ssidcrc = akinfo_getu8(&ac->val[2]);

    if (lc->prslen > (sizeof(lc->data) - 1))
    {
        ret = 0;
        AKLOG_D("prslen(%d) large than(%d)", lc->prslen, (sizeof(lc->data) - 1));
    }

    return ret;
}

static int ak_magicfield_input(akcode_t *ac, uint16_t len)
{
    int mc;

    mc = len >> 4;
    if (mc == 0)
    {
        ac->val[0] = len;
        ac->pos = 1;
    }
    else if (mc == ac->pos)
    {
        ac->val[ac->pos] = len;
        ac->pos ++;
    }
    else
    {
        ac->pos = 0;
    }

    return (ac->pos == 4);
}

static int ak_get_prefixfield(akloc_context_t *lc, akcode_t *ac)
{
    int ret;
    uint8_t crc;

    lc->pwdlen = akinfo_getu8(&ac->val[0]);
    crc = akinfo_getu8(&ac->val[2]);
    if (airkiss_crc8(&lc->pwdlen, 1) != crc)
        ret = 0;

    return ret;
}

static int ak_prefixfield_input(akcode_t *ac, uint16_t len)
{
    int mc;

    mc = len >> 4;
    if (mc == 4)
    {
        ac->val[0] = len;
        ac->pos = 1;
    }
    else if (mc == (ac->pos + 4))
    {
        ac->val[ac->pos] = len;
        ac->pos ++;
    }
    else
    {
        ac->pos = 0;
    }

    return (ac->pos == 4);
}

static int ak_get_datafield(akloc_context_t *lc, akcode_t *ac)
{
    uint8_t tmp[6];
    int n;
    int ret = 0;
    int pos;
    int seqi;

    seqi = ac->val[1] & 0x7f;
    if (seqi > (lc->prslen/4))
    {
        AKLOG_D("data seqi[%X] err\n", ac->val[1]);
        return 0;
    }

    if (lc->seq[seqi])
        return 0;

    pos = seqi * 4;
    n = lc->prslen - pos;
    if (n > 4)
        n = 4;

    tmp[0] = ac->val[0] & 0x7F;
    tmp[1] = ac->val[1] & 0x7F;
    tmp[2] = ac->val[2] & 0xFF;
    tmp[3] = ac->val[3] & 0xFF;
    tmp[4] = ac->val[4] & 0xFF;
    tmp[5] = ac->val[5] & 0xFF;

    ret = ((airkiss_crc8(&tmp[1], n + 1) & 0x7F) == tmp[0]);
    if (ret)
    {
        memcpy(&lc->data[pos], &tmp[2], n);
        lc->reclen += n;
        lc->seq[seqi] = 1;

#ifdef AIRKISS_LOG_GDO_ENABLE
        AKLOG_D("getdata(%d, %d)\n", seqi, n);
#endif
    }

    return ret;
}

static void akaddr_fromframe(akaddr_t *a, uint8_t *f)
{
    f += 10;

    a->id[0] = f[4];
    a->id[1] = f[5];
    a->id[2] = f[10];
    a->id[3] = f[11];
}

static akcode_guide_t *ak_guide_getcode(akloc_context_t *lc, unsigned char *f)
{
    akcode_guide_t *ac;

    if (f == NULL) /* 是模拟测试 */
    {
        ac = &AKLOC_CODE1(lc, 2);
    }
    else
    {
        akaddr_t sa;
        unsigned i;
        int found = 0;
        akcode_guide_t *imin;

        akaddr_fromframe(&sa, f);
        imin = &AKLOC_CODE1(lc, 0);
        ac = imin;
        for (i = 0; i < sizeof(lc->uc.code1) / sizeof(lc->uc.code1[0]); i++)
        {
            /* 匹配地址 */
            found = !memcmp(&sa, &ac->sa, sizeof(ac->sa));
            if (found)
                break;
            /* 记录权值最小的 */
            if (ac->wval < imin->wval)
                imin = ac;
            ac++;
        }

        if (!found)
        {
            /* 淘汰输入最少的 */
            ac = imin;
            ac->pos = 0;
            ac->err = 0;
            ac->scnt = 0;
            ac->wval = 0;
            ac->sa = sa;
        }
    }

    return ac;
}

static int ak_guidefield_input(akcode_guide_t *ac, uint8_t *f, uint16_t len)
{
    akwire_seq_t ws = 0;

    if (f)
        ws = akwseq_make(f + 22);

    if (ac->pos < 4)
    {
        if ((ac->pos != 0) && ((len - ac->val[ac->pos - 1]) != 1))
        {
            ac->pos = 0;
            if (ac->wval > 0)
                ac->wval--;
        }

        if (ac->pos == 0)
        {
            ac->ws = ws;
            ac->seqcnt = 0;
        }
        ac->seqcnt += (ws - ac->ws);

        ac->val[ac->pos] = len;
        ac->pos++;
        ac->wval += ac->pos;
    }

    return (ac->pos == 4);
}

static int ak_waitfor_guidefield(akloc_context_t *lc, uint8_t *f, uint16_t len)
{
    int ret = AIRKISS_STATUS_CONTINUE;
    akcode_guide_t *ac;

    ac = ak_guide_getcode(lc, f);

    if (ak_guidefield_input(ac, f, len))
    {
        ac->pos = 0;
        ac->scnt++;

        /* 至少两次相同的guide code才算获取成功 */
        if ((ac->scnt >= 2) && ac->wval >= 20)
        {
            lc->state = AKSTATE_WFM;
            lc->baselen = ac->val[0] - 1;
            lc->seqstep = ac->seqcnt/6;

            AKLOG_D("guide baselen(%d) seqstep(%d)\n", lc->baselen, lc->seqstep);
        }

        if (lc->state == AKSTATE_WFM)
        {
            lc->locked = ac->sa;
            memset(&lc->uc, 0, sizeof(lc->uc));
            ret = AIRKISS_STATUS_CHANNEL_LOCKED;
        }
    }

    return ret;
}

static int ak_waitfor_magicfield(akloc_context_t *lc, uint16_t len)
{
    int ret = AIRKISS_STATUS_CONTINUE;
    akcode_t *ac = AKLOC_CODE2(lc);
    int udplen;

    udplen = aklen_udp(lc, len);

    if (ak_magicfield_input(ac, udplen))
    {
        ac->pos = 0;

        if (ak_get_magicfield(lc, ac))
        {
            lc->state = AKSTATE_WFP;

            AKLOG_D("magic: prslen(%d) ssidcrc(%X)\n", lc->prslen, lc->ssidcrc);
        }
    }

    if (ac->rcnt++ > 250)
    {
        akloc_reset(lc);
        AKLOG_D("reset from magic\n");
    }

    return ret;
}

static int ak_waitfor_prefixfield(akloc_context_t *lc, uint16_t len)
{
    int ret = AIRKISS_STATUS_CONTINUE;
    akcode_t *ac = AKLOC_CODE2(lc);
    int udplen;

    udplen = aklen_udp(lc, len);

    if (ak_prefixfield_input(ac, udplen))
    {
        ac->pos = 0;

        if (ak_get_prefixfield(lc, ac))
        {
            lc->state = AKSTATE_WFD;

            AKLOG_D("prefix: pwdlen(%d)\n", lc->pwdlen);
        }
    }

    return ret;
}

#ifdef AIRKISS_LOG_DFDUMP_ENABLE
static void akdata_dump(akloc_context_t *lc, uint8_t *f, uint16_t len)
{
    uint8_t seq[2];

    seq[0] = f[22];
    seq[1] = f[23];

    if (len & 0x100)
    {
        AKLOG_D("%02X%02X %X %c", seq[0], seq[1], len, len & 0xff);
    }
    else
    {
        AKLOG_D("%02X%02X %X", seq[0], seq[1], len);
    }
}
#endif

/*
  只判断密码和random是否收完
*/
static int ak_is_pwdrand_complete(akloc_context_t *lc)
{
    int ret = 0;
    unsigned i;
    int n = 0;

    for (i = 0; i < (sizeof(lc->seq) / sizeof(lc->seq[0])); i++)
    {
        if (lc->seq[i] == 0)
            break;

        n += 4;
        if (n >= (lc->pwdlen + 1))
        {
            ret = 1;
            break;
        }
    }

    return ret;
}

static int ak_get_datafield_try(akloc_context_t *lc, akdatf_seq_t *ds)
{
    int ret = 0;
    int pos;
    uint8_t seqi;

    seqi = ds->ind & 0x7f;
    if (lc->seq[seqi] == 0)
    {
        int size = 4;
        char d[6] = {0};
        int i;
        uint8_t crc;

        pos = seqi * 4;
        size = lc->prslen - pos;
        if (size > 4)
            size = 4;

        for (i = 0; i < size; i ++)
        {
            if (lc->data[pos + i] == 0)
                return 0;
        }

        d[0] = seqi;
        memcpy(&d[1], &lc->data[pos], size);
        crc = airkiss_crc8((uint8_t*)d, size + 1) & 0x7f;
        if (crc == (ds->crc & 0x7f))
        {
            lc->seq[seqi] = 1;
            lc->reclen += size;
            ret = 1;

#ifdef AIRKISS_LOG_GTO_ENABLE
            AKLOG_D("found data(%d, %d)[%X,%X,%X,%X]\n", seqi, size, d[1], d[2], d[3], d[4]);
#endif
        }
    }

    return ret;
}

static int ak_dataheader_input(akloc_context_t *lc, akdatf_seq_t *ds, uint16_t len, akwire_seq_t ws)
{
    int ret = 0;

    if (ds->ws == 0)
    {
        ds->ws = ws;
        ds->crc = len;
    }
    else
    {
        akwire_seq_t offs;

        offs = (ws - ds->ws)/lc->seqstep;
        if (offs < 2)
        {
            /* 正确的包头 */
            ds->ind = len;
            /* 保存它 */
            AKLOC_DFSEQ_PREV(lc) = *ds;
        }
        else if (offs == 6)
        {
            /* 下一个包头 */
            ds->ws = ws;
            ds->crc = len;
            ds->ind = 0;
        }
        else
        {
            /* 包头错误 */
            ds->ws = 0;
            ds->crc = 0;
            ds->ind = 0;
        }
    }

    return ret;
}

static int ak_seq_getpos(akloc_context_t *lc, akdatf_seq_t *ds, akwire_seq_t ws)
{
    int pos = -1;
    akwire_seq_t off802;
    int offmax;

    /* 无效包头 */
    if (ds->ind == 0)
        return -1;

    /* 与上个包头的80211帧偏差 */
    off802 = ws - ds->ws;
    off802 /= lc->seqstep;
    /* 数据最大偏差 */
    offmax = lc->prslen + ((lc->prslen + 3)/4) * 2;
    if (off802 < offmax)
    {
        int i;

        i = (off802 % 6) + ((off802 / 6) * 4);
        if (i > 1)
            pos = ((ds->ind & 0x7f) * 4) + i - 2;
    }

    return pos;
}

static int ak_databody_input(akloc_context_t *lc, akdatf_seq_t *ds, uint16_t len, akwire_seq_t ws)
{
    int ret = 0;

    if (ds->ind != 0) /* 有包头 */
    {
        int seqi;

        seqi = ds->ind & 0x7f;
        if (lc->seq[seqi] == 0)
        {
            int pos;

            pos = ak_seq_getpos(lc, ds, ws);
            if (pos != -1)
            {
                lc->data[pos] = len & 0xFF;

#ifdef AIRKISS_LOG_DIWSO_ENABLE
                AKLOG_D("input(%d) %c", pos, lc->data[pos]);
#endif
                ak_get_datafield_try(lc, ds);
            }
         }  
    }
    else
    {
        memset(ds, 0, sizeof(*ds));
    }

    return ret;
}

static void ak_datainput_withwireseq(akloc_context_t *lc, uint8_t *f, uint16_t len)
{
    uint8_t *seq;
    akwire_seq_t ws;
    akdatf_seq_t *ds;

    ds = &AKLOC_DFSEQ_CUR(lc);
    ws = akwseq_make(f + 22);

    if (len & 0x100)
    {
        ak_databody_input(lc, ds, len, ws);
    }
    else
    {
        ak_dataheader_input(lc, ds, len, ws);
    }

    if (lc->reclen == lc->prslen)
        lc->state = AKSTATE_CMP;
}

static int ak_datainput_onlylength(akloc_context_t *lc, akcode_t *ac, uint16_t len)
{
    int n = 6;

    if (len & 0x100)
    {
        if (ac->pos > 1)
        {
            int size;

            ac->val[ac->pos] = len;
            ac->pos ++;

            size = (ac->val[1] & 0x7f) * 4;
            if (size <  lc->prslen)
            {
                size = lc->prslen - size;
                if (size < 4) /* 最后一个包不足4 */
                {
                    n = size + 2;
                }
            }
        }
        else
        {
            ac->pos = 0;
        }
    }
    else
    {
        if (ac->pos < 2)
        {
            ac->val[ac->pos] = len;
            ac->pos ++;
        }
        else
        {
            ac->val[0] = len;
            ac->pos = 1;
        }
    }

    return (ac->pos == n);
}

static int ak_waitfor_datafield(akloc_context_t *lc, uint8_t *f, uint16_t len, int nossid)
{
    int ret = AIRKISS_STATUS_CONTINUE;
    akcode_t *ac = AKLOC_CODE2(lc);
    uint16_t udplen;

    udplen = aklen_udp(lc, len);
    if (udplen < 0x80)
    {
        return ret;
    }

#ifdef AIRKISS_LOG_DFDUMP_ENABLE
    if (f)
        akdata_dump(lc, f, udplen);
#endif

    if (ak_datainput_onlylength(lc, ac, udplen))
    {
        ac->pos = 0;

        ak_get_datafield(lc, ac);

        if (lc->reclen == lc->prslen)
        {
            lc->state = AKSTATE_CMP;
            goto _out;
        }
    }

    if (f)
    {
        ak_datainput_withwireseq(lc, f, udplen);
    }

    if (nossid && ak_is_pwdrand_complete(lc))
    {
        lc->state = AKSTATE_CMP;
        AKLOG_D("data complete nossid\n");
    }

_out:
    if (lc->state == AKSTATE_CMP)
    {
        lc->nossid = nossid;
        ret = AIRKISS_STATUS_COMPLETE;
    }

    return ret;
}

static int ak_sa_filter(akloc_context_t *lc, uint8_t *f)
{
    int ret = 0;

    if (lc->state != AKSTATE_WFG)
    {
        akaddr_t sa;

        akaddr_fromframe(&sa, f);
        ret = memcmp(&lc->locked, &sa, sizeof(sa));
    }

    return ret;
}

int airkiss_filter(const void *f, int len)
{
    int ret = 0;
    unsigned char *da, *p;
    int i;

    p = (unsigned char *)f;
    if ((len < 25) || (p[0] != 0x08))
        return 1;

    da = p + 4;

    for (i = 0; i < 6; i++)
    {
        if (da[i] != 0xFF)
        {
            ret = 1;
            break;
        }
    }

    return ret;
}

static int _ak_recv(airkiss_context_t *c, const void *frame, uint16_t length, int nossid)
{
    int ret = AIRKISS_STATUS_CONTINUE;
    akloc_context_t *lc = (akloc_context_t *)c;
    unsigned char *f = (unsigned char *)frame;

    if (frame != NULL) /* 模拟测试时可只传length */
    {
        if (airkiss_filter(frame, length))
            return ret;
        if (ak_sa_filter(lc, f))
            return ret;
    }

    switch (lc->state)
    {
    case AKSTATE_WFG:
    {
        ret = ak_waitfor_guidefield(lc, f, length);
    }
    break;
    case AKSTATE_WFM:
    {
        ret = ak_waitfor_magicfield(lc, length);
    }
    break;
    case AKSTATE_WFP:
    {
        ret = ak_waitfor_prefixfield(lc, length);
    }
    break;
    case AKSTATE_WFD:
    {
        ret = ak_waitfor_datafield(lc, f, length, nossid);
    }
    break;
    case AKSTATE_CMP:
    {
        ret = AIRKISS_STATUS_COMPLETE;
    }
    break;
    }

    return ret;
}

const char *airkiss_version(void)
{
    return "airkiss-1.0.0-open";
}

int airkiss_init(airkiss_context_t *c, const airkiss_config_t *config)
{
    akloc_context_t *lc = (akloc_context_t *)c;

    lc->cfg = config;
    akloc_reset(lc);

    return 0;
}

int airkiss_recv(airkiss_context_t *c, const void *frame, unsigned short length)
{
    return _ak_recv(c, frame, length, 0);
}

int airkiss_get_result(airkiss_context_t *c, airkiss_result_t *res)
{
    akloc_context_t *lc = (akloc_context_t *)c;

    if (lc->state != AKSTATE_CMP)
        return -1;

    res->pwd = (char *)&lc->data[0];
    res->pwd_length = lc->pwdlen;
    if (lc->data[lc->pwdlen] == 0)
    {
        res->random = lc->random;
    }
    else
    {
        res->random = lc->data[lc->pwdlen];
        lc->random = lc->data[lc->pwdlen];
        lc->data[lc->pwdlen] = 0;
    }

    res->ssid_crc = lc->ssidcrc;
    if (lc->nossid)
    {
        res->ssid = "";
        res->ssid_length = 0;
    }
    else
    {
        res->ssid = (char *)&lc->data[lc->pwdlen + 1];
        res->ssid_length = lc->prslen - lc->pwdlen - 1;
    }
    lc->data[lc->prslen] = 0;

    return 0;
}

int airkiss_recv_nossid(airkiss_context_t *c, const void *frame, unsigned short length)
{
    return _ak_recv(c, frame, length, 1);
}

int airkiss_change_channel(airkiss_context_t *c)
{
    akloc_context_t *lc = (akloc_context_t *)c;

    akloc_reset(lc);

    return 0;
}
