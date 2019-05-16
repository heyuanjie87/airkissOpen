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

typedef struct
{
    uint16_t val[6];
    uint8_t pos;
    uint8_t scnt;
    uint8_t err;
} akcode_t;

typedef struct
{
    uint8_t val[4];
    uint8_t pos : 4;
    uint8_t scnt : 4;
    uint8_t err;
    uint16_t icnt;
    uint8_t sa[12];
} akcode_guide_t;

typedef struct
{
    union {
        akcode_guide_t code1[3];
        akcode_t code2[2];
    } uc;

    uint8_t reclen;
    uint8_t state;
    uint8_t nossid;
    char seq[16];

    uint8_t data[66];
    uint8_t random;
    uint8_t baselen;
    uint8_t prslen;
    uint8_t ssidcrc;
    uint8_t pwdlen;
    uint8_t pwdcrc;
    const airkiss_config_t *cfg;
} akloc_context_t;

#define AKLOC_CODE1(x, i) ((x)->uc.code1[i])
#define AKLOC_CODE2(x) (&(x)->uc.code2[0])
#define AKLOC_CODE3(x) (&(x)->uc.code2[1])

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

static void akloc_reset(akloc_context_t *lc)
{
    lc->state = 0;
    lc->reclen = 0;
    lc->baselen = 0;
    memset(lc->seq, 0xff, sizeof(lc->seq));
    memset(&lc->uc, 0, sizeof(lc->uc));
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

static int aklen_input(akloc_context_t *lc, akcode_t *ac, int fmlen, int num)
{
    if (ac->pos < num)
    {
        ac->val[ac->pos] = aklen_udp(lc, fmlen);
        ac->pos++;
    }

    return (ac->pos == num);
}

static void ak_codemve(akcode_t *ac, int pos, int n)
{
    int i;

    for (i = 0; i < n; i++)
    {
        ac->val[i] = ac->val[pos + i];
    }
    ac->pos = n;
}

static int akseq_num(akloc_context_t *lc)
{
    int n;

    n = lc->prslen - lc->reclen;
    if (n > 4)
        n = 6;
    else if (n != 0)
        n += 2;

    return n;
}

static int akseq_input(akloc_context_t *lc, uint8_t *d, int n, int seqi)
{
    int i;
    int ret;
AKLOG_D("seqi %d", seqi);
    if (lc->seq[seqi] != seqi)
    {
        int pos;

        lc->seq[seqi] = seqi;
        n -= 2;
        pos = seqi * 4;

        for (i = 0; i < n; i++)
        {
            lc->data[pos] = d[i];
            lc->reclen++;
            pos++;
        }
    }

    ret = lc->prslen - lc->reclen;

    return ret;
}

static int ak_is_guidefield(akcode_t *ac)
{
    int ret = 0;

    if ((ac->val[1] - ac->val[0] == 1) &&
        (ac->val[2] - ac->val[0] == 2) &&
        (ac->val[3] - ac->val[0] == 3))
    {
        ret = 1;
    }

    return ret;
}

/*
  在接收magicfield阶段检查是否收到乱序的guide code
*/
static int ak_is_guidefield_errseq(akcode_t *ac)
{
    int ret = 0;

    if ((ac->val[0] < 5) &&
        (ac->val[1] < 5) &&
        (ac->val[2] < 5) &&
        (ac->val[3] < 5))
    {
        ret = 1;
    }

    return ret;
}

/*
  在4个包中从指定位置找出符合magicfield的序列
*/
static int ak_is_magicfield_corseq(akcode_t *ac, int pos, int n)
{
    int ret;
    uint8_t v[4];
    uint8_t vd[4] = {0, 1, 2, 3};
    int i;

    for (i = 0; i < n; i++)
    {
        v[i] = ac->val[pos + i] >> 4;
    }
    ret = !memcmp(v, vd, n);

    return ret;
}

/*
  检查是否是错误的magicfield序列
*/
static int ak_is_magicfield_errseq(akcode_t *ac)
{
    int i;

    for (i = 0; i < 4; i++)
    {
        if ((ac->val[i] >> 4) > 3)
            break;
    }

    return (i == 4);
}

/*
  剔除错误的magicfield序列
*/
static int ak_realign_magicfield(akcode_t *ac)
{
    int r = 1;

    while (r < 4)
    {
        if (ak_is_magicfield_corseq(ac, r, 4 - r))
        {
            ak_codemve(ac, r, 4 - r);
            r = -1;
            break;
        }

        r++;
    }

    return (r == -1);
}

static int ak_get_magicfield(akloc_context_t *lc, akcode_t *ac)
{
    int ret;

    if ((ret = ak_is_magicfield_corseq(ac, 0, 4)) != 0)
    {
        if (ac->val[0] == 8)
            ac->val[0] = 0;
        lc->prslen = akinfo_getu8(&ac->val[0]);
        lc->ssidcrc = akinfo_getu8(&ac->val[2]);
    }

    return ret;
}

static int ak_is_prefixfield_corseq(akcode_t *ac, int pos, int n)
{
    uint8_t v[4];
    uint8_t vd[4] = {4, 5, 6, 7};
    int i;
    int ret;

    for (i = 0; i < n; i++)
    {
        v[i] = ac->val[pos + i] >> 4;
    }

    ret = !memcmp(v, vd, n);

    return ret;
}

static int ak_get_prefixfield(akloc_context_t *lc, akcode_t *ac)
{
    int ret;

    if ((ret = ak_is_prefixfield_corseq(ac, 0, 4)) != 0)
    {
        lc->pwdlen = akinfo_getu8(&ac->val[0]);
        lc->pwdcrc = akinfo_getu8(&ac->val[2]);
    }

    return ret;
}

static int ak_realign_prefixfield(akcode_t *ac)
{
    int r;

    r = 1;
    while (r < 4)
    {
        if (ak_is_prefixfield_corseq(ac, r, 4 - r))
        {
            ak_codemve(ac, r, 4 - r);
            r = -1;
            break;
        }

        r++;
    }

    return (r == -1);
}

static int ak_is_datafield_corseq(akcode_t *ac, int pos, int n)
{
    int ret;
    int i;
    uint8_t v[6];
    uint8_t vd[6] = {1, 1, 2, 2, 2, 2};

    for (i = 0; i < n; i++)
    {
        if (i < 2)
            v[i] = ac->val[i + pos] >> 7;
        else
            v[i] = (ac->val[i + pos] & 0x100) >> 7;
    }

    ret = !memcmp(v, vd, n);

    return ret;
}

static int ak_get_datafield(akcode_t *ac, uint8_t data[4], int *seqi, int n)
{
    int i = 0;
    int fail = 1;
    uint8_t tmp[6] = {0};

    if (n < 3 || n > 6)
        goto _out;
    if (!ak_is_datafield_corseq(ac, 0, n))
        goto _out;

    tmp[0] = ac->val[i++] & 0x7F;
    tmp[1] = ac->val[i++] & 0x7F;
    tmp[2] = ac->val[i++] & 0xFF;
    tmp[3] = ac->val[i++] & 0xFF;
    tmp[4] = ac->val[i++] & 0xFF;
    tmp[5] = ac->val[i++] & 0xFF;

    fail = ((airkiss_crc8(&tmp[1], n - 1) & 0x7F) != tmp[0]);
    if (!fail)
    {
        memcpy(data, &tmp[2], 4);
        *seqi = tmp[1];
    }

_out:
    return (!fail);
}

static int ak_realign_datafield(akcode_t *ac)
{
    int r = 1;

    while (r < 6)
    {
        if (ak_is_datafield_corseq(ac, r, 6 - r))
        {
            ak_codemve(ac, r, 6 - r);
            r = -1;
            break;
        }

        r++;
    }

    return (r == -1);
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
        unsigned char *sa;
        unsigned i;
        int found = 0;
        akcode_guide_t *imin;

        sa = f + 10;
        imin = &AKLOC_CODE1(lc, 0);
        ac = imin;
        for (i = 0; i < sizeof(lc->uc.code1) / sizeof(lc->uc.code1[0]); i++)
        {
            /* 匹配地址 */
            found = !memcmp(ac->sa, sa, sizeof(ac->sa));
            if (found)
                break;
            /* 记录输入最少的 */
            if (ac->icnt < imin->icnt)
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
            ac->icnt = 0;
            memcpy(ac->sa, sa, sizeof(ac->sa));
        }
    }

    return ac;
}

static int ak_guidefield_input(akcode_guide_t *ac, uint16_t len)
{
    if (ac->pos < 4)
    {
        if ((ac->pos != 0) && ((len - ac->val[ac->pos - 1]) != 1))
        {
            ac->pos = 0;
            if (ac->icnt > 0)
                ac->icnt--;
        }

        ac->val[ac->pos] = len;
        ac->pos++;
        ac->icnt += ac->pos;
    }

    return (ac->pos == 4);
}

static int ak_waitfor_guidefield(akloc_context_t *lc, uint8_t *f, uint16_t len)
{
    int ret = AIRKISS_STATUS_CONTINUE;
    akcode_guide_t *ac;

    ac = ak_guide_getcode(lc, f);

    if (ak_guidefield_input(ac, len))
    {
        ac->pos = 0;
        ac->scnt++;

        /* 至少两次相同的guide code才算获取成功 */
        if ((ac->scnt >= 2) && ac->icnt >= 20)
        {
            lc->state = AKSTATE_WFM;
            lc->baselen = ac->val[0] - 1;
            ac->scnt = 0;
            ac->err = 0;
            ac->icnt = 0;

            AKLOG_D("guide baselen %d\n", lc->baselen);
        }
    }

    if (lc->state == AKSTATE_WFM)
    {
        if (ac != &AKLOC_CODE1(lc, 2))
        {
            memcpy(AKLOC_CODE1(lc, 2).sa, ac->sa, sizeof(ac->sa));
        }
        memset(AKLOC_CODE2(lc), 0, sizeof(akcode_t) * 2);
        ret = AIRKISS_STATUS_CHANNEL_LOCKED;
    }

    return ret;
}

static int ak_waitfor_magicfield(akloc_context_t *lc, uint16_t len)
{
    int ret = AIRKISS_STATUS_CONTINUE;
    akcode_t *ac = AKLOC_CODE2(lc);

    if (aklen_input(lc, ac, len, 4))
    {
        ac->pos = 0;

        if (ak_get_magicfield(lc, ac))
        {
            lc->state = AKSTATE_WFP;
            ac->err = 0;

            AKLOG_D("magic: prslen(%d) ssidcrc(%X)\n", lc->prslen, lc->ssidcrc);
        }
        else if (ak_is_guidefield(ac) ||
                 ak_is_guidefield_errseq(ac))
        {
            /* 收到的还是或乱序的guidecode则忽略 */
        }
        else if (ak_realign_magicfield(ac))
        {
            /* 保留符合要求的序列 */
        }
        else
        {
            if (ac->err++ > 6)
            {
                akloc_reset(lc);
                AKLOG_D("airkiis reset from magic\n");
            }
        }
    }

    return ret;
}

static int ak_waitfor_prefixfield(akloc_context_t *lc, uint16_t len)
{
    int ret = AIRKISS_STATUS_CONTINUE;
    akcode_t *ac = AKLOC_CODE2(lc);

    if (aklen_input(lc, ac, len, 4))
    {
        ac->pos = 0;

        if (ak_get_prefixfield(lc, ac))
        {
            lc->state = AKSTATE_WFD;
            ac->err = 0;

            AKLOG_D("prefix: pwdlen(%d) pwdcrc(%X)\n", lc->pwdlen, lc->pwdcrc);
        }
        else if (ak_is_magicfield_corseq(ac, 0, 4) ||
                 ak_is_magicfield_errseq(ac))
        {
            /* 收到magicfield 忽略 */
        }
        else if (ak_realign_prefixfield(ac))
        {
            /* 保留符合要求的 */
        }
        else
        {
            if (ac->err++ > 5)
            {
                akloc_reset(lc);
                AKLOG_D("airkiss reset from prefix");
            }
        }
    }

    return ret;
}

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
        if (lc->seq[i] == 0xff)
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

static int _datafield_input(akloc_context_t *lc, akcode_t *ac, uint16_t len, int n, int nossid)
{
    int ret = 0;

    if (n && aklen_input(lc, ac, len, n))
    {
        uint8_t data[4];
        int seqi;

        ac->pos = 0;

        if ((ret = ak_get_datafield(ac, data, &seqi, n)) == 1)
        {
            if (akseq_input(lc, data, n, seqi) == 0)
            {
                lc->state = AKSTATE_CMP;

                AKLOG_D("data complete %d\n", n);
            }
            else if (nossid && ak_is_pwdrand_complete(lc))
            {
                lc->state = AKSTATE_CMP;

                AKLOG_D("data nossid complete\n");
            }
        }
        else
        {
            if (!ak_realign_datafield(ac))
            {
                ac->err++;
            }
        }
    }

    return ret;
}

static int ak_waitfor_datafield(akloc_context_t *lc, uint16_t len, int nossid)
{
    int ret = AIRKISS_STATUS_CONTINUE;
    akcode_t *ac = AKLOC_CODE2(lc);
    int n;
    uint16_t udplen;

    udplen = aklen_udp(lc, len);
    if (udplen < 0x80)
    {
        return ret;
    }

    if (udplen & 0x100)
    {
        AKLOG_D("<%X> %c", udplen, udplen&0xff);
    }
    else
    {
        AKLOG_D("<%X>", udplen);
    }

    n = lc->prslen & 0x03;
    if (n && (lc->prslen > 8) && !nossid)
    {
        akcode_t *ac3 = AKLOC_CODE3(lc);

        if (_datafield_input(lc, ac3, len, n + 2, 0))
        {
            if ((n = akseq_num(lc)) == 0)
                goto _out;
            ac->pos = 0;

            return ret;
        }
    }

    /* 期望当前序列的包数(6, <6, 0) */
    n = akseq_num(lc);

    _datafield_input(lc, ac, len, n, nossid);
    if (ac->err > 20)
    {
        akloc_reset(lc);
        AKLOG_D("airkiss reset from data\n");
    }

_out:
    if ((lc->state == AKSTATE_CMP) || (n == 0))
    {
        lc->nossid = nossid;
        lc->state = AKSTATE_CMP;
        ret = AIRKISS_STATUS_COMPLETE;
    }

    return ret;
}

static int ak_sa_filter(akloc_context_t *lc, uint8_t *f)
{
    unsigned char *sa;

    sa = f + 10;
    return memcmp(AKLOC_CODE1(lc, 2).sa, sa, sizeof(AKLOC_CODE1(lc, 2).sa));
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
        if ((lc->state != AKSTATE_WFG) && ak_sa_filter(lc, f))
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
        ret = ak_waitfor_datafield(lc, length, nossid);
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
