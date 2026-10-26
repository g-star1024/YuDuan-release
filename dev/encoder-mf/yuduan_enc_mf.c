/*
 * yuduan_enc_mf.c — 御端原生编码器（Windows Media Foundation 后端）
 *
 * 实现 protocol.md §8.3.4 C-ABI 契约（与 encoder-vt / encoder-vaapi 同构）：
 *   void*    yuduan_enc_create (const char* codec, uint32_t width, uint32_t height);
 *   uint32_t yuduan_enc_encode(void* h, const uint8_t* rgba, uint32_t rgba_len,
 *                              uint8_t* out, uint32_t out_cap);
 *   void     yuduan_enc_destroy(void* h);
 *
 * 扩展（不改变上述三符号契约，附加导出）：
 *   uint32_t yuduan_enc_flush(void* h, uint8_t* out, uint32_t out_cap);
 *     —— 冲刷 MFT 管线尾部（DRAIN），把剩余已编码帧交给调用方；
 *        用于需要「末帧不丢」的收尾场景（会话结束 / 离线导出）。
 *
 * 行为：
 *   - 仅接受 "h264"（其余 codec 返回 NULL，能力探测不虚标）；
 *   - 输入 RGBA8，内部 BT.601 转 NV12 喂 MFT（微软 H.264 编码器输入要求 NV12）；
 *   - 输出 Annex-B（MS H264 MFT 在关键帧自带 SPS/PPS in-band，无需手工前置）；
 *   - CBR 码控（YUDUAN_ENC_KBPS 默认 4000），GOP 内 P 帧 + 周期强制关键帧
 *     （ICodecAPI CODECAPI_AVEncVideoForceKeyFrame）；
 *   - 返回写入字节数；out 不足返回 0（该帧留在 pending，扩张后重投交付同一帧）。
 *
 * ⚠️ 出帧模型（Windows 11 / MS H.264 编码 MFT 实测结论，写新后端前必读）：
 *
 *   1) 该 MFT 是**同步** MFT（MF_TRANSFORM_ASYNC=0，不支持 IMFMediaEventGenerator），
 *      且有**固有 12 帧管线延迟**：提交第 N 帧的输出要到提交第 N+12 帧时才被顶出。
 *      实测（16 组 ICodecAPI 配置全扫）：低延迟开关不可用——
 *        CODECAPI_AVEncCommonLowLatency / CODECAPI_AVEncCommonRealTime → E_NOTIMPL(0x80004001)
 *        CODECAPI_AVEncCommonRateControlMode=LowDelayVBR            → E_INVALIDARG(0x80070057)
 *        码控模式 / Profile / QualityVsSpeed / MaxKeyframeDistance / 码率 均不改变延迟。
 *      → 延迟是编码器固有属性，无法通过配置消除。
 *   2) **必须逐帧提交 + 逐帧拉取**：一次性塞 N 帧再 DRAIN 会丢帧
 *      （实测提交 40 帧后 DRAIN 只得到 13 帧——MFT 输入队列有界，超出的输入被拒）。
 *      逐帧提交+逐帧拉取则 40 帧输入无损得到 40 帧输出。
 *   3) 因此本库采用与 encoder-vt 同构的**预置 + 输出队列**方案（§8.3.8）：
 *      create() 提交若干黑帧把 12 帧管线填满并顶出首帧（同时完成「该 codec 真能
 *      出码流」的能力验证，取不到输出即 create 失败、副端诚实回退）；
 *      之后每次 encode() 提交 1 帧、拉取 1 帧，从队列取队首交付。
 *      副作用：码流开头有 12 帧黑帧（含首帧黑 IDR + 参数集，解码器可立即起播），
 *      与 encoder-vt 的「1 帧黑 IDR」同性质，实测带宽影响可忽略（黑 P 帧 ~70~200B）。
 *   4) 管线尾部剩余帧需用 yuduan_enc_flush() 冲刷（或在 destroy 时丢弃）。
 *
 * 构建（Windows 目标机，见 build-windows.cmd）：SDK 头 <mfapi.h> <mfidl.h>
 * <mftransform.h> <icodecapi.h> <codecapi.h> + 链接 mfplat.lib mfuuid.lib
 * ole32.lib oleaut32.lib。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* C-ABI 导出标注。
 * macOS/Linux 侧 clang -dynamiclib 默认导出全部符号，故 encoder-vt/encoder-vaapi
 * 无需标注；Windows DLL 必须显式 __declspec(dllexport)，否则导出表为空，
 * LoadLibraryA + GetProcAddress 取不到 yuduan_enc_*（实机构建时发现）。
 * 语义与其余平台一致：导出 yuduan_enc_create / encode / destroy（+ 扩展 flush）。 */
#if defined(_WIN32)
#define YUDUAN_ENC_API __declspec(dllexport)
#else
#define YUDUAN_ENC_API __attribute__((visibility("default")))
#endif

#ifdef _WIN32
#include <windows.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mfobjects.h>
#include <mftransform.h>
#include <codecapi.h>
#include <icodecapi.h>
#include <combaseapi.h>
#include <Mferror.h>
#include <amvideo.h>   /* VIDEOINFOHEADER 完整定义 */
#else
#include "mfstub.h"
#endif

/* 真 SDK 兼容层（实机构建修复）：
 *  1. ICodecAPI 接口声明在 <icodecapi.h>，<codecapi.h> 只含 GUID 定义；
 *  2. MFSetAttributeSize / MFSetAttributeRatio 在 SDK 中是 __cplusplus 内的
 *     inline 辅助函数，纯 C 编译不可见 —— 用等价的 SetUINT64 实现；
 *  3. PROPVARIANT/VARIANT 的 C 布局成员直接挂在结构体上（C++ 下才是 pv.u.ul），
 *     且 ICodecAPI::SetValue 形参是 VARIANT* 而非 PROPVARIANT*；
 *  4. IID_ICodecAPI 与 CODECAPI_AVEncVideoForceKeyFrame 在 SDK 中只有
 *     EXTERN_C 声明（需 INITGUID + mfuuid.lib 才有定义），此处自包含定义。
 */
#ifndef __cplusplus
/* MF_MT_FRAME_SIZE / MF_MT_FRAME_RATE 的存储语义（见 mfapi.h 注释）：
 *   UINT64，HI32 = 宽(或分子)，LO32 = 高(或分母)。
 *   SDK 自带的 MFSetAttributeSize/MFSetAttributeRatio 是 __cplusplus 内的 inline
 *   辅助函数，纯 C 编译不可见；此处用公开的 SetUINT64 等价实现，
 *   打包顺序与 SDK 的 Pack2UINT32AsUINT64(high32, low32) 一致。 */
static HRESULT yd_set_size(IMFMediaType *a, const GUID *k, UINT32 w, UINT32 h) {
    return a->lpVtbl->SetUINT64(a, k, ((UINT64)w << 32) | (UINT64)h);
}
static HRESULT yd_set_ratio(IMFMediaType *a, const GUID *k, UINT32 num, UINT32 den) {
    return a->lpVtbl->SetUINT64(a, k, ((UINT64)num << 32) | (UINT64)den);
}
#define MFSetAttributeSize  yd_set_size
#define MFSetAttributeRatio yd_set_ratio
#else
/* C++ 下 SDK 自带 inline 版本可用，这里统一到同名实现以免两套写法。 */
static HRESULT yd_set_size(IMFMediaType *a, const GUID *k, UINT32 w, UINT32 h) {
    return MFSetAttributeSize(a, k, w, h);
}
static HRESULT yd_set_ratio(IMFMediaType *a, const GUID *k, UINT32 num, UINT32 den) {
    return MFSetAttributeRatio(a, k, num, den);
}
#endif

#ifdef _WIN32
/* IID_ICodecAPI：{901DB4C7-31CE-41A2-85DC-8FA0BF41B8DA}（MSDN/SDK 一致） */
static const GUID kIID_ICodecAPI =
    {0x901db4c7, 0x31ce, 0x41a2, {0x85, 0xdc, 0x8f, 0xa0, 0xbf, 0x41, 0xb8, 0xda}};
/* CODECAPI_AVEncVideoForceKeyFrame：
 *   {398C1B98-8353-475A-9EF2-8F265D260345}（取自 codecapi.h 的 STATIC_ 分量） */
static const GUID kCODECAPI_AVEncVideoForceKeyFrame =
    {0x398c1b98, 0x8353, 0x475a, {0x9e, 0xf2, 0x8f, 0x26, 0x5d, 0x26, 0x03, 0x45}};
#endif


static int mf_debug(void) {
    static int init = 0, on = 0;
    if (!init) {
        const char *e = getenv("YUDUAN_ENC_DEBUG");
        /* 宽松匹配：cmd 的 `set VAR=1 && cmd` 会把值写成 "1 "（含尾随空格），
         * 严格 strcmp 会让调试开关静默失效，导致排障时看不到任何 HRESULT。 */
        if (e) {
            while (*e == ' ' || *e == '\t') e++;
            on = (*e == '1' || *e == 'y' || *e == 'Y') ? 1 : 0;
        } else {
            on = 0;
        }
        init = 1;
    }
    return on;
}
#define DBG(...) do { if (mf_debug()) fprintf(stderr, "[enc_mf] " __VA_ARGS__); } while (0)

/* 已编码帧队列节点 */
typedef struct frame_node {
    uint8_t *b;
    size_t n;
    struct frame_node *next;
} frame_node;

typedef struct {
    IMFTransform *mft;
    ICodecAPI *codec;
    int com_init;       /* create 中 CoInitializeEx 成功标记 */
    int mf_started;
    int w, h;
    uint8_t *nv12;      /* RGBA->NV12 暂存（w*h*3/2） */
    int64_t frame;      /* 提交给 MFT 的总帧序（含预置黑帧），100ns 时基 */
    int64_t real_frame; /* 真实内容帧序（不含预置黑帧），用于关键帧节奏 */
    int gop;
    DWORD out_cb;       /* GetOutputStreamInfo 的 cbSize（输出缓冲尺寸） */
    DWORD in_id, out_id;
    frame_node *q_head, *q_tail;   /* 已编码帧队列 */
    int q_count;
    uint8_t *pend_b;    /* 重投：已出队但调用方缓冲不足 */
    size_t pend_n;
    int drained;        /* 已 DRAIN：不再提交新帧，只从队列取 */
    int failed;
} mf_enc;

YUDUAN_ENC_API void yuduan_enc_destroy(void *handle);

/* RGBA -> NV12（BT.601 限幅，与 encoder-vaapi 同口径） */
static void rgba_to_nv12(const uint8_t *rgba, int w, int h,
                         uint8_t *yp, int ypitch, uint8_t *uvp, int uvpitch) {
    for (int y = 0; y < h; y++) {
        const uint8_t *row = rgba + (size_t)y * w * 4;
        uint8_t *yrow = yp + (size_t)y * ypitch;
        for (int x = 0; x < w; x++) {
            int r = row[x * 4], g = row[x * 4 + 1], b = row[x * 4 + 2];
            yrow[x] = (uint8_t)(((47 * r + 157 * g + 16 * b) >> 8) + 16);
        }
    }
    for (int y = 0; y < h / 2; y++) {
        const uint8_t *r0 = rgba + (size_t)(y * 2) * w * 4;
        const uint8_t *r1 = r0 + (size_t)w * 4;
        uint8_t *uvrow = uvp + (size_t)y * uvpitch;
        for (int x = 0; x < w / 2; x++) {
            int i = x * 8;
            int r = (r0[i] + r0[i + 4] + r1[i] + r1[i + 4]) >> 2;
            int g = (r0[i + 1] + r0[i + 5] + r1[i + 1] + r1[i + 5]) >> 2;
            int b = (r0[i + 2] + r0[i + 6] + r1[i + 2] + r1[i + 6]) >> 2;
            uvrow[x * 2]     = (uint8_t)(((-26 * r - 87 * g + 112 * b) >> 8) + 128);
            uvrow[x * 2 + 1] = (uint8_t)(((112 * r - 102 * g - 10 * b) >> 8) + 128);
        }
    }
}

/* 队列操作 */
static void q_push(mf_enc *e, uint8_t *b, size_t n) {
    frame_node *node = (frame_node *)malloc(sizeof(frame_node));
    if (!node) { free(b); return; }
    node->b = b; node->n = n; node->next = NULL;
    if (e->q_tail) e->q_tail->next = node; else e->q_head = node;
    e->q_tail = node;
    e->q_count++;
}

static frame_node *q_pop(mf_enc *e) {
    frame_node *n = e->q_head;
    if (!n) return NULL;
    e->q_head = n->next;
    if (!e->q_head) e->q_tail = NULL;
    e->q_count--;
    return n;
}

static void q_clear(mf_enc *e) {
    frame_node *n;
    while ((n = q_pop(e)) != NULL) { free(n->b); free(n); }
}

/* 把 MF 输出 sample 拷贝到新分配的缓冲（成功返回 0，*ob/*on 给出结果） */
static int sample_copy(IMFSample *sample, uint8_t **ob, size_t *on) {
    IMFMediaBuffer *buf = NULL;
    BYTE *data = NULL;
    DWORD len = 0, max = 0;
    *ob = NULL; *on = 0;
    if (sample->lpVtbl->ConvertToContiguousBuffer(sample, &buf) != S_OK) return -1;
    if (buf->lpVtbl->Lock(buf, &data, &max, &len) != S_OK) {
        buf->lpVtbl->Release(buf);
        return -1;
    }
    uint8_t *cp = (uint8_t *)malloc(len ? len : 1);
    if (cp && len) memcpy(cp, data, len);
    buf->lpVtbl->Unlock(buf);
    buf->lpVtbl->Release(buf);
    if (!cp) return -1;
    *ob = cp; *on = len;
    return 0;
}

/* 选可用输出类型：遍历 GetOutputAvailableType 找 H264 子型，并补码率/Profile */
static HRESULT configure_output_type(mf_enc *e) {
    IMFMediaType *t = NULL;
    HRESULT hr;
    for (DWORD idx = 0; idx < 64; idx++) {
        hr = e->mft->lpVtbl->GetOutputAvailableType(e->mft, e->out_id, idx, &t);
        if (hr != S_OK) {
            DBG("GetOutputAvailableType idx=%u hr=0x%08lx (枚举结束)", idx, (unsigned long)hr);
            return hr; /* 枚举尽未找到 */
        }
        GUID sub;
        HRESULT hr_g = t->lpVtbl->GetGUID(t, &MF_MT_SUBTYPE, &sub);
        if (hr_g == S_OK && memcmp(&sub, &MFVideoFormat_H264, sizeof(GUID)) == 0) {
            int kbps = getenv("YUDUAN_ENC_KBPS") ? atoi(getenv("YUDUAN_ENC_KBPS")) : 4000;
            HRESULT hr_b = t->lpVtbl->SetUINT32(t, &MF_MT_AVG_BITRATE, (UINT32)kbps * 1000);
            HRESULT hr_p = t->lpVtbl->SetUINT32(t, &MF_MT_MPEG2_PROFILE,
                                 eAVEncH264VProfile_Base);
            /* 微软 H.264 编码器要求输出类型必须自带分辨率与帧率，
             * 否则 SetOutputType 返回 MF_E_ATTRIBUTENOTFOUND(0xC00D36E6)。 */
            HRESULT hr_fs = yd_set_size(t, &MF_MT_FRAME_SIZE, (UINT32)e->w, (UINT32)e->h);
            HRESULT hr_fr = yd_set_ratio(t, &MF_MT_FRAME_RATE, 30, 1);
            HRESULT hr_it = t->lpVtbl->SetUINT32(t, &MF_MT_INTERLACE_MODE,
                                 MFVideoInterlace_Progressive);
            DBG("out type: bitrate hr=0x%08lx profile hr=0x%08lx size hr=0x%08lx "
                "rate hr=0x%08lx interlace hr=0x%08lx",
                (unsigned long)hr_b, (unsigned long)hr_p,
                (unsigned long)hr_fs, (unsigned long)hr_fr, (unsigned long)hr_it);
            hr = e->mft->lpVtbl->SetOutputType(e->mft, e->out_id, t, 0);
            DBG("SetOutputType hr=0x%08lx", (unsigned long)hr);
            t->lpVtbl->Release(t);
            return hr;
        }
        t->lpVtbl->Release(t);
        t = NULL;
    }
    return E_FAIL;
}

/* 类型协商 + 流启动。
 * 实机结论（Windows 11 / MS H.264 编码 MFT）：
 *  1. SetOutputType 必须在 SetInputType 之前 —— 反序时 MFT 返回
 *     MF_E_TRANSFORM_TYPE_NOT_SET(0xC00D6D60)；
 *  2. 输出类型必须自带 MF_MT_FRAME_SIZE / MF_MT_FRAME_RATE，否则
 *     SetOutputType 返回 MF_E_ATTRIBUTENOTFOUND(0xC00D36E6)；
 *  3. 流启动需 BEGIN_STREAMING → COMMAND_FLUSH → START_OF_STREAM。
 */
static HRESULT configure_types(mf_enc *e) {
    HRESULT hr;

    /* 输出类型：H264 + 码率 + Profile + 分辨率/帧率 */
    hr = configure_output_type(e);
    if (hr != S_OK) {
        DBG("SetOutputType(H264) 失败 hr=0x%08lx", (unsigned long)hr);
        return hr;
    }

    /* 输入类型：NV12 渐进。
     * 优先使用 MFT 自己声明的输入类型（GetInputAvailableType）——编码器在其中
     * 已填好 stride / sample size / fixed-size 等必需属性，只需覆盖尺寸与帧率；
     * 若该 API 不可用，再退回手工构造（VIDEOINFOHEADER 路径）。
     * 手工只设部分属性时，编码器接收输入却恒返回 MF_E_TRANSFORM_NEED_MORE_INPUT
     * （不出帧），这是实机踩到的坑。 */
    IMFMediaType *in = NULL;
    for (DWORD ii = 0; ii < 16; ii++) {
        IMFMediaType *cand = NULL;
        HRESULT hr_i = e->mft->lpVtbl->GetInputAvailableType(e->mft, e->in_id, ii, &cand);
        if (hr_i != S_OK) break;
        GUID isub;
        if (cand->lpVtbl->GetGUID(cand, &MF_MT_SUBTYPE, &isub) == S_OK &&
            memcmp(&isub, &MFVideoFormat_NV12, sizeof(GUID)) == 0) {
            in = cand;
            break;
        }
        cand->lpVtbl->Release(cand);
    }
    if (!in) {
        /* 退路：手工构造 */
        if (MFCreateMediaType(&in) != S_OK) return E_FAIL;
        in->lpVtbl->SetGUID(in, &MF_MT_MAJOR_TYPE, &MFMediaType_Video);
        in->lpVtbl->SetGUID(in, &MF_MT_SUBTYPE, &MFVideoFormat_NV12);
        in->lpVtbl->SetUINT32(in, &MF_MT_FIXED_SIZE_SAMPLES, 1);
        in->lpVtbl->SetUINT32(in, &MF_MT_SAMPLE_SIZE, (UINT32)((size_t)e->w * e->h * 3 / 2));
        DBG("手工构造输入类型（无 GetInputAvailableType）");
    } else {
        DBG("采用 MFT 声明的 NV12 输入类型");
    }
    /* 覆盖尺寸/帧率/渐进模式 */
    MFSetAttributeSize(in, &MF_MT_FRAME_SIZE, (UINT32)e->w, (UINT32)e->h);
    MFSetAttributeRatio(in, &MF_MT_FRAME_RATE, 30, 1);
    in->lpVtbl->SetUINT32(in, &MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive);
    in->lpVtbl->SetUINT32(in, &MF_MT_ALL_SAMPLES_INDEPENDENT, 0);
    hr = e->mft->lpVtbl->SetInputType(e->mft, e->in_id, in, 0);
    in->lpVtbl->Release(in);
    DBG("SetInputType(NV12) hr=0x%08lx", (unsigned long)hr);
    if (hr != S_OK) return hr;

    /* 流启动 */
    e->mft->lpVtbl->ProcessMessage(e->mft, MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0);
    e->mft->lpVtbl->ProcessMessage(e->mft, MFT_MESSAGE_COMMAND_FLUSH, 0);
    e->mft->lpVtbl->ProcessMessage(e->mft, MFT_MESSAGE_NOTIFY_START_OF_STREAM, e->in_id);
    e->mft->lpVtbl->QueryInterface(e->mft, &kIID_ICodecAPI, (void **)&e->codec);
    return S_OK;
}

/* 提交一帧 NV12 到 MFT。src 可为 NULL（表示全黑，用于预置） */
static HRESULT submit_nv12(mf_enc *e, const uint8_t *src) {
    size_t nbytes = (size_t)e->w * e->h * 3 / 2;
    if (!src) {
        /* 黑帧：Y=16（黑电平），UV=128（中性色度） */
        memset(e->nv12, 16, (size_t)e->w * e->h);
        memset(e->nv12 + (size_t)e->w * e->h, 128, (size_t)e->w * e->h / 2);
    } else {
        memcpy(e->nv12, src, nbytes);
    }
    IMFMediaBuffer *ib = NULL;
    IMFSample *sample = NULL;
    HRESULT hr = MFCreateMemoryBuffer((UINT32)nbytes, &ib);
    if (hr != S_OK) return hr;
    BYTE *dst = NULL;
    hr = ib->lpVtbl->Lock(ib, &dst, NULL, NULL);
    if (hr != S_OK) { ib->lpVtbl->Release(ib); return hr; }
    memcpy(dst, e->nv12, nbytes);
    ib->lpVtbl->SetCurrentLength(ib, (DWORD)nbytes);
    ib->lpVtbl->Unlock(ib);
    hr = MFCreateSample(&sample);
    if (hr != S_OK) { ib->lpVtbl->Release(ib); return hr; }
    sample->lpVtbl->AddBuffer(sample, ib);
    sample->lpVtbl->SetSampleTime(sample, e->frame * 333333); /* 30fps，100ns 单位 */
    sample->lpVtbl->SetSampleDuration(sample, 333333);
    hr = e->mft->lpVtbl->ProcessInput(e->mft, e->in_id, sample, 0);
    sample->lpVtbl->Release(sample);
    ib->lpVtbl->Release(ib);
    if (hr == S_OK) e->frame++;
    return hr;
}

/* 拉取 MFT 当前可用的全部输出帧入队，返回本次拉到的帧数 */
static int pull_outputs(mf_enc *e) {
    int got = 0;
    for (int k = 0; k < 256; k++) {
        IMFMediaBuffer *ob = NULL;
        IMFSample *os = NULL;
        if (MFCreateMemoryBuffer(e->out_cb, &ob) != S_OK) break;
        if (MFCreateSample(&os) != S_OK) { ob->lpVtbl->Release(ob); break; }
        os->lpVtbl->AddBuffer(os, ob);
        MFT_OUTPUT_DATA_BUFFER odb; memset(&odb, 0, sizeof(odb));
        odb.dwStreamID = e->out_id;
        odb.pSample = os;
        UINT32 num_pending = 0;
        HRESULT hr = e->mft->lpVtbl->ProcessOutput(e->mft, 0, 1, &odb, &num_pending);
        if (hr == S_OK && odb.pSample) {
            uint8_t *b = NULL; size_t n = 0;
            if (sample_copy(odb.pSample, &b, &n) == 0 && n > 0) {
                q_push(e, b, n);
                got++;
                DBG("frame %lld out=%zu bytes", (long long)(e->frame - 1), n);
            } else {
                free(b);
            }
        }
        if (odb.pSample) odb.pSample->lpVtbl->Release(odb.pSample);
        if (ob) ob->lpVtbl->Release(ob);
        if (hr != S_OK) break;   /* MF_E_TRANSFORM_NEED_MORE_INPUT 等 */
    }
    return got;
}

/* 预置：提交黑帧把 12 帧管线填满并顶出首帧。
 * 返回 0 成功；失败返回 -1（该 codec 真的出不了码流 → create 必须失败）。
 *
 * 预置同时承担能力验证职责（§8.3.8 同构做法）：
 *   ① 吸收编码器冷启动；② 验证该 codec 真能出码流并取到参数集；
 *   ③ 首帧输出留在队列，成为码流首个关键帧被第一次 encode() 取走。 */
static int prime_pipeline(mf_enc *e) {
    /* 上限给足：实测延迟 12 帧 → 需提交 13 帧才能顶出首帧；留出余量。 */
    for (int i = 0; i < 64; i++) {
        HRESULT hr = submit_nv12(e, NULL);
        if (hr != S_OK) {
            DBG("预置提交黑帧失败 i=%d hr=0x%08lx", i, (unsigned long)hr);
            return -1;
        }
        pull_outputs(e);
        if (e->q_count > 0) {
            DBG("预置完成：提交 %d 帧黑帧，队列=%d", i + 1, e->q_count);
            return 0;
        }
    }
    DBG("预置失败：64 帧黑帧仍未顶出任何输出");
    return -1;
}

YUDUAN_ENC_API void *yuduan_enc_create(const char *codec, uint32_t width, uint32_t height) {
    HRESULT hr;
    DBG("create entered codec=%s w=%u h=%u", codec ? codec : "(null)", width, height);
    if (!codec || strcmp(codec, "h264") != 0 || width == 0 || height == 0 ||
        (width % 2) || (height % 2)) {
        DBG("create rejected by arg check");
        return NULL;
    }

    mf_enc *e = (mf_enc *)calloc(1, sizeof(mf_enc));
    if (!e) { DBG("calloc failed"); return NULL; }
    e->w = (int)width; e->h = (int)height;
    e->gop = getenv("YUDUAN_ENC_GOP") ? atoi(getenv("YUDUAN_ENC_GOP")) : 120;
    e->nv12 = (uint8_t *)malloc((size_t)e->w * e->h * 3 / 2);
    if (!e->nv12) { DBG("nv12 alloc failed"); goto fail; }

#ifndef _WIN32
    /* 非 Windows 仅做类型自检，不走真实 MF 初始化 */
    goto fail;
#else
    if (CoInitializeEx(NULL, COINIT_MULTITHREADED) == S_OK) e->com_init = 1;
    else DBG("CoInitializeEx != S_OK (already init)");
    HRESULT hr_s = MFStartup(MF_VERSION, MFSTARTUP_LITE);
    if (hr_s == S_OK) e->mf_started = 1;
    else { DBG("MFStartup 失败 hr=0x%08lx", (unsigned long)hr_s); goto fail; }
    DBG("MFStartup OK");

    /* 枚举同步 MFT 视频编码器（输出 H264）
     * 注：真 SDK 的 MFTEnumEx 首参是 GUID 值传递（不是指针），
     *   末参为 IMFActivate***。
     * 枚举全部（软+硬），逐个尝试激活并打印其属性，避免锁定到
     * 异步硬件 MFT 导致同步管线恒 NEED_MORE_INPUT。 */
    MFT_REGISTER_TYPE_INFO out_info = { MFMediaType_Video, MFVideoFormat_H264 };
    IMFActivate **acts = NULL;
    UINT32 count = 0;
    HRESULT hr_e = MFTEnumEx(MFT_CATEGORY_VIDEO_ENCODER, MFT_ENUM_FLAG_ALL,
                             NULL, &out_info, &acts, &count);
    DBG("MFTEnumEx(ALL) hr=0x%08lx count=%u", (unsigned long)hr_e, count);
    if (hr_e != S_OK || count == 0) {
        DBG("无可用 H264 编码器 MFT（能力探测失败，诚实回退）");
        if (acts) CoTaskMemFree(acts);
        goto fail;
    }
    /* 逐个尝试候选 MFT：激活 → 打印名字 → 类型协商。
     * Windows 10/11 上首选常常是异步硬件编码器（同步管线喂它恒
     * NEED_MORE_INPUT），因此这里遍历全部候选，取第一个协商成功的。 */
    hr = E_FAIL;
    for (UINT32 i = 0; i < count; i++) {
        IMFTransform *mft = NULL;
        HRESULT hr_a = acts[i]->lpVtbl->ActivateObject(acts[i], &IID_IMFTransform, (void **)&mft);
        if (hr_a != S_OK || !mft) {
            DBG("cand[%u] ActivateObject 失败 hr=0x%08lx", i, (unsigned long)hr_a);
            continue;
        }
        {
            IMFAttributes *at = NULL;
            if (mft->lpVtbl->GetAttributes(mft, &at) == S_OK && at) {
                UINT32 is_async = 0;
                at->lpVtbl->GetUINT32(at, &MF_TRANSFORM_ASYNC, &is_async);
                DBG("cand[%u] MF_TRANSFORM_ASYNC=%u", i, is_async);
                at->lpVtbl->Release(at);
            }
        }
        e->mft = mft;
        mft->lpVtbl->GetStreamIDs(mft, 1, &e->in_id, 1, &e->out_id);
        hr = configure_types(e);
        if (hr == S_OK) {
            DBG("cand[%u] 协商成功", i);
            break;
        }
        DBG("cand[%u] 协商失败 hr=0x%08lx", i, (unsigned long)hr);
        e->mft->lpVtbl->Release(e->mft);
        e->mft = NULL;
        hr = E_FAIL;
    }
    for (UINT32 i = 0; i < count; i++) acts[i]->lpVtbl->Release(acts[i]);
    CoTaskMemFree(acts);
    if (!e->mft) { DBG("全部候选 MFT 均协商失败"); goto fail; }

    /* 输出缓冲尺寸必须按 GetOutputStreamInfo 的 cbSize 分配（文档要求），
     * 自行按 w*h 估算会偏小，导致编码帧写不下而始终不出帧。 */
    MFT_OUTPUT_STREAM_INFO si; memset(&si, 0, sizeof(si));
    if (SUCCEEDED(e->mft->lpVtbl->GetOutputStreamInfo(e->mft, e->out_id, &si))) {
        e->out_cb = si.cbSize ? si.cbSize : (DWORD)((size_t)e->w * e->h + (1 << 16));
        DBG("GetOutputStreamInfo flags=0x%08lx cbSize=%u",
            (unsigned long)si.dwFlags, (unsigned long)si.cbSize);
    } else {
        e->out_cb = (DWORD)((size_t)e->w * e->h * 3 / 2);
    }

    /* 预置：填满 12 帧管线并验证该编码器真能出码流 */
    if (prime_pipeline(e) != 0) {
        DBG("预置失败：该 H264 编码器取不到任何输出（能力不宣告）");
        goto fail;
    }

    DBG("create OK %dx%d 管线延迟已由预置吸收", e->w, e->h);
    return e;
#endif

fail:
    yuduan_enc_destroy(e);
    return NULL;
}

YUDUAN_ENC_API uint32_t yuduan_enc_encode(void *handle, const uint8_t *rgba, uint32_t rgba_len,
                           uint8_t *out, uint32_t out_cap) {
    mf_enc *e = (mf_enc *)handle;
    if (!e || e->failed || !out || !out_cap) return 0;

    /* 重投语义：上一帧已出队但调用方缓冲不足，这里原样交付（不重复编码、不乱序）。 */
    if (e->pend_b) {
        if (e->pend_n > out_cap) return 0;
        memcpy(out, e->pend_b, e->pend_n);
        size_t n = e->pend_n;
        free(e->pend_b);
        e->pend_b = NULL; e->pend_n = 0;
        return (uint32_t)n;
    }

#ifndef _WIN32
    (void)rgba; (void)rgba_len;
    return 0;
#else
    if (!e->drained) {
        if (!rgba || rgba_len < (uint32_t)((size_t)e->w * e->h * 4)) return 0;

        /* GOP 关键帧：ICodecAPI 强推
         *    ICodecAPI::SetValue 的第三个形参是 VARIANT*（不是 PROPVARIANT*），
         *    且纯 C 下 VARIANT/PROPVARIANT 都是扁平布局，成员直接挂在结构体上。
         *    故统一用 VARIANT + VariantInit/ulVal，避免类型混用。
         *    节奏按**真实内容帧**计（不含预置黑帧）：真实内容首帧强制 IDR，
         *    之后每 gop 帧一次。预置黑帧本身已由编码器输出 IDR（码流首个关键帧）。 */
        if (e->codec && e->gop > 0 &&
            (e->real_frame == 0 || (e->real_frame % e->gop) == 0)) {
            VARIANT pv; VariantInit(&pv);
            pv.vt = VT_UI4;
            pv.ulVal = 1;
            e->codec->lpVtbl->SetValue(e->codec, &kCODECAPI_AVEncVideoForceKeyFrame, &pv);
            VariantClear(&pv);
        }

        /* RGBA -> NV12 并提交（逐帧提交 + 逐帧拉取：一次性塞多帧会丢帧） */
        rgba_to_nv12(rgba, e->w, e->h, e->nv12, e->w,
                     e->nv12 + (size_t)e->w * e->h, e->w);
        HRESULT hr = submit_nv12(e, e->nv12);
        if (hr != S_OK) {
            DBG("ProcessInput 失败 frame=%lld hr=0x%08lx",
                (long long)e->frame, (unsigned long)hr);
            e->failed = 1;
            return 0;
        }
        e->real_frame++;
        pull_outputs(e);
    }

    /* 从队列取队首交付 */
    frame_node *nd = q_pop(e);
    if (!nd) {
        /* 正常不会发生（预置已吸收 12 帧延迟，稳态每提交一帧即有一帧产出）。
         * 万一发生（编码器异常），返回 0 由上层按丢弃重采处理。 */
        DBG("队列空 frame=%lld", (long long)e->frame);
        return 0;
    }
    if (nd->n > out_cap) {
        e->pend_b = nd->b; e->pend_n = nd->n;   /* 保留：等调用方扩张缓冲后原帧重投 */
        free(nd);
        return 0;
    }
    memcpy(out, nd->b, nd->n);
    uint32_t n = (uint32_t)nd->n;
    free(nd->b);
    free(nd);
    return n;
#endif
}

/* 扩展：冲刷管线尾部（DRAIN），把剩余已编码帧交付给调用方。
 * 返回写入字节数；out 不足时返回 0（该帧留在 pending，重投交付）。 */
YUDUAN_ENC_API uint32_t yuduan_enc_flush(void *handle, uint8_t *out, uint32_t out_cap) {
    mf_enc *e = (mf_enc *)handle;
    if (!e || e->failed) return 0;
#ifndef _WIN32
    (void)out; (void)out_cap;
    return 0;
#else
    if (e->pend_b) {
        if (e->pend_n > out_cap) return 0;
        memcpy(out, e->pend_b, e->pend_n);
        size_t n = e->pend_n;
        free(e->pend_b);
        e->pend_b = NULL; e->pend_n = 0;
        return (uint32_t)n;
    }
    if (!e->drained && e->mft) {
        e->mft->lpVtbl->ProcessMessage(e->mft, MFT_MESSAGE_NOTIFY_END_OF_STREAM, e->in_id);
        e->mft->lpVtbl->ProcessMessage(e->mft, MFT_MESSAGE_COMMAND_DRAIN, e->in_id);
        pull_outputs(e);
        e->drained = 1;
        DBG("flush: 队列剩余 %d 帧", e->q_count);
    }
    frame_node *nd = q_pop(e);
    if (!nd) return 0;
    if (nd->n > out_cap) {
        e->pend_b = nd->b; e->pend_n = nd->n;
        free(nd);
        return 0;
    }
    memcpy(out, nd->b, nd->n);
    uint32_t n = (uint32_t)nd->n;
    free(nd->b);
    free(nd);
    return n;
#endif
}

YUDUAN_ENC_API void yuduan_enc_destroy(void *handle) {
    mf_enc *e = (mf_enc *)handle;
    if (!e) return;
#ifdef _WIN32
    if (e->mft) {
        e->mft->lpVtbl->ProcessMessage(e->mft, MFT_MESSAGE_NOTIFY_END_OF_STREAM, e->in_id);
        e->mft->lpVtbl->ProcessMessage(e->mft, MFT_MESSAGE_NOTIFY_END_STREAMING, 0);
        e->mft->lpVtbl->Release(e->mft);
    }
    if (e->codec) e->codec->lpVtbl->Release(e->codec);
    if (e->mf_started) MFShutdown();
    if (e->com_init) CoUninitialize();
#endif
    q_clear(e);
    free(e->pend_b);
    free(e->nv12);
    free(e);
}
