/*
 * yuduan_enc_vt.c — 御端原生编码器（macOS VideoToolbox 后端）
 *
 * 实现 protocol.md §8.3.3 C-ABI 契约：
 *   void*    yuduan_enc_create (const char* codec, uint32_t width, uint32_t height);
 *   uint32_t yuduan_enc_encode(void* h, const uint8_t* rgba, uint32_t rgba_len,
 *                              uint8_t* out, uint32_t out_cap);
 *   void     yuduan_enc_destroy(void* h);
 * §8.3.15 可选导出（码率重参数化）：
 *   void     yuduan_enc_set_bitrate(void* h, uint32_t kbps);
 *
 * 行为：
 *   - 仅接受 "h264" / "h265"（其余 codec 返回 NULL，供能力探测不虚标）；
 *   - 输入 RGBA8（紧凑，w*h*4 字节），内部转 BGRA 喂 VideoToolbox；
 *   - 输出 Annex-B（00 00 00 01 起始码）；参数集（H.264: SPS/PPS；HEVC: VPS/SPS/PPS）
 *     从输出样缓冲的 FormatDescription 提取，随关键帧前置（解码器可随时起播）；
 *   - 返回写入字节数；out 不足返回 0 并把该帧留在 pending，调用方扩张后原帧重投
 *     （不重复编码，不改变输出顺序）。
 *
 * VideoToolbox 出帧模型（本机实测，两个必须绕开的坑）：
 *   ① **固定 1 帧管线延迟**：提交第 N 帧不会立刻回调，第 N-1 帧的输出是在提交第 N
 *      帧时才被"顶"出来的。因此同步地「提交一帧→死等它自己的回调」必然超时挂起。
 *      → 本实现采用 **队列 + 预置帧**：create() 先提交一帧黑帧做**预置**（同时吸收
 *        编码器冷启动），此后每次 encode()「提交新帧 → 取回上一帧输出」，既有迟到
 *        保护又不空转；代价是输出比输入滞后 1 帧（≈ 1 个采集周期），远控可接受。
 *   ② **CompleteFrames 会把被推出的帧变成 IDR**：实测每帧 flush ⇒ 每帧 20KB+ 全关键
 *      帧；不 flush ⇒ 首帧 IDR、后续 P 帧仅 300~600 字节（带宽差一个数量级）。
 *      → 稳态**不 flush**，仅在管线饥饿（异常/长时间未出帧）时兜底强推一次。
 *
 * 构建（见 build.sh）：
 *   clang -dynamiclib -O2 -framework VideoToolbox -framework CoreMedia \
 *         -framework CoreFoundation -framework CoreVideo yuduan_enc_vt.c -o libyuduan_enc_vt.dylib
 *
 * 环境变量：
 *   YUDUAN_ENC_DEBUG=1  打印会话创建/出帧各阶段 OSStatus 与时序（排障用，生产关闭）
 *   YUDUAN_ENC_HW=0|1   0=强制软件编码器，1=强制硬件编码器，未设置=系统启发式
 *                       （实测本机软件 H.264 会话不回调，故**默认不强制**）
 */

#include <VideoToolbox/VideoToolbox.h>
#include <CoreMedia/CoreMedia.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CoreVideo/CoreVideo.h>
#include <dispatch/dispatch.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define VT_WAIT_SEC 30      /* 兜底：管线饥饿强推后仍未拿到输出的等待上限 */
#define VT_PIPE_WAIT_MS 500 /* 正常出帧等待窗口（超时判定为管线饥饿） */

/* 诊断输出：YUDUAN_ENC_DEBUG=1 时打印各阶段 OSStatus 与时序。 */
static int vt_debug(void) {
    static int init = 0, on = 0;
    if (!init) {
        const char *e = getenv("YUDUAN_ENC_DEBUG");
        on = (e && (strcmp(e, "1") == 0 || strcasecmp(e, "true") == 0)) ? 1 : 0;
        init = 1;
    }
    return on;
}
#define DBG(...) do { if (vt_debug()) fprintf(stderr, "[enc_vt] " __VA_ARGS__); } while (0)

#include <stdio.h>

void yuduan_enc_destroy(void *handle); /* 前置声明（create 失败清理用） */
void yuduan_enc_set_bitrate(void *handle, uint32_t kbps); /* §8.3.15 可选导出 */

/* 输出队列节点：回调即时入队，encode() 取队首（管线出帧，顺序与输入一致） */
typedef struct outnode {
    uint8_t *b;
    size_t n;
    struct outnode *next;
} outnode;

typedef struct {
    VTCompressionSessionRef session;
    dispatch_semaphore_t sem;     /* 回调到达信号 */
    outnode *qh, *qt;             /* 已编码输出队列 */
    outnode *pending;             /* 已出队但因调用方缓冲不足待原样重投的帧 */
    uint8_t *ps_buf;              /* 参数集（含起始码），随关键帧输出前置 */
    size_t ps_len;
    int ps_known;                 /* 参数集是否已取得 */
    int w, h;
    long frame;                   /* 帧序号（时间戳用） */
    long frame_seq;               /* 提交序号（回调打点用） */
    CMVideoCodecType ctype;       /* kCMVideoCodecType_H264 / HEVC */
    int failed;
    /* 回调到达计数（create 阶段验证用）。

     * 重要：不要按代次丢弃回调——VideoToolbox 出帧滞后 1 帧，
     * 上一次提交的输出正是下一次 encode() 要取走的货，按代次过滤会把
     * 整条管线饿到只能靠 CompleteFrames 强推（每帧 IDR，带宽暴涨 10 倍）。 */
    volatile int cb_arrived;
} vt_enc;

static const uint8_t SC4[4] = {0x00, 0x00, 0x00, 0x01};

/* 追加字节；内存不足返回 -1 */
static int buf_append(uint8_t **buf, size_t *cap, size_t *len, const uint8_t *p, size_t n) {
    if (*len + n > *cap) {
        size_t ncap = *cap ? *cap * 2 : 1 << 16;
        while (ncap < *len + n) ncap *= 2;
        uint8_t *nb = realloc(*buf, ncap);
        if (!nb) return -1;
        *buf = nb;
        *cap = ncap;
    }
    memcpy(*buf + *len, p, n);
    *len += n;
    return 0;
}

/* 从格式描述提取参数集（H.264: SPS+PPS；HEVC: VPS/SPS/PPS），Annex-B 前缀后追加 */
static void emit_parameter_sets(uint8_t **buf, size_t *cap, size_t *len, CMVideoCodecType ctype,
                                CMFormatDescriptionRef desc) {
    const uint8_t *ps[3];
    size_t pslen[3];
    size_t cnt = 0;
    if (ctype == kCMVideoCodecType_H264) {
        for (int i = 0; i < 2 && cnt < 3; i++) {
            if (CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
                    desc, i, &ps[cnt], &pslen[cnt], NULL, NULL) == noErr) {
                cnt++;
            }
        }
    } else {
        for (int i = 0; i < 3 && cnt < 3; i++) {
            if (CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(
                    desc, i, &ps[cnt], &pslen[cnt], NULL, NULL) == noErr) {
                cnt++;
            }
        }
    }
    for (size_t i = 0; i < cnt; i++) {
        buf_append(buf, cap, len, SC4, 4);
        buf_append(buf, cap, len, ps[i], pslen[i]);
    }
}

/* AVCC（4 字节长度前缀 NALU 序列）→ Annex-B */
static void emit_avcc_as_annexb(uint8_t **buf, size_t *cap, size_t *len,
                                const uint8_t *data, size_t n) {
    size_t off = 0;
    while (off + 4 <= n) {
        uint32_t sz = ((uint32_t)data[off] << 24) | ((uint32_t)data[off + 1] << 16) |
                      ((uint32_t)data[off + 2] << 8) | (uint32_t)data[off + 3];
        off += 4;
        if (sz == 0 || off + sz > n) break;
        buf_append(buf, cap, len, SC4, 4);
        buf_append(buf, cap, len, data + off, sz);
        off += sz;
    }
}

/* 是否关键帧（同步样）：缺 NotSync 标记即为可独立解码的同步样 */
static int is_sync_sample(CMSampleBufferRef sb) {
    CFArrayRef arr = CMSampleBufferGetSampleAttachmentsArray(sb, true);
    if (!arr || CFArrayGetCount(arr) == 0) return 1; /* 无附加载信息时按同步样处理 */
    CFDictionaryRef d = (CFDictionaryRef)CFArrayGetValueAtIndex(arr, 0);
    if (!d) return 1;
    CFBooleanRef ns = (CFBooleanRef)CFDictionaryGetValue(d, kCMSampleAttachmentKey_NotSync);
    return (ns == NULL) || (CFBooleanGetValue(ns) == false);
}

static void release_pixel_cb(void *releaseRefCon, const void *baseAddress) {
    (void)releaseRefCon;
    free((void *)baseAddress);
}

static void compression_cb(void *ctx, void *source, OSStatus status,
                           VTEncodeInfoFlags flags, CMSampleBufferRef sb) {
    vt_enc *vt = (vt_enc *)ctx;
    (void)flags;
    unsigned long long g = (unsigned long long)(uintptr_t)source;
    vt->cb_arrived = vt->cb_arrived + 1;
    if (status != noErr || !sb || !CMSampleBufferDataIsReady(sb)) {
        vt->failed = 1;
        dispatch_semaphore_signal(vt->sem);
        return;
    }
    CMFormatDescriptionRef desc = CMSampleBufferGetFormatDescription(sb);
    int sync = desc ? is_sync_sample(sb) : 0;

    /* 参数集：首次拿到格式描述即缓存，后续随关键帧前置（解码器中途接入也能起播） */
    if (!vt->ps_known && desc) {
        uint8_t *psb = NULL;
        size_t psc = 0, psl = 0;
        emit_parameter_sets(&psb, &psc, &psl, vt->ctype, desc);
        if (psl > 0) {
            vt->ps_buf = psb;
            vt->ps_len = psl;
            vt->ps_known = 1;
            DBG("取得参数集 %zu 字节\n", psl);
        } else if (psb) {
            free(psb);
        }
    }

    CMBlockBufferRef bb = CMSampleBufferGetDataBuffer(sb);
    size_t total = bb ? CMBlockBufferGetDataLength(bb) : 0;
    if (total > 0) {
        uint8_t *tmp = malloc(total);
        if (tmp) {
            if (CMBlockBufferCopyDataBytes(bb, 0, total, tmp) == kCMBlockBufferNoErr) {
                uint8_t *nb = NULL;
                size_t nc = 0, nl = 0;
                int ok = 1;
                if (sync && vt->ps_buf) {
                    if (buf_append(&nb, &nc, &nl, vt->ps_buf, vt->ps_len) != 0) ok = 0;
                }
                if (ok) emit_avcc_as_annexb(&nb, &nc, &nl, tmp, total);
                if (ok && nl > 0) {
                    outnode *nd = calloc(1, sizeof(outnode));
                    if (nd) {
                        nd->b = nb;
                        nd->n = nl;
                        if (vt->qt) vt->qt->next = nd; else vt->qh = nd;
                        vt->qt = nd;
                        DBG("入队 gen=%llu len=%zu keyframe=%d\n", g, nl, sync);
                    } else {
                        free(nb);
                    }
                } else {
                    free(nb);
                }
            }
            free(tmp);
        }
    }
    dispatch_semaphore_signal(vt->sem);
}

/* 等待输出队列非空（最多 wait_ms 毫秒）。返回 1=已有输出；0=超时。 */
static int wait_queue(vt_enc *vt, long wait_ms) {
    dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, wait_ms * (long)NSEC_PER_MSEC / 1000);
    while (!vt->qh) {
        if (dispatch_time(DISPATCH_TIME_NOW, 0) >= deadline) return 0;
        (void)dispatch_semaphore_wait(vt->sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)20 * NSEC_PER_MSEC));
    }
    return 1;
}

/* 等待"至少一次回调到达且已取得参数集"（create 阶段验证编码器真的能出码流）。
 * 返回 1=验证通过；0=超时。 */
static int wait_first_output(vt_enc *vt, long wait_ms) {
    dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, wait_ms * (long)NSEC_PER_MSEC / 1000);
    while (!(vt->cb_arrived > 0 && vt->ps_known)) {
        if (dispatch_time(DISPATCH_TIME_NOW, 0) >= deadline) return 0;
        (void)dispatch_semaphore_wait(vt->sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)20 * NSEC_PER_MSEC));
    }
    return 1;
}

/* 队列深度（含 pending） */
static int queue_depth(vt_enc *vt) {
    int n = vt->pending ? 1 : 0;
    for (outnode *p = vt->qh; p; p = p->next) n++;
    return n;
}

static outnode *pop_queue(vt_enc *vt) {
    outnode *nd = vt->qh;
    if (!nd) return NULL;
    vt->qh = nd->next;
    if (!vt->qh) vt->qt = NULL;
    nd->next = NULL;
    return nd;
}

/* 提交一帧（RGBA→BGRA 复制；调用方串行） */
static int submit_frame(vt_enc *vt, const uint8_t *rgba, long ts) {
    size_t need = (size_t)vt->w * vt->h * 4;
    uint8_t *bgra = malloc(need);
    if (!bgra) return -1;
    if (rgba) {
        for (size_t i = 0; i < need; i += 4) {
            bgra[i] = rgba[i + 2];
            bgra[i + 1] = rgba[i + 1];
            bgra[i + 2] = rgba[i];
            bgra[i + 3] = rgba[i + 3];
        }
    } else {
        memset(bgra, 0, need); /* 预置黑帧 */
    }

    CVImageBufferRef pb = NULL;
    CVReturn cvr = CVPixelBufferCreateWithBytes(
        NULL, vt->w, vt->h, kCVPixelFormatType_32BGRA, bgra, (size_t)vt->w * 4,
        release_pixel_cb, NULL, NULL, &pb);
    if (cvr != kCVReturnSuccess) {
        free(bgra);
        DBG("CVPixelBufferCreateWithBytes 失败 cvr=%d\n", (int)cvr);
        return -1;
    }
    vt->failed = 0;
    CMTime pts = CMTimeMake(ts, 30);
    CMTime dur = CMTimeMake(1, 30);
    CFMutableDictionaryRef fprops = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    unsigned long long gen = (unsigned long long)++vt->frame_seq;
    OSStatus st = VTCompressionSessionEncodeFrame(
        vt->session, pb, pts, dur, fprops, (void *)(uintptr_t)gen, NULL);
    CFRelease(fprops);
    CVBufferRelease(pb); /* bgra 由 release_pixel_cb 在像素缓冲释放时 free */
    if (st != noErr) {
        DBG("VTCompressionSessionEncodeFrame 失败 st=%d\n", (int)st);
        return -1;
    }
    return 0;
}

void *yuduan_enc_create(const char *codec, uint32_t width, uint32_t height) {
    CMVideoCodecType ctype;
    if (strcmp(codec, "h264") == 0) {
        ctype = kCMVideoCodecType_H264;
    } else if (strcmp(codec, "h265") == 0) {
        ctype = kCMVideoCodecType_HEVC;
    } else {
        return NULL; /* 供能力探测不虚标 */
    }
    if (width == 0 || height == 0 || (width % 2) || (height % 2)) {
        return NULL;
    }

    vt_enc *vt = calloc(1, sizeof(vt_enc));
    if (!vt) return NULL;
    vt->w = (int)width;
    vt->h = (int)height;
    vt->ctype = ctype;
    vt->sem = dispatch_semaphore_create(0);
    if (!vt->sem) {
        free(vt);
        return NULL;
    }

    /* sourceImageBufferAttributes：像素缓冲尺寸提示 */
    int32_t cvW = (int32_t)width, cvH = (int32_t)height;
    CFMutableDictionaryRef pbAttrs = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFCopyStringDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    CFNumberRef nW = CFNumberCreate(NULL, kCFNumberSInt32Type, &cvW);
    CFNumberRef nH = CFNumberCreate(NULL, kCFNumberSInt32Type, &cvH);
    CFDictionarySetValue(pbAttrs, kCVPixelBufferWidthKey, nW);
    CFDictionarySetValue(pbAttrs, kCVPixelBufferHeightKey, nH);

    /* 编码器选择（YUDUAN_ENC_HW）：
     *   未设置 = 系统启发式；0 = 强制软件；1 = 强制硬件。
     * 默认不强制的理由：铁律 2 要求三平台同构，后端选型不应绑死某一实现；
     * 另本机实测软件 H.264 会话不回调，强制软件反而不可用。 */
    const char *hwenv = getenv("YUDUAN_ENC_HW");
    CFMutableDictionaryRef encSpec = NULL;
    if (hwenv && (strcmp(hwenv, "0") == 0 || strcmp(hwenv, "1") == 0)) {
        encSpec = CFDictionaryCreateMutable(
            kCFAllocatorDefault, 0, &kCFCopyStringDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks);
        CFStringRef key = (strcmp(hwenv, "1") == 0)
            ? kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder
            : kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder;
        CFDictionarySetValue(encSpec, key,
                             (strcmp(hwenv, "1") == 0) ? kCFBooleanTrue : kCFBooleanFalse);
        DBG("编码器规格: %s\n", strcmp(hwenv, "1") == 0 ? "强制硬件" : "强制软件");
    }

    OSStatus st = VTCompressionSessionCreate(
        kCFAllocatorDefault, (int32_t)width, (int32_t)height, ctype,
        encSpec, pbAttrs, NULL,
        compression_cb, vt, &vt->session);
    if (encSpec) CFRelease(encSpec);
    CFRelease(nW);
    CFRelease(nH);
    CFRelease(pbAttrs);
    if (st != noErr || !vt->session) {
        DBG("VTCompressionSessionCreate 失败 st=%d\n", (int)st);
        if (vt->sem) dispatch_release(vt->sem);
        free(vt);
        return NULL;
    }

    VTSessionSetProperty(vt->session, kVTCompressionPropertyKey_RealTime, kCFBooleanTrue);
    VTSessionSetProperty(vt->session, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanFalse);
    CFNumberRef maxKF = CFNumberCreate(NULL, kCFNumberIntType, &(int){60});
    VTSessionSetProperty(vt->session, kVTCompressionPropertyKey_MaxKeyFrameInterval, maxKF);
    CFRelease(maxKF);
    if (ctype == kCMVideoCodecType_H264) {
        VTSessionSetProperty(vt->session, kVTCompressionPropertyKey_ProfileLevel,
                             kVTProfileLevel_H264_Main_AutoLevel);
    } else {
        VTSessionSetProperty(vt->session, kVTCompressionPropertyKey_ProfileLevel,
                             kVTProfileLevel_HEVC_Main_AutoLevel);
    }
    if (VTCompressionSessionPrepareToEncodeFrames(vt->session) != noErr) {
        DBG("PrepareToEncodeFrames 失败\n");
        VTCompressionSessionInvalidate(vt->session);
        CFRelease(vt->session);
        dispatch_release(vt->sem);
        free(vt);
        return NULL;
    }

    /* 预置（两个黑帧）：
     *   ① 吸收编码器冷启动；
     *   ② 建立 1 帧管线延迟所需的前置链路——提交第 2 帧时第 1 帧的输出才被顶出，
     *      借此在 create() 里验证该编码器真的能出码流并拿到参数集（能力探测不虚标）；
     *   ③ 第 2 帧的输出留在队列里，成为码流首个关键帧被第一次 encode() 取走
     *      （黑 IDR + 参数集，解码器可立即起播）。
     * 验证失败 → 会话不可信，返回 NULL 让副端诚实回退。 */
    if (submit_frame(vt, NULL, 0) != 0 || submit_frame(vt, NULL, 1) != 0) {
        DBG("预置帧提交失败\n");
        yuduan_enc_destroy(vt);
        return NULL;
    }
    if (!wait_first_output(vt, VT_WAIT_SEC * 1000)) {
        DBG("预置验证超时(%ds)：cb_arrived=%d ps_known=%d\n", VT_WAIT_SEC, vt->cb_arrived, vt->ps_known);
        yuduan_enc_destroy(vt);
        return NULL;
    }
    return vt;
}

uint32_t yuduan_enc_encode(void *handle, const uint8_t *rgba, uint32_t rgba_len,
                           uint8_t *out, uint32_t out_cap) {
    vt_enc *vt = (vt_enc *)handle;
    if (!vt || !out) return 0;
    DBG("encode 入口 w=%d h=%d rgba_len=%u out_cap=%u 队列=%d pending=%d frame=%ld\n",
        vt->w, vt->h, rgba_len, out_cap, queue_depth(vt), vt->pending ? 1 : 0, vt->frame);

    /* 重投语义：上一帧已出队但调用方缓冲不足，这里原样交付（不重复编码、不乱序）。 */
    if (vt->pending) {
        if (vt->pending->n > 0 && (size_t)out_cap >= vt->pending->n) {
            memcpy(out, vt->pending->b, vt->pending->n);
            uint32_t n = (uint32_t)vt->pending->n;
            free(vt->pending->b);
            free(vt->pending);
            vt->pending = NULL;
            return n;
        }
        return 0;
    }
    if (!rgba) return 0;

    size_t need = (size_t)vt->w * vt->h * 4;
    if ((size_t)rgba_len < need) return 0; /* 帧与会话尺寸不符：交由上层回退 */

    /* 落后保护：队列已有 ≥2 帧说明上次走了兜底强推、出现了堆积，本次只排不提交，
     * 把延迟拉回 1 帧以内，避免无限累加。 */
    int drain_only = queue_depth(vt) >= 2;
    if (!drain_only && submit_frame(vt, rgba, vt->frame) != 0) return 0;
    vt->frame++;

    if (!wait_queue(vt, VT_PIPE_WAIT_MS)) {
        DBG("管线饥饿，CompleteFrames 兜底强推 frame=%ld\n", (long)vt->frame - 1);
        CMTime until = CMTimeMake(vt->frame, 30);
        OSStatus cst = VTCompressionSessionCompleteFrames(vt->session, until);
        if (cst != noErr) DBG("CompleteFrames 失败 st=%d\n", (int)cst);
        if (!wait_queue(vt, VT_WAIT_SEC * 1000)) {
            DBG("等待第 %ld 帧输出超时(%ds)\n", (long)vt->frame - 1, VT_WAIT_SEC);
            return 0; /* 超时：本帧丢弃；迟到回调入队后供下一次调用取走 */
        }
    }

    outnode *nd = pop_queue(vt);
    if (!nd || nd->n == 0) {
        free(nd);
        return 0;
    }
    if ((size_t)out_cap < nd->n) {
        vt->pending = nd; /* 保留：等调用方扩张缓冲后原帧重投 */
        return 0;
    }
    memcpy(out, nd->b, nd->n);
    uint32_t n = (uint32_t)nd->n;
    free(nd->b);
    free(nd);
    return n;
}

void yuduan_enc_destroy(void *handle) {
    vt_enc *vt = (vt_enc *)handle;
    if (!vt) return;
    if (vt->session) {
        VTCompressionSessionInvalidate(vt->session);
        CFRelease(vt->session);
    }
    if (vt->sem) dispatch_release(vt->sem);
    outnode *nd = vt->qh;
    while (nd) {
        outnode *nx = nd->next;
        free(nd->b);
        free(nd);
        nd = nx;
    }
    if (vt->pending) {
        free(vt->pending->b);
        free(vt->pending);
    }
    free(vt->ps_buf);
    free(vt);
}

/* §8.3.15 码率重参数化（可选导出）：会话中途调整目标码率。
 * 经 VTSessionSetProperty 改 AverageBitRate（单位 bps），下一帧起生效；
 * 句柄无效 / 会话未建 / kbps=0 时静默忽略（调用方以日志为准，无需返回值）。 */
void yuduan_enc_set_bitrate(void *handle, uint32_t kbps) {
    vt_enc *vt = (vt_enc *)handle;
    if (!vt || !vt->session || kbps == 0) return;
    int32_t bps = (int32_t)kbps * 1000;
    CFNumberRef br = CFNumberCreate(NULL, kCFNumberIntType, &bps);
    if (!br) return;
    OSStatus st = VTSessionSetProperty(vt->session, kVTCompressionPropertyKey_AverageBitRate, br);
    CFRelease(br);
    DBG("set_bitrate %u kbps st=%d\n", kbps, (int)st);
}
