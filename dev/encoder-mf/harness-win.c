/*
 * harness-win.c — 御端原生编码器 C-ABI（§8.3.3）直测工具（Windows 版）
 *
 * 与 encoder-vt/harness.c 同构：唯一的差别是动态库加载用 LoadLibraryA/GetProcAddress
 * 替换 dlopen/dlsym（Windows 无 dlfcn）。任何新编码器库（MediaFoundation 等）都必须
 * 能被本 harness 跑通产出合法裸流。
 *
 * 构建（在 "x64 Native Tools Command Prompt" 下）：
 *   cl /nologo /O2 /W4 harness-win.c /Fe:enc_harness.exe
 *
 * 用法：
 *   enc_harness.exe <dll> <h264|h265> <width> <height> <frames> <outfile> [扩张倍数]
 *
 * 行为：
 *   1. LoadLibraryA 动态库，解析 yuduan_enc_create / encode / destroy；
 *   2. create(codec,w,h) —— 失败即退出 2（能力探测语义：库不支持该 codec）；
 *   3. 逐帧送合成 RGBA（渐变+移动方块，确保非全黑、有运动），调用 encode；
 *      encode 返回 0 时按 2 倍扩张输出缓冲重试，最多 [扩张倍数] 次（默认 8 次 → 256x）；
 *   4. 写出裸流（Annex-B）供 ffprobe/ffplay 验证；
 *   5. 打印每帧字节数与总字节数。
 *
 * 注意：契约要求 create/encode/destroy 同线程调用，本工具为单线程，天然满足。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>

typedef void *(*fn_create)(const char *, uint32_t, uint32_t);
typedef uint32_t (*fn_encode)(void *, const uint8_t *, uint32_t, uint8_t *, uint32_t);
typedef void (*fn_destroy)(void *);

/* 合成测试帧：横向渐变 + 随帧移动的白色方块（验证编码器真实产出非空洞内容） */
static void fill_rgba(uint8_t *p, uint32_t w, uint32_t h, uint32_t frame) {
    uint32_t bw = w / 8 ? w / 8 : 1, bh = h / 8 ? h / 8 : 1;
    uint32_t bx = (frame * 7) % (w > bw ? w - bw : 1);
    uint32_t by = (frame * 5) % (h > bh ? h - bh : 1);
    for (uint32_t y = 0; y < h; y++) {
        for (uint32_t x = 0; x < w; x++) {
            uint8_t *q = p + ((size_t)y * w + x) * 4;
            q[0] = (uint8_t)(x * 255 / (w > 1 ? w - 1 : 1));
            q[1] = (uint8_t)(y * 255 / (h > 1 ? h - 1 : 1));
            q[2] = (uint8_t)((x + y + frame * 3) & 0xFF);
            q[3] = 255;
            if (x >= bx && x < bx + bw && y >= by && y < by + bh) {
                q[0] = q[1] = q[2] = 255;
            }
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 7) {
        fprintf(stderr, "usage: enc_harness <dll> <h264|h265> <w> <h> <frames> <out> [grow]\n");
        return 1;
    }
    const char *lib = argv[1], *codec = argv[2];
    uint32_t w = (uint32_t)strtoul(argv[3], NULL, 10);
    uint32_t h = (uint32_t)strtoul(argv[4], NULL, 10);
    uint32_t frames = (uint32_t)strtoul(argv[5], NULL, 10);
    const char *out = argv[6];
    int grow = argc > 7 ? atoi(argv[7]) : 8;

    HMODULE dl = LoadLibraryA(lib);
    if (!dl) {
        fprintf(stderr, "LoadLibraryA 失败: %s (GetLastError=%lu)\n", lib, (unsigned long)GetLastError());
        return 2;
    }
    fn_create create = (fn_create)(void *)GetProcAddress(dl, "yuduan_enc_create");
    fn_encode encode = (fn_encode)(void *)GetProcAddress(dl, "yuduan_enc_encode");
    fn_destroy destroy = (fn_destroy)(void *)GetProcAddress(dl, "yuduan_enc_destroy");
    if (!create || !encode || !destroy) {
        fprintf(stderr, "符号缺失（须导出 yuduan_enc_create/encode/destroy）\n");
        return 2;
    }

    void *hd = create(codec, w, h);
    if (!hd) {
        fprintf(stderr, "create 失败：库不支持 codec=%s 或尺寸 %ux%u\n", codec, w, h);
        return 2;
    }
    printf("create OK codec=%s %ux%u\n", codec, w, h);

    size_t rgba_len = (size_t)w * h * 4;
    uint8_t *rgba = (uint8_t *)malloc(rgba_len);
    if (!rgba) return 3;
    size_t cap = 1 << 20;
    uint8_t *ob = (uint8_t *)malloc(cap);
    if (!ob) return 3;

    FILE *f = fopen(out, "wb");
    if (!f) {
        fprintf(stderr, "无法写出 %s\n", out);
        return 3;
    }
    uint32_t ok_frames = 0;
    size_t total = 0;
    for (uint32_t i = 0; i < frames; i++) {
        fill_rgba(rgba, w, h, i);
        uint32_t n = 0;
        for (int g = 0; g < grow; g++) {
            n = encode(hd, rgba, (uint32_t)rgba_len, ob, (uint32_t)cap);
            if (n > 0) break;
            cap *= 2;
            uint8_t *nb = (uint8_t *)realloc(ob, cap);
            if (!nb) {
                fprintf(stderr, "OOM 扩张输出缓冲\n");
                return 3;
            }
            ob = nb;
        }
        if (n == 0) {
            fprintf(stderr, "第 %u 帧编码失败（多次扩张仍返回 0）\n", i);
            fclose(f);
            return 4;
        }
        fwrite(ob, 1, n, f);
        total += n;
        ok_frames++;
        printf("frame %u: %u bytes%s\n", i, n, i == 0 ? " (含参数集/关键帧)" : "");
    }
    fclose(f);
    destroy(hd);
    printf("OK frames=%u total=%zu bytes -> %s\n", ok_frames, total, out);
    return 0;
}
