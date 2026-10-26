#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* 验证桩编码器，对齐 protocol.md §8.3.3 C-ABI 契约：
 *   void*    yuduan_enc_create(const char* codec, unsigned w, unsigned h)
 *   unsigned yuduan_enc_encode(void* h, const uint8_t* rgba, unsigned len,
 *                              uint8_t* out, unsigned cap)   // 返回 written；0=缓冲区不足
 *   void     yuduan_enc_destroy(void* h)
 * §8.3.15 可选导出（码率重参数化验证桩）：
 *   void     yuduan_enc_set_bitrate(void* h, unsigned kbps)
 * 行为：仅接受 "h264"（其余 codec 返回 NULL，用于验证能力探测不虚标）；
 *      输出 "STUB" + 原始 RGBA，供对端校验载荷特征。 */
void* yuduan_enc_create(const char* codec, unsigned w, unsigned h) {
    (void)w; (void)h;
    if (!codec || strcmp(codec, "h264") != 0) return NULL;
    return (void*)1;
}
unsigned yuduan_enc_encode(void* handle, const uint8_t* rgba, unsigned len,
                           uint8_t* out, unsigned cap) {
    (void)handle;
    if ((unsigned long)cap < (unsigned long)len + 4) return 0;
    memcpy(out, "STUB", 4);
    memcpy(out + 4, rgba, len);
    return len + 4;
}
void yuduan_enc_destroy(void* handle) { (void)handle; }
void yuduan_enc_set_bitrate(void* handle, unsigned kbps) { (void)handle; (void)kbps; }
