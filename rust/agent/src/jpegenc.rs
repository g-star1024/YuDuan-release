//! 纯 Rust baseline JPEG 编码器（零第三方依赖，标准库实现）。
//!
//! 用途（§8.3.7/§8.3.10 JPEG 路径降采样）：远控 JPEG 路径原先依赖平台 CLI
//! （macOS `screencapture` / Linux `scrot` / Windows 无对应工具），只能全分辨率出帧。
//! 改为「RGBA 采集（三平台同构，rc.rs 已实现）→ fit_dims 降采样 → 本模块编码」，
//! 5K 屏从 2.3MB/帧（全分辨率 JPEG）降至 1080p JPEG（~200KB 级）；RGBA 采集
//! 不可用时仍回退原 CLI 路径（capture_jpeg_cli）。
//!
//! 实现范围（baseline sequential DCT, JFIF 1.01）：
//!   - 输入 RGBA8（紧凑 w*h*4）；YCbCr BT.601；4:2:0 色度下采样；
//!   - 标准 Annex K 量化表（quality 可调 1..=100）+ 标准 Huffman 表；
//!   - MCU 16×16（4Y+1Cb+1Cr），边缘复制填充；0xFF 字节填充。
//! 已知取舍：f32 分离式 FDCT（每块两次 8 点变换），1080p 全帧 ~几十毫秒（release），
//! 满足 JPEG 兜底路径 15fps 目标；性能敏感路径请用原生编码器（VideoToolbox 等）。

/// 标准 Annex K 亮度量化表（quality=50 基准，zigzag 前的自然序）。
const QTABLE_LUMA: [u16; 64] = [
    16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69,
    56, 14, 17, 22, 29, 51, 87, 80, 62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81,
    104, 113, 92, 49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99,
];
/// 标准 Annex K 色度量化表。
const QTABLE_CHROMA: [u16; 64] = [
    17, 18, 24, 47, 99, 99, 99, 99, 18, 21, 26, 66, 99, 99, 99, 99, 24, 26, 56, 99, 99, 99, 99,
    99, 47, 66, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
];

/// zigzag 序（自然序 → 序列化顺序的索引）。
const ZIGZAG: [usize; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27,
    20, 13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58,
    59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

/// 标准 Huffman DC 亮度：16 段 bit 长度 + 12 个值。
const HUFF_DC_LUMA_BITS: [u8; 16] = [0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0];
const HUFF_DC_LUMA_VALS: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
/// 标准 Huffman DC 色度。
const HUFF_DC_CHROMA_BITS: [u8; 16] = [0, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0];
const HUFF_DC_CHROMA_VALS: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
/// 标准 Huffman AC 亮度。
const HUFF_AC_LUMA_BITS: [u8; 16] = [0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 125];
const HUFF_AC_LUMA_VALS: [u8; 162] = [
    0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61,
    0x07, 0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xA1, 0x08, 0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52,
    0xD1, 0xF0, 0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x25,
    0x26, 0x27, 0x28, 0x29, 0x2A, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45,
    0x46, 0x47, 0x48, 0x49, 0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x63, 0x64,
    0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x83,
    0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99,
    0x9A, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6,
    0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xD2, 0xD3,
    0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8,
    0xE9, 0xEA, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA,
];
/// 标准 Huffman AC 色度。
const HUFF_AC_CHROMA_BITS: [u8; 16] = [0, 2, 1, 2, 4, 4, 3, 4, 7, 5, 4, 4, 0, 1, 2, 119];
const HUFF_AC_CHROMA_VALS: [u8; 162] = [
    0x00, 0x01, 0x02, 0x03, 0x11, 0x04, 0x05, 0x21, 0x31, 0x06, 0x12, 0x41, 0x51, 0x07, 0x61,
    0x71, 0x13, 0x22, 0x32, 0x81, 0x08, 0x14, 0x42, 0x91, 0xA1, 0xB1, 0xC1, 0x09, 0x23, 0x33,
    0x52, 0xF0, 0x15, 0x62, 0x72, 0xD1, 0x0A, 0x16, 0x24, 0x34, 0xE1, 0x25, 0xF1, 0x17, 0x18,
    0x19, 0x1A, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44,
    0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x63,
    0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A,
    0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9A, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4,
    0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
    0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
    0xE8, 0xE9, 0xEA, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA,
];

/// 由 (bits, vals) 构建 Huffman 码表（T.81 附录 C 生成法）。
/// 返回 256 项符号直查表：sym → (code, len)；未定义符号为 (0,0)（码流不应出现）。
fn build_huff(bits: &[u8; 16], vals: &[u8]) -> Vec<(u16, u8)> {
    let mut tbl = vec![(0u16, 0u8); 256];
    let mut code: u16 = 0;
    let mut vi = 0usize;
    for (li, &cnt) in bits.iter().enumerate() {
        let l = (li + 1) as u8;
        for _ in 0..cnt {
            assert!(vi < vals.len(), "Huffman bits 与 values 数量不符");
            tbl[vals[vi] as usize] = (code, l);
            code += 1;
            vi += 1;
        }
        code <<= 1;
    }
    assert_eq!(vi, vals.len(), "Huffman bits 与 values 数量不符");
    tbl
}

/// MSB 位流写出（含 0xFF→0xFF 0x00 填充）。
struct BitWriter {
    out: Vec<u8>,
    acc: u32,
    nbits: u32,
}

impl BitWriter {
    fn new() -> Self {
        BitWriter { out: Vec::new(), acc: 0, nbits: 0 }
    }
    fn put(&mut self, code: u16, len: u8) {
        if len == 0 {
            return;
        }
        self.acc = (self.acc << len) | code as u32;
        self.nbits += len as u32;
        while self.nbits >= 8 {
            self.nbits -= 8;
            let b = ((self.acc >> self.nbits) & 0xFF) as u8;
            self.out.push(b);
            if b == 0xFF {
                self.out.push(0x00);
            }
        }
    }
    /// 定长补齐到字节边界（pad 1，SOS 末尾要求）。
    fn flush(&mut self) {
        if self.nbits > 0 {
            let pad = 8 - self.nbits;
            self.put(((1 << pad) - 1) as u16, pad as u8);
        }
    }
}

/// 追加段标记（0xFF marker + 2 字节大端长度，len 含自身）。
fn push_marker(out: &mut Vec<u8>, marker: u8, payload: &[u8]) {
    out.push(0xFF);
    out.push(marker);
    out.extend_from_slice(&(payload.len() as u16 + 2).to_be_bytes());
    out.extend_from_slice(payload);
}

/// 按 quality（1..=100）缩放标准量化表（T.81 K.1 推荐式）。
fn scale_qtable(base: &[u16; 64], quality: u32) -> [u16; 64] {
    let q = quality.clamp(1, 100);
    let scale = if q < 50 { 5000 / q } else { 200 - 2 * q };
    let mut out = [0u16; 64];
    for i in 0..64 {
        let v = (base[i] as u32 * scale + 50) / 100;
        out[i] = v.clamp(1, 255) as u16;
    }
    out
}

/// FDCT（分离式，f32）：8×8 空域块 → 频域系数（自然序）。
/// cos 表为 T[频率][空间] = cos((2n+1)fπ/16)，行/列 pass 均按 [频率][空间] 取索引。
fn fdct(s: &[f32; 64], cos: &[[f32; 8]; 8], tmp: &mut [f32; 64], out: &mut [f32; 64]) {
    // 行变换：tmp[y][f] = 0.5*C(f)*Σ_n s[y][n]*T[f][n]
    for y in 0..8 {
        for f in 0..8 {
            let mut sum = 0.0f32;
            for n in 0..8 {
                sum += s[y * 8 + n] * cos[f][n];
            }
            tmp[y * 8 + f] = sum * 0.5 * if f == 0 { std::f32::consts::FRAC_1_SQRT_2 } else { 1.0 };
        }
    }
    // 列变换：out[f2][f] = 0.5*C(f2)*Σ_n tmp[n][f]*T[f2][n]
    for f in 0..8 {
        for f2 in 0..8 {
            let mut sum = 0.0f32;
            for n in 0..8 {
                sum += tmp[n * 8 + f] * cos[f2][n];
            }
            out[f2 * 8 + f] = sum * 0.5 * if f2 == 0 { std::f32::consts::FRAC_1_SQRT_2 } else { 1.0 };
        }
    }
}

/// RGBA8（w*h*4，紧凑）→ baseline JPEG（JFIF 1.01，YCbCr 4:2:0）。
/// 输入不合法返回 None（调用方回退），不产出错误码流。
pub fn encode_rgba(rgba: &[u8], w: u32, h: u32, quality: u32) -> Option<Vec<u8>> {
    if w == 0 || h == 0 || rgba.len() != (w as usize) * (h as usize) * 4 {
        return None;
    }
    let (w, h) = (w as usize, h as usize);

    // RGBA → 平面 Y / Cb / Cr（BT.601），MCU 边缘复制填充到 16 的倍数。
    let mw = (w + 15) / 16 * 16;
    let mh = (h + 15) / 16 * 16;
    let mut y8 = vec![128f32; mw * mh];
    let mut cb8 = vec![128f32; mw * mh];
    let mut cr8 = vec![128f32; mw * mh];
    for yy in 0..h {
        for xx in 0..w {
            let p = (yy * w + xx) * 4;
            let (r, g, b) = (rgba[p] as f32, rgba[p + 1] as f32, rgba[p + 2] as f32);
            let y = 0.299 * r + 0.587 * g + 0.114 * b;
            let cb = -0.168736 * r - 0.331264 * g + 0.5 * b + 128.0;
            let cr = 0.5 * r - 0.418688 * g - 0.081312 * b + 128.0;
            y8[yy * mw + xx] = y;
            cb8[yy * mw + xx] = cb;
            cr8[yy * mw + xx] = cr;
        }
    }
    // 4:2:0：2×2 平均下采样（写入独立半分辨率平面——原位会污染首行未读区）。
    let mut cb = vec![128f32; (mw / 2) * (mh / 2)];
    let mut cr = vec![128f32; (mw / 2) * (mh / 2)];
    for yy in 0..(mh / 2) {
        for xx in 0..(mw / 2) {
            let (x2, y2) = (xx * 2, yy * 2);
            let avg = |a: f32, b: f32, c: f32, d: f32| (a + b + c + d) / 4.0;
            cb[yy * (mw / 2) + xx] = avg(
                cb8[y2 * mw + x2], cb8[y2 * mw + x2 + 1],
                cb8[(y2 + 1) * mw + x2], cb8[(y2 + 1) * mw + x2 + 1]);
            cr[yy * (mw / 2) + xx] = avg(
                cr8[y2 * mw + x2], cr8[y2 * mw + x2 + 1],
                cr8[(y2 + 1) * mw + x2], cr8[(y2 + 1) * mw + x2 + 1]);
        }
    }
    // cb8/cr8 全分辨率平面使命完成，仅 Y 平面继续参与编码
    drop(cb8);
    drop(cr8);
    let cb8 = cb;
    let cr8 = cr;

    let (qy, qc) = (scale_qtable(&QTABLE_LUMA, quality), scale_qtable(&QTABLE_CHROMA, quality));

    // 预计算 cos 表：T[频率][空间] = cos((2n+1)·f·π/16)——T.81 A.3.3 核。
    // 注意 (2n+1) 必须乘空间索引 n：写反会得到 DCT-III（逆变换）核，
    // 常数块产生大量假 AC 系数（本机实测：纯灰 256×256 从 ~1.6KB 涨到 8.4KB）。
    let mut cos = [[0f32; 8]; 8];
    for f in 0..8 {
        for n in 0..8 {
            cos[f][n] = ((2 * n + 1) as f32 * f as f32 * std::f32::consts::PI / 16.0).cos();
        }
    }

    let dc_l = build_huff(&HUFF_DC_LUMA_BITS, &HUFF_DC_LUMA_VALS);
    let dc_c = build_huff(&HUFF_DC_CHROMA_BITS, &HUFF_DC_CHROMA_VALS);
    let ac_l = build_huff(&HUFF_AC_LUMA_BITS, &HUFF_AC_LUMA_VALS);
    let ac_c = build_huff(&HUFF_AC_CHROMA_BITS, &HUFF_AC_CHROMA_VALS);

    let mut out = vec![0xFF, 0xD8]; // SOI
    push_marker(&mut out, 0xE0, &[
        b'J', b'F', b'I', b'F', 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, // APP0 JFIF v1.01 无密度
    ]);
    // DQT ×2（亮度 id=0、色度 id=1，zigzag 序）
    let mut dq = [0u8; 65];
    dq[0] = 0;
    for i in 0..64 {
        dq[1 + i] = qy[ZIGZAG[i]] as u8;
    }
    push_marker(&mut out, 0xDB, &dq);
    dq[0] = 1;
    for i in 0..64 {
        dq[1 + i] = qc[ZIGZAG[i]] as u8;
    }
    push_marker(&mut out, 0xDB, &dq);
    // SOF0：8bit 精度，h×w，3 分量。分量三元组 = (id, 采样因子 h/v, 量化表 id)：
    // 4:2:0 的 MCU 为 4Y+1Cb+1Cr → Y 采样 2×2(0x22) 用量化表 0；色度 1×1(0x11) 用表 1。
    let sof = [
        8u8, (h >> 8) as u8, h as u8, (w >> 8) as u8, w as u8, 3,
        1, 0x22, 0x00, 2, 0x11, 0x01, 3, 0x11, 0x01,
    ];
    push_marker(&mut out, 0xC0, &sof);
    // DHT ×4：DC0 / AC0 / DC1 / AC1
    let mut dht = vec![0u8]; // class 0, id 0
    dht.extend_from_slice(&HUFF_DC_LUMA_BITS);
    dht.extend_from_slice(&HUFF_DC_LUMA_VALS);
    push_marker(&mut out, 0xC4, &dht);
    let mut dht = vec![0x10u8]; // class 1, id 0
    dht.extend_from_slice(&HUFF_AC_LUMA_BITS);
    dht.extend_from_slice(&HUFF_AC_LUMA_VALS);
    push_marker(&mut out, 0xC4, &dht);
    let mut dht = vec![1u8]; // class 0, id 1
    dht.extend_from_slice(&HUFF_DC_CHROMA_BITS);
    dht.extend_from_slice(&HUFF_DC_CHROMA_VALS);
    push_marker(&mut out, 0xC4, &dht);
    let mut dht = vec![0x11u8]; // class 1, id 1
    dht.extend_from_slice(&HUFF_AC_CHROMA_BITS);
    dht.extend_from_slice(&HUFF_AC_CHROMA_VALS);
    push_marker(&mut out, 0xC4, &dht);
    // SOS
    push_marker(&mut out, 0xDA, &[3, 1, 0x00, 2, 0x11, 3, 0x11, 0, 63, 0]);

    // 熵编码：逐 MCU（16×16 = 4Y + Cb + Cr）
    let mut bw = BitWriter::new();
    let mut block = [0f32; 64];
    let mut tmp = [0f32; 64];
    let mut coef = [0f32; 64];
    let mut pred = [0i32; 3]; // DC 预测：0=Y 1=Cb 2=Cr
    let mut quant = [0i32; 64];

    let encode_block = |bw: &mut BitWriter, plane: &[f32], stride: usize, ox: usize, oy: usize,
                        qt: &[u16; 64],
                        dc: &[(u16, u8)], ac: &[(u16, u8)],
                        pred: &mut i32, block: &mut [f32; 64], tmp: &mut [f32; 64],
                        coef: &mut [f32; 64], cos: &[[f32; 8]; 8], quant: &mut [i32; 64]| {
        for by in 0..8 {
            for bx in 0..8 {
                block[by * 8 + bx] = plane[(oy + by) * stride + ox + bx] - 128.0;
            }
        }
        fdct(block, cos, tmp, coef);
        for i in 0..64 {
            quant[i] = (coef[i] / qt[i] as f32).round() as i32;
        }
        // DC（差分 + category）
        let diff = quant[0] - *pred;
        *pred = quant[0];
        let (cat, vbits) = encode_category(diff);
        let (c, l) = dc[cat as usize];
        bw.put(c, l);
        if cat > 0 {
            bw.put(vbits as u16, cat as u8);
        }
        // AC：游程 + ZRL + EOB
        let mut run = 0u32;
        for i in 1..64 {
            let v = quant[ZIGZAG[i]];
            if v == 0 {
                run += 1;
                continue;
            }
            while run > 15 {
                let (c, l) = ac[0xF0]; // ZRL：15,0
                bw.put(c, l);
                run -= 16;
            }
            let (cat, vbits) = encode_category(v);
            let sym = ((run as u8) << 4) | cat as u8;
            let (c, l) = ac[sym as usize];
            bw.put(c, l);
            if cat > 0 {
                bw.put(vbits as u16, cat as u8);
            }
            run = 0;
        }
        if run > 0 {
            let (c, l) = ac[0x00]; // EOB
            bw.put(c, l);
        }
    };

    for my in (0..mh).step_by(16) {
        for mx in (0..mw).step_by(16) {
            for i in 0..4 {
                let (ox, oy) = (mx + (i % 2) * 8, my + (i / 2) * 8);
                encode_block(&mut bw, &y8, mw, ox, oy, &qy,
                    &dc_l, &ac_l,
                    &mut pred[0], &mut block, &mut tmp, &mut coef, &cos, &mut quant);
            }
            let (cxs, cys) = (mx / 2, my / 2);
            encode_block(&mut bw, &cb8, mw / 2, cxs, cys, &qc,
                &dc_c, &ac_c,
                &mut pred[1], &mut block, &mut tmp, &mut coef, &cos, &mut quant);
            encode_block(&mut bw, &cr8, mw / 2, cxs, cys, &qc,
                &dc_c, &ac_c,
                &mut pred[2], &mut block, &mut tmp, &mut coef, &cos, &mut quant);
        }
    }
    bw.flush();
    out.extend_from_slice(&bw.out);
    out.extend_from_slice(&[0xFF, 0xD9]); // EOI
    Some(out)
}

/// 差值 → (category, 定长比特值)。category = 有效位数；负数按规范偏移。
fn encode_category(v: i32) -> (u32, u32) {
    if v == 0 {
        return (0, 0);
    }
    let mut cat = 32 - (v.abs() as u32).leading_zeros();
    let val = if v < 0 { (v - 1) as u32 } else { v as u32 };
    (cat, val & ((1u32 << cat) - 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 合成测试图：横向渐变 + 竖向渐变叠加（有真实空间频率，验证 DCT/量化/熵编码）。
    fn gradient(w: u32, h: u32) -> Vec<u8> {
        let mut v = Vec::with_capacity((w * h * 4) as usize);
        for y in 0..h {
            for x in 0..w {
                v.push((x * 255 / w.max(1)) as u8);
                v.push((y * 255 / h.max(1)) as u8);
                v.push(((x + y) % 256) as u8);
                v.push(255);
            }
        }
        v
    }

    #[test]
    fn jpeg_output_has_valid_marker_skeleton() {
        // 结构：SOI → APP0(JFIF) → DQT×2 → SOF0 → DHT×4 → SOS → 熵编码 → EOI
        let (w, h) = (64u32, 48u32);
        let jpg = encode_rgba(&gradient(w, h), w, h, 80).expect("合法输入应编码成功");
        assert_eq!(&jpg[0..2], &[0xFF, 0xD8], "SOI");
        assert_eq!(&jpg[jpg.len() - 2..], &[0xFF, 0xD9], "EOI");
        // 扫描段骨架：APP0/DQT/SOF0/DHT 齐备，且 SOF 尺寸与输入一致
        let mut i = 2usize;
        let (mut sof_w, mut sof_h) = (0usize, 0usize);
        let mut seen = std::collections::HashSet::new();
        while i + 4 <= jpg.len() {
            if jpg[i] != 0xFF {
                break; // 进入熵编码
            }
            let marker = jpg[i + 1];
            if marker == 0xD8 || (0xD0..=0xD7).contains(&marker) || marker == 0x01 || marker == 0xFF {
                i += 2;
                continue;
            }
            let len = u16::from_be_bytes([jpg[i + 2], jpg[i + 3]]) as usize;
            match marker {
                0xE0 => { seen.insert("APP0"); }
                0xDB => { seen.insert("DQT"); }
                0xC0 => {
                    seen.insert("SOF0");
                    sof_h = ((jpg[i + 5] as usize) << 8) | jpg[i + 6] as usize;
                    sof_w = ((jpg[i + 7] as usize) << 8) | jpg[i + 8] as usize;
                }
                0xC4 => { seen.insert("DHT"); }
                0xDA => {
                    seen.insert("SOS");
                    break;
                }
                _ => {}
            }
            i += 2 + len;
        }
        for m in ["APP0", "DQT", "SOF0", "DHT", "SOS"] {
            assert!(seen.contains(m), "缺少段 {}", m);
        }
        assert_eq!((sof_w, sof_h), (w as usize, h as usize), "SOF 尺寸应与输入一致");
    }

    #[test]
    fn jpeg_solid_gray_is_tiny_and_category_math_holds() {
        // 纯灰图 DC 相同 → 压缩后应极小（<2KB），验证 DC 预测与 EOB 链路
        let (w, h) = (256u32, 256u32);
        let mut solid = vec![128u8; (w * h * 4) as usize];
        for p in solid.iter_mut().step_by(4) {
            *p = 160;
        }
        let jpg = encode_rgba(&solid, w, h, 80).expect("应编码成功");
        assert!(jpg.len() < 2048, "纯灰 256×256 应 <2KB，实际 {}", jpg.len());

        // category 数学：正数/负数/边界（T.81 F.1.2.1：负数 = v-1 的低 cat 位）
        assert_eq!(encode_category(0), (0, 0));
        assert_eq!(encode_category(1), (1, 1));
        assert_eq!(encode_category(-1), (1, 0)); // -2 = ...11111110，低 1 位 = 0
        assert_eq!(encode_category(255), (8, 255));
        assert_eq!(encode_category(-255), (8, 0)); // -256 = ...111100000000，低 8 位 = 0
    }

    #[test]
    fn jpeg_rejects_bad_input_and_quality_bounds_hold() {
        assert!(encode_rgba(&[0u8; 10], 4, 4, 80).is_none(), "长度不符应拒绝");
        assert!(encode_rgba(&[], 0, 0, 80).is_none(), "零尺寸应拒绝");
        // quality 两个极端都不崩、量化值落在 1..=255
        for q in [1u32, 50, 100, 0, 999] {
            let jpg = encode_rgba(&gradient(16, 16), 16, 16, q).expect("越界 quality 应被夹取");
            assert!(jpg.len() > 100 && jpg[0] == 0xFF && jpg[1] == 0xD8);
        }
        // quality=1 应全 255（scale=5000 夹取上限，最粗糙）
        let q1 = scale_qtable(&QTABLE_LUMA, 1);
        let q100 = scale_qtable(&QTABLE_LUMA, 100);
        assert!(q1.iter().all(|&v| v == 255), "quality=1 应全 255（最粗糙）");
        assert!(q100.iter().all(|&v| (1..=2).contains(&v)), "quality=100 应接近全 1");
        let _ = q100;
    }
}
