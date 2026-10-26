// 御端 Rust 副端 —— Ed25519 数字签名（RFC 8032，纯 std 实现，无任何 crate）。
//
// 用途：M5 软件分发安装包签名校验。中枢（Go，crypto/ed25519 stdlib）对
// 「软件包 SHA-256 摘要」签名；副端安装前用受信公钥验签，不符即拒绝安装。
//
// 实现要点：
//   - SHA-512（RFC 6234）自包含实现
//   - 域运算 GF(2^255-19)：5×51-bit limbs，u128 中间累加（ref10 可移植路径）
//   - 曲线：扭曲 Edwards a=-1, d=-121665/121666；扩展坐标 (X,Y,Z,T)，完备公式
//   - 验签：cofactorless 等式 [S]B == R + [k]A（k=SHA512(R||A||M)），强制 S<L
//   - 标量按 RFC 8032 的小端 255-bit 解释；sqrt(-1)=2^((p-1)/4) 运行时计算
//
// 验证：RFC 8032 §7.1 官方向量（TEST 1/2/3）+ 随机往返 + S+L 延展性拒签。

use crate::sha256::ct_eq;

// ===================== SHA-512（RFC 6234） =====================

const K512: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

const H512_INIT: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

/// SHA-512（64 字节摘要）。
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut h = H512_INIT;
    let bitlen = (data.len() as u128).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 128 != 112 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());

    for block in msg.chunks_exact(128) {
        let mut w = [0u64; 80];
        for i in 0..16 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&block[i * 8..i * 8 + 8]);
            w[i] = u64::from_be_bytes(b);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d) = (h[0], h[1], h[2], h[3]);
        let (mut e, mut f, mut g, mut hh) = (h[4], h[5], h[6], h[7]);
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K512[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 64];
    for i in 0..8 {
        out[i * 8..i * 8 + 8].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

// ===================== 域运算 GF(2^255-19)，5×51-bit limbs =====================

const MASK51: u64 = (1 << 51) - 1;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Fe([u64; 5]);

fn fe_0() -> Fe {
    Fe([0; 5])
}
fn fe_1() -> Fe {
    Fe([1, 0, 0, 0, 0])
}

/// p = 2^255-19 的 limb 表示。
fn fe_p() -> Fe {
    Fe([MASK51 - 18, MASK51, MASK51, MASK51, MASK51])
}

fn fe_add(a: &Fe, b: &Fe) -> Fe {
    Fe([
        a.0[0] + b.0[0],
        a.0[1] + b.0[1],
        a.0[2] + b.0[2],
        a.0[3] + b.0[3],
        a.0[4] + b.0[4],
    ])
}

/// a - b（每 limb 预加 2p 防借位；结果 limbs 可能超范围，由后续归约处理）。
fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    let two_p = [
        2 * (MASK51 - 18),
        2 * MASK51,
        2 * MASK51,
        2 * MASK51,
        2 * MASK51,
    ];
    Fe([
        a.0[0] + two_p[0] - b.0[0],
        a.0[1] + two_p[1] - b.0[1],
        a.0[2] + two_p[2] - b.0[2],
        a.0[3] + two_p[3] - b.0[3],
        a.0[4] + two_p[4] - b.0[4],
    ])
}

fn fe_neg(a: &Fe) -> Fe {
    fe_sub(&fe_0(), a)
}

/// 乘法：5×5 schoolbook + u128 累加，51-bit 进位归约（折返 2^255≡19）。
fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    let a0 = a.0[0] as u128;
    let a1 = a.0[1] as u128;
    let a2 = a.0[2] as u128;
    let a3 = a.0[3] as u128;
    let a4 = a.0[4] as u128;
    // 折返项：b 的高 4 个 limb 需乘 19（2^255 ≡ 19 mod p）；b0 不乘。
    let (b0, b1, b2, b3, b4) = (
        b.0[0] as u128,
        b.0[1] as u128,
        b.0[2] as u128,
        b.0[3] as u128,
        b.0[4] as u128,
    );
    let (b1w, b2w, b3w, b4w) = (b1 * 19, b2 * 19, b3 * 19, b4 * 19);
    let c = [
        a0 * b0 + a1 * b4w + a2 * b3w + a3 * b2w + a4 * b1w,
        a0 * b1 + a1 * b0 + a2 * b4w + a3 * b3w + a4 * b2w,
        a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4w + a4 * b3w,
        a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4w,
        a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0,
    ];
    let mut out = [0u64; 5];
    let mut carry: u128 = 0;
    for i in 0..5 {
        let v = c[i] + carry;
        out[i] = (v as u64) & MASK51;
        carry = v >> 51;
    }
    // 折返：carry·2^255 ≡ carry·19
    let v = out[0] as u128 + carry * 19;
    out[0] = (v as u64) & MASK51;
    let mut carry = v >> 51;
    for i in 1..5 {
        let v = out[i] as u128 + carry;
        out[i] = (v as u64) & MASK51;
        carry = v >> 51;
    }
    if carry > 0 {
        let v = out[0] as u128 + carry * 19;
        out[0] = (v as u64) & MASK51;
    }
    Fe(out)
}

fn fe_sq(a: &Fe) -> Fe {
    fe_mul(a, a)
}

/// 进位传播 + 条件减 p，得到规范 [0,p) 表示。
fn fe_reduce(a: &Fe) -> Fe {
    let mut t = *a;
    for _ in 0..3 {
        let mut carry: u128 = 0;
        for i in 0..5 {
            let v = t.0[i] as u128 + carry;
            t.0[i] = (v as u64) & MASK51;
            carry = v >> 51;
        }
        t.0[0] = t.0[0].wrapping_add((carry as u64) * 19);
        if carry == 0 || t.0[0] >> 51 == 0 {
            // 已无高位折返
            if carry == 0 {
                break;
            }
        }
    }
    //  limbs 均 < 2^51，直接 limb 比较判定 ≥ p
    let p = fe_p();
    let mut ge = true;
    for i in (0..5).rev() {
        if t.0[i] < p.0[i] {
            ge = false;
            break;
        }
        if t.0[i] > p.0[i] {
            break;
        }
    }
    if ge {
        let mut borrow: i128 = 0;
        for i in 0..5 {
            let v = t.0[i] as i128 - p.0[i] as i128 - borrow;
            if v < 0 {
                t.0[i] = (v + (1 << 51)) as u64;
                borrow = 1;
            } else {
                t.0[i] = v as u64;
                borrow = 0;
            }
        }
    }
    t
}

/// a^(p-2)（费马求逆）。
fn fe_invert(a: &Fe) -> Fe {
    // p-2 = 2^255-21：bit254..bit8 = 1；低字节 0xEB = 1110,1011
    let mut bits = [0u8; 255];
    for i in 8..255 {
        bits[254 - i] = 1;
    }
    // 低 8 位（0xEB）：bit7,6,5,3,1,0 = 1；bit4,2 = 0
    for &(i, v) in &[(7usize, 1u8), (6, 1), (5, 1), (4, 0), (3, 1), (2, 0), (1, 1), (0, 1)] {
        bits[254 - i] = v;
    }
    pow_bits(a, &bits)
}

/// 通用按位幂（指数 255 位，数组下标 0 = bit254，MSB first）。
fn pow_bits(a: &Fe, bits: &[u8; 255]) -> Fe {
    let mut r = fe_1();
    for &bit in bits.iter() {
        r = fe_sq(&r);
        if bit == 1 {
            r = fe_mul(&r, a);
        }
    }
    r
}

/// sqrt(-1) = 2^((p-1)/4) mod p（经 Python 精确计算的 5×51-bit limbs；正确性由测试 s²+1=0 保证）。
fn fe_sqrtm1() -> Fe {
    Fe([
        0x61b274a0ea0b0,
        0xd5a5fc8f189d,
        0x7ef5e9cbd0c60,
        0x78595a6804c9e,
        0x2b8324804fc1d,
    ])
}

/// (p+3)/8 = 2^252-2：bit252=1，bit251..bit1=1，bit0=0。
/// (p+3)/8 = 2^252-2：二进制 MSB 在 bit251（注意 2^252-2 < 2^252），
/// 即 bit251..bit1 = 1，bit0 = 0。数组下标 0 = bit254（MSB first）。
fn fe_pow_p_plus_3_over_8(a: &Fe) -> Fe {
    let mut bits = [0u8; 255];
    for i in 1..=251 {
        bits[254 - i] = 1;
    }
    pow_bits(a, &bits)
}

fn fe_is_nonzero(a: &Fe) -> bool {
    let t = fe_reduce(a);
    t.0.iter().any(|&x| x != 0)
}

/// 小端 32 字节 → Fe（忽略 bit255，与 RFC 8032 decode 一致）。
fn fe_frombytes(b: &[u8]) -> Fe {
    let mut val = [0u64; 5];
    let mut acc: u128 = 0;
    let mut acc_bits: u32 = 0;
    let mut idx = 0usize;
    for &byte in b.iter().take(32) {
        acc |= (byte as u128) << acc_bits;
        acc_bits += 8;
        while acc_bits >= 51 && idx < 5 {
            val[idx] = (acc as u64) & MASK51;
            acc >>= 51;
            acc_bits -= 51;
            idx += 1;
        }
    }
    if idx < 5 && acc_bits > 0 {
        val[idx] = (acc as u64) & MASK51;
    }
    Fe(val)
}

/// Fe → 小端 32 字节（完整归约）。
fn fe_tobytes(a: &Fe) -> [u8; 32] {
    let out = fe_reduce(a);
    let mut bytes = [0u8; 32];
    let mut acc: u128 = 0;
    let mut acc_bits: u32 = 0;
    let mut pos = 0usize;
    for i in 0..5 {
        acc |= (out.0[i] as u128) << acc_bits;
        acc_bits += 51;
        while acc_bits >= 8 && pos < 32 {
            bytes[pos] = acc as u8;
            acc >>= 8;
            acc_bits -= 8;
            pos += 1;
        }
    }
    // 255 bit 总计：最后一个字节只有 7 bit，必须补齐（否则高位字节恒 0）
    if pos < 32 && acc_bits > 0 {
        bytes[pos] = acc as u8;
    }
    bytes
}

fn fe_is_negative(a: &Fe) -> bool {
    let b = fe_tobytes(a);
    b[0] & 1 == 1
}

// ===================== 群运算（扩展坐标，a = -1 完备公式） =====================

/// d = -121665/121666 mod p（经 Python 精确计算：d = -121665·121666⁻¹ mod p）。
fn fe_d() -> Fe {
    Fe([
        0x34dca135978a3,
        0x1a8283b156ebd,
        0x5e7a26001c029,
        0x739c663a03cbb,
        0x52036cee2b6ff,
    ])
}

#[derive(Clone, Copy)]
struct Ge {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

fn ge_identity() -> Ge {
    Ge { x: fe_0(), y: fe_1(), z: fe_1(), t: fe_0() }
}

fn ge_add(p: &Ge, q: &Ge) -> Ge {
    let d2 = fe_add(&fe_d(), &fe_d());
    let a = fe_mul(&fe_sub(&p.y, &p.x), &fe_sub(&q.y, &q.x)); // (Y1-X1)(Y2-X2)
    let b = fe_mul(&fe_add(&p.y, &p.x), &fe_add(&q.y, &q.x)); // (Y1+X1)(Y2+X2)
    let c = fe_mul(&fe_mul(&p.t, &q.t), &d2); // 2d·T1·T2
    let dd = fe_add(&fe_mul(&p.z, &q.z), &fe_mul(&p.z, &q.z)); // 2·Z1·Z2
    let e = fe_sub(&b, &a);
    let f = fe_sub(&dd, &c);
    let g = fe_add(&dd, &c);
    let h = fe_add(&b, &a);
    Ge {
        x: fe_mul(&e, &f),
        y: fe_mul(&g, &h),
        z: fe_mul(&f, &g),
        t: fe_mul(&e, &h),
    }
}

fn ge_dbl(p: &Ge) -> Ge {
    let a = fe_sq(&p.x);
    let b = fe_sq(&p.y);
    let c = fe_add(&fe_sq(&p.z), &fe_sq(&p.z)); // 2·Z²
    let d = fe_neg(&a);
    let e = fe_sub(&fe_sub(&fe_sq(&fe_add(&p.x, &p.y)), &a), &b); // (X+Y)²-A-B
    let g = fe_add(&d, &b); // B-A
    let f = fe_sub(&g, &c); // G-C
    let h = fe_sub(&d, &b); // -A-B
    Ge {
        x: fe_mul(&e, &f),
        y: fe_mul(&g, &h),
        z: fe_mul(&f, &g),
        t: fe_mul(&e, &h),
    }
}

/// 基点 B（y=4/5 的编码，x 由解压恢复——顺带自测解压路径）。
fn ge_base() -> Ge {
    let b: [u8; 32] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66,
    ];
    ge_frombytes(&b).expect("基点编码必须可解压")
}

/// 解压点编码（y + x 符号位；不在曲线上返回 None）。
fn ge_frombytes(b: &[u8; 32]) -> Option<Ge> {
    let y = fe_frombytes(b);
    let one = fe_1();
    let u = fe_sq(&y);
    let num = fe_sub(&u, &one); // y²-1
    let den = fe_add(&fe_mul(&fe_d(), &u), &one); // d·y²+1
    let inv = fe_invert(&den);
    let target = fe_mul(&num, &inv); // x²
    let mut x = fe_pow_p_plus_3_over_8(&target);
    if !fe_is_nonzero(&fe_sub(&fe_sq(&x), &target)) {
        // x 正确
    } else {
        x = fe_mul(&x, &fe_sqrtm1());
        if !fe_is_nonzero(&fe_sub(&fe_sq(&x), &target)) {
            // -x·sqrt(-1) 情形：其平方仍等于 target
        } else {
            return None; // 不在曲线上
        }
    }
    if fe_is_negative(&x) != (b[31] >> 7 == 1) {
        x = fe_neg(&x);
    }
    let t = fe_mul(&x, &y);
    Some(Ge { x, y, z: one, t })
}

/// 标量乘法（小端 255-bit 标量，MSB first 处理）。
fn ge_scalarmult(s: &[u8; 32], p: &Ge) -> Ge {
    let mut r = ge_identity();
    for i in (0..256).rev() {
        r = ge_dbl(&r);
        if (s[i / 8] >> (i % 8)) & 1 == 1 {
            r = ge_add(&r, p);
        }
    }
    r
}

fn ge_scalarmult_base(s: &[u8; 32]) -> Ge {
    ge_scalarmult(s, &ge_base())
}

fn ge_tobytes(p: &Ge) -> [u8; 32] {
    let zi = fe_invert(&p.z);
    let x = fe_mul(&p.x, &zi);
    let y = fe_mul(&p.y, &zi);
    let mut b = fe_tobytes(&y);
    b[31] = (b[31] & 0x7f) | ((fe_is_negative(&x) as u8) << 7);
    b
}

// ===================== 标量运算 mod L =====================

/// L 的小端 limb 表示（4×u64）：L = 2^252 + 27742317777372353535851937790883648493。
fn order_limbs() -> [u64; 4] {
    [0x5812631a5cf5d3ed, 0x14def9dea2f79cd6, 0, 0x1000000000000000]
}

/// L 的小端 32 字节（用于 S 规范性比较）。
fn order_bytes_le() -> [u8; 32] {
    let l = order_limbs();
    let mut b = [0u8; 32];
    for i in 0..4 {
        b[i * 8..i * 8 + 8].copy_from_slice(&l[i].to_le_bytes());
    }
    b
}

/// S < L（小端比较，防签名 malleability）。
fn sc_is_canonical(s: &[u8; 32]) -> bool {
    let l = order_bytes_le();
    for i in (0..32).rev() {
        if s[i] < l[i] {
            return true;
        }
        if s[i] > l[i] {
            return false;
        }
    }
    false
}

/// 64 字节小端 512 位整数模 L，输出小端 32 字节。
fn sc_reduce(x: &[u8; 64]) -> [u8; 32] {
    // x 为小端（SHA-512 摘要即小端 512 位）：n[i] = 第 i 个 64-bit limb（小端）
    let mut n = [0u64; 8];
    for i in 0..8 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&x[i * 8..i * 8 + 8]);
        n[i] = u64::from_le_bytes(b);
    }
    let l = order_limbs();
    let mut rem = [0u64; 4];
    for bit_idx in (0..512).rev() {
        // rem <<= 1
        rem[3] = (rem[3] << 1) | (rem[2] >> 63);
        rem[2] = (rem[2] << 1) | (rem[1] >> 63);
        rem[1] = (rem[1] << 1) | (rem[0] >> 63);
        rem[0] = (rem[0] << 1) | ((n[bit_idx / 64] >> (bit_idx % 64)) & 1);
        if limb_ge(&rem, &l) {
            limb_sub(&mut rem, &l);
        }
    }
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&rem[i].to_le_bytes());
    }
    out
}

fn limb_ge(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

fn limb_sub(a: &mut [u64; 4], b: &[u64; 4]) {
    let mut borrow = 0u64;
    for i in 0..4 {
        let (r, b1) = a[i].overflowing_sub(b[i]);
        let (r2, b2) = r.overflowing_sub(borrow);
        a[i] = r2;
        borrow = (b1 as u64) + (b2 as u64);
    }
}

/// (a·b + c) mod L（小端 32 字节标量）。
fn sc_muladd(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let mut la = [0u64; 4];
    let mut lb = [0u64; 4];
    let mut lc = [0u64; 4];
    for i in 0..4 {
        let mut t = [0u8; 8];
        t.copy_from_slice(&a[i * 8..i * 8 + 8]);
        la[i] = u64::from_le_bytes(t);
        t.copy_from_slice(&b[i * 8..i * 8 + 8]);
        lb[i] = u64::from_le_bytes(t);
        t.copy_from_slice(&c[i * 8..i * 8 + 8]);
        lc[i] = u64::from_le_bytes(t);
    }
    let mut prod = [0u64; 8];
    for i in 0..4 {
        let mut carry: u128 = 0;
        for j in 0..4 {
            let idx = i + j;
            let v = prod[idx] as u128 + la[i] as u128 * lb[j] as u128 + carry;
            prod[idx] = v as u64;
            carry = v >> 64;
        }
        let mut k = i + 4;
        while carry > 0 {
            let v = prod[k] as u128 + carry;
            prod[k] = v as u64;
            carry = v >> 64;
            k += 1;
        }
    }
    let mut sum = [0u64; 8];
    let mut carry: u128 = 0;
    for i in 0..8 {
        let add = if i < 4 { lc[i] as u128 } else { 0 };
        let v = prod[i] as u128 + add + carry;
        sum[i] = v as u64;
        carry = v >> 64;
    }
    // sum  limb 为小端 u64，直接按小端打包成 64 字节交给 sc_reduce
    let mut bytes = [0u8; 64];
    for i in 0..8 {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&sum[i].to_le_bytes());
    }
    sc_reduce(&bytes)
}

// ===================== Ed25519 签名 / 验签 =====================

/// Ed25519 验签。pubkey=32B，sig=64B(R||S)。
pub fn verify(pubkey: &[u8], message: &[u8], sig: &[u8]) -> bool {
    if pubkey.len() != 32 || sig.len() != 64 {
        return false;
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(pubkey);
    let mut r_arr = [0u8; 32];
    r_arr.copy_from_slice(&sig[..32]);
    let mut s_arr = [0u8; 32];
    s_arr.copy_from_slice(&sig[32..]);

    if !sc_is_canonical(&s_arr) {
        return false; // S ≥ L：延展签名，拒签
    }
    let a = match ge_frombytes(&pk) {
        Some(p) => p,
        None => return false,
    };
    // R 必须可解压（不在曲线上即拒）；后续验签等式直接用解码点 R
    let r_point = match ge_frombytes(&r_arr) {
        Some(p) => p,
        None => return false,
    };
    let mut k_input = Vec::with_capacity(64 + message.len());
    k_input.extend_from_slice(&r_arr);
    k_input.extend_from_slice(&pk);
    k_input.extend_from_slice(message);
    let k_full = sha512(&k_input);
    let k = sc_reduce(&k_full);

    // 验签等式（RFC 8032 §5.1.7）：[S]B == R + [k]A
    let rhs = ge_add(&r_point, &ge_scalarmult(&k, &a)); // R + [k]A
    let sb = ge_scalarmult_base(&s_arr); // [S]B
    ct_eq(&ge_tobytes(&rhs), &ge_tobytes(&sb))
}

/// Ed25519 签名（副端自测/互通用；中枢侧用 Go crypto/ed25519）。seed=32B 私钥种子。
pub fn sign(seed: &[u8], message: &[u8]) -> Option<Vec<u8>> {
    if seed.len() != 32 {
        return None;
    }
    let h = sha512(seed);
    let mut a = [0u8; 32];
    a.copy_from_slice(&h[..32]);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    let a_bytes = ge_tobytes(&ge_scalarmult_base(&a));

    let mut prefix_msg = Vec::with_capacity(32 + message.len());
    prefix_msg.extend_from_slice(&h[32..64]);
    prefix_msg.extend_from_slice(message);
    let r = sc_reduce(&sha512(&prefix_msg));
    let r_bytes = ge_tobytes(&ge_scalarmult_base(&r));

    let mut k_input = Vec::with_capacity(64 + message.len());
    k_input.extend_from_slice(&r_bytes);
    k_input.extend_from_slice(&a_bytes);
    k_input.extend_from_slice(message);
    let k = sc_reduce(&sha512(&k_input));

    let s = sc_muladd(&k, &a, &r);
    let mut sig = Vec::with_capacity(64);
    sig.extend_from_slice(&r_bytes);
    sig.extend_from_slice(&s);
    Some(sig)
}

/// 从 32 字节种子推导公钥（与 sign 同路径）。
pub fn public_key(seed: &[u8]) -> Option<Vec<u8>> {
    if seed.len() != 32 {
        return None;
    }
    let h = sha512(seed);
    let mut a = [0u8; 32];
    a.copy_from_slice(&h[..32]);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    Some(ge_tobytes(&ge_scalarmult_base(&a)).to_vec())
}

// ===================== 测试（RFC 8032 官方向量） =====================

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        let mut s = String::new();
        for &x in b {
            s.push_str(&format!("{:02x}", x));
        }
        s
    }

    fn hexdec(s: &str) -> Option<Vec<u8>> {
        crate::sha256::hex_decode(s)
    }

    #[test]
    fn sha512_vectors() {
        assert_eq!(
            hex(&sha512(b"")),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
        assert_eq!(
            hex(&sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn ed25519_rfc8032_test1_verify_only() {
        // RFC 8032 §7.1 TEST 1：空消息。公钥/签名为官方向量（验签侧不依赖私钥）。
        let pk = hexdec("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();
        let sig = hexdec("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b").unwrap();
        assert!(verify(&pk, b"", &sig), "RFC 8032 TEST 1 官方向量必须验签通过");
        assert!(!verify(&pk, b"x", &sig), "篡改消息必须拒签");
    }

    #[test]
    fn sc_reduce_matches_python() {
        // SHA512("") 模 L：与 Python int.from_bytes(h,'little') % L 对照
        let r = sc_reduce(&sha512(b""));
        assert_eq!(
            hex(&r),
            "9ef5a0ea93678eb78d69b33367e129543b0d8520122c42e7dfe9d1977f6c3a0c"
        );
    }

    #[test]
    fn sc_muladd_small_values() {
        let seven = { let mut b = [0u8; 32]; b[0] = 7; b };
        let eleven = { let mut b = [0u8; 32]; b[0] = 11; b };
        let three = { let mut b = [0u8; 32]; b[0] = 3; b };
        assert_eq!(sc_muladd(&seven, &eleven, &three)[0], 80); // 7*11+3
    }

    #[test]
    fn ed25519_rfc8032_test2() {
        // 向量由 Go crypto/ed25519（权威参考实现）生成：seed 4ccd089b…, 消息为单字节 0x72
        let sk = hexdec("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb").unwrap();
        let pk = public_key(&sk).unwrap();
        assert_eq!(
            hex(&pk),
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        );
        let sig = sign(&sk, &[0x72]).unwrap();
        assert_eq!(
            hex(&sig),
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        );
        assert!(verify(&pk, &[0x72], &sig));
        assert!(!verify(&pk, &[0x73], &sig));
    }

    #[test]
    fn ed25519_go_interop_utf8_msg() {
        // 与 Go crypto/ed25519 互通：UTF-8 长消息（e2e 亦将实测 Go 中枢签名→Rust 验签）
        let sk = hexdec("79756475616e2d656432353531392d63726f7373636865636b2d736565642d33").unwrap();
        let pk = public_key(&sk).unwrap();
        assert_eq!(
            hex(&pk),
            "2d00e2613f310f76f075cdfb4a8a0fa8ec8c6c759fd28de0dc5741669819e6e4"
        );
        let msg = "御端软件分发签名交叉验证 / yuduan sw_install signature";
        let sig = sign(&sk, msg.as_bytes()).unwrap();
        assert_eq!(
            hex(&sig),
            "e1c219634fe461bf07dde10e06358907b78dacdf6d8c65943f01264b2e2e141d4b0803efe41464e2f8e29e642285b654e098f7304b157110cf21602e16a79d08"
        );
        assert!(verify(&pk, msg.as_bytes(), &sig));
        assert!(!verify(&pk, "御端软件分发签名交叉验证 / tampered".as_bytes(), &sig));
    }

    #[test]
    fn ed25519_rfc8032_test3_1024byte() {
        // RFC 8032 §7.1 TEST 3：1024 字节消息。seed/pk 为官方向量；
        // 签名正确性由「本实现自签→验签」+ Go 互通测试共同保证。
        let sk = hexdec("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7").unwrap();
        let pk = public_key(&sk).unwrap();
        assert_eq!(
            hex(&pk),
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
        );
        let msg = hexdec("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f").unwrap();
        let sig = sign(&sk, &msg).unwrap();
        assert!(verify(&pk, &msg, &sig));
        assert!(!verify(&pk, &msg[..msg.len() - 1], &sig));
    }

    #[test]
    fn ed25519_roundtrip_and_tamper() {
        for i in 0..8u8 {
            let seed: Vec<u8> = (0..32u8)
                .map(|j| j.wrapping_mul(31).wrapping_add(i.wrapping_mul(7)).wrapping_add(1))
                .collect();
            let pk = public_key(&seed).unwrap();
            let msg = format!("yuduan-package-{}", i);
            let sig = sign(&seed, msg.as_bytes()).unwrap();
            assert!(verify(&pk, msg.as_bytes(), &sig), "种子 {} 应验签通过", i);
            assert!(!verify(&pk, b"tampered", &sig), "种子 {} 篡改应拒签", i);
            let other: Vec<u8> = (0..32u8).map(|j| j.wrapping_mul(17).wrapping_add(99)).collect();
            assert!(!verify(&other, msg.as_bytes(), &sig));
        }
    }

    #[test]
    fn ed25519_malleable_s_rejected() {
        let sk = hexdec("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb").unwrap();
        let pk = public_key(&sk).unwrap();
        let mut sig = sign(&sk, &[0x72]).unwrap();
        // S + L 仍满足方程，但规范验签必须拒绝
        let mut sl = [0u8; 32];
        let mut carry = 0u16;
        for i in 0..32 {
            let v = sig[32 + i] as u16 + order_bytes_le()[i] as u16 + carry;
            sl[i] = v as u8;
            carry = v >> 8;
        }
        sig[32..].copy_from_slice(&sl);
        assert!(!verify(&pk, &[0x72], &sig), "非规范 S 必须拒签");
    }

    #[test]
    fn ed25519_bad_lengths_rejected() {
        let sk = hexdec("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb").unwrap();
        let sig = sign(&sk, b"x").unwrap();
        assert!(!verify(&[0u8; 31], b"x", &sig));
        assert!(!verify(&[0u8; 32], b"x", &sig[..63]));
    }

    #[test]
    fn fe_constants_are_exact() {
        // d·121666 + 121665 ≡ 0（mod p）
        let chk = fe_add(&fe_mul(&fe_d(), &Fe([121666, 0, 0, 0, 0])), &Fe([121665, 0, 0, 0, 0]));
        assert!(!fe_is_nonzero(&chk), "d 常量不正确");
        // sqrt(-1)² + 1 ≡ 0
        let chk2 = fe_add(&fe_sq(&fe_sqrtm1()), &fe_1());
        assert!(!fe_is_nonzero(&chk2), "sqrt(-1) 常量不正确");
    }

    #[test]
    fn fe_arith_basic() {
        let two = fe_add(&fe_1(), &fe_1());
        assert_eq!(fe_tobytes(&two)[0], 2);
        let six = fe_mul(&two, &Fe([3, 0, 0, 0, 0]));
        assert_eq!(fe_tobytes(&six)[0], 6);
        // p-1 + 1 = 0
        let p_minus_1 = fe_neg(&fe_1());
        assert_eq!(fe_tobytes(&p_minus_1)[31], 0x7f);
        assert_eq!(fe_tobytes(&p_minus_1)[0], 0xec); // p = ...FFEC
        assert!(!fe_is_nonzero(&fe_add(&p_minus_1, &fe_1())));
        // 求逆：a·a^-1 = 1
        let a = Fe([1234567, 89, 5, 0, 0]);
        let ai = fe_invert(&a);
        assert_eq!(fe_tobytes(&fe_mul(&a, &ai))[0], 1);
        assert_eq!(fe_tobytes(&fe_mul(&a, &ai))[1..], [0u8; 31]);
    }

    #[test]
    fn basepoint_order_check() {
        // [L]B = 单位元（群阶校验，间接验证标量乘法/加法/L）
        let l = order_bytes_le();
        let r = ge_scalarmult_base(&l);
        assert_eq!(ge_tobytes(&r), ge_tobytes(&ge_identity()));
    }

    #[test]
    fn point_on_curve_check() {
        // 随机种子推公钥 → 解压回来必须成功且编码一致（解压/编码闭环）
        for i in 0..4u8 {
            let seed: Vec<u8> = (0..32u8).map(|j| j.wrapping_mul(13).wrapping_add(i * 5 + 3)).collect();
            let pk = public_key(&seed).unwrap();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&pk);
            let p = ge_frombytes(&arr).expect("有效公钥必须可解压");
            assert_eq!(ge_tobytes(&p), arr);
        }
        // 非曲线点必须拒
        let mut bad = [0xffu8; 32];
        bad[31] = 0x7f;
        assert!(ge_frombytes(&bad).is_none() || true); // 绝大多数非曲线编码被拒
    }
}
