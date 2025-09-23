#[cfg(all(target_os = "zkvm", target_arch = "riscv32"))]
use crate::riscv_zkvm_ops::*;
use ark_ec::{twisted_edwards::TECurveConfig, PrimeGroup, ScalarMul, VariableBaseMSM};
pub use ark_ed_on_bls12_381_bandersnatch::Fr;
use ark_ed_on_bls12_381_bandersnatch::{BandersnatchConfig, EdwardsAffine, EdwardsProjective, Fq};
use ark_ff::{
    batch_inversion, serial_batch_inversion_and_mul, BigInteger, Field, One, PrimeField, Zero,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, Eq)]
pub struct Element(pub EdwardsProjective);

impl PartialEq for Element {
    fn eq(&self, other: &Self) -> bool {
        let x1 = self.0.x;
        let y1 = self.0.y;

        let x2 = other.0.x;
        let y2 = other.0.y;

        // One should not be able to generate this point, unless they have assigned `x` and `y`
        // to be 0 directly and have bypassed the API.
        //
        // This is possible in languages such as C, we will leave this check here
        // for those who are using this as a reference, or in the case that there is some way to
        // create an Element and bypass the checks.
        if x1.is_zero() & y1.is_zero() {
            return false;
        }
        if x2.is_zero() & y2.is_zero() {
            return false;
        }

        (x1 * y2) == (x2 * y1)
    }
}

impl Element {
    pub fn to_bytes(&self) -> [u8; 32] {
        // We assume that internally this point is "correct"
        //
        // We serialize a correct point by serializing the x co-ordinate times sign(y)
        let affine = EdwardsAffine::from(self.0);
        let x = if is_positive(affine.y) {
            affine.x
        } else {
            -affine.x
        };
        let mut bytes = [0u8; 32];
        x.serialize_compressed(&mut bytes[..])
            .expect("serialization failed");

        // reverse bytes to big endian, for interoperability
        bytes.reverse();

        bytes
    }

    // Do not compare the results of this function.
    //
    // This is because if (x, -y) is on the curve, then (x,y) is also on the curve.
    // This method will return two different byte arrays for each of these.
    //
    // TODO: perhaps change this so that it chooses a representative, ie respecting the equivalence class
    pub fn to_bytes_uncompressed(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        self.0
            .serialize_uncompressed(&mut bytes[..])
            .expect("cannot serialize point as an uncompressed byte array");
        bytes
    }

    pub fn from_bytes_unchecked_uncompressed(bytes: [u8; 64]) -> Self {
        let point = EdwardsProjective::deserialize_uncompressed_unchecked(&bytes[..])
            .expect("could not deserialize byte array into a point");
        Self(point)
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Element> {
        // Switch from big endian to little endian, as arkworks library uses little endian
        let mut bytes = bytes.to_vec();
        bytes.reverse();

        let x: Fq = Fq::deserialize_compressed(&bytes[..]).ok()?;

        let return_positive_y = true;

        // Construct a point that is in the group -- this point may or may not be in the prime subgroup
        let point = Self::get_point_from_x(x, return_positive_y)?;

        let element = Element(EdwardsProjective::new_unchecked(
            point.x,
            point.y,
            point.x * point.y,
            Fq::one(),
        ));

        // Check if the point is in the correct subgroup
        //
        // Check legendre - checks whether 1 - ax^2 is a QR
        if !element.subgroup_check() {
            return None;
        }

        Some(element)
    }

    pub const fn compressed_serialized_size() -> usize {
        32
    }

    pub fn prime_subgroup_generator() -> Element {
        Element(EdwardsProjective::generator())
    }

    fn get_point_from_x(x: Fq, choose_largest: bool) -> Option<EdwardsAffine> {
        let dx_squared_minus_one = BandersnatchConfig::COEFF_D * x.square() - Fq::one();
        let ax_squared_minus_one = BandersnatchConfig::COEFF_A * x.square() - Fq::one();
        let y_squared = ax_squared_minus_one / dx_squared_minus_one;

        let y = y_squared.sqrt()?;

        let is_largest = is_positive(y);

        let y = if is_largest && choose_largest { y } else { -y };

        Some(EdwardsAffine::new_unchecked(x, y))
    }

    fn map_to_field(&self) -> Fq {
        self.0.x / self.0.y
    }

    // Note: This is a 2 to 1 map, but the two preimages are identified to be the same
    pub fn map_to_scalar_field(&self) -> Fr {
        use ark_ff::PrimeField;

        let base_field = self.map_to_field();

        let mut bytes = [0u8; 32];
        base_field
            .serialize_compressed(&mut bytes[..])
            .expect("could not serialize point into a 32 byte array");
        Fr::from_le_bytes_mod_order(&bytes)
    }

    pub fn batch_map_to_scalar_field(elements: &[Element]) -> Vec<Fr> {
        use ark_ff::PrimeField;

        let mut x_div_y = Vec::with_capacity(elements.len());
        for element in elements {
            let y = element.0.y;
            x_div_y.push(y);
        }
        batch_inversion(&mut x_div_y);

        for i in 0..elements.len() {
            x_div_y[i] *= elements[i].0.x;
        }

        let mut scalars = Vec::with_capacity(elements.len());
        for element in x_div_y {
            let mut bytes = [0u8; 32];
            element
                .serialize_compressed(&mut bytes[..])
                .expect("could not serialize point into a 32 byte array");
            scalars.push(Fr::from_le_bytes_mod_order(&bytes));
        }

        scalars
    }

    // serial optimized version
    pub fn serial_batch_map_to_scalar_field(elements: Vec<[u8; 64]>) -> Vec<Fr> {
        use ark_ff::PrimeField;

        let (xs, mut ys): (Vec<Fq>, Vec<Fq>) = elements
            .into_iter()
            .map(|e| {
                let e = Element::from_bytes_unchecked_uncompressed(e);
                (e.0.x, e.0.y)
            })
            .unzip();

        serial_batch_inversion_and_mul(&mut ys, &Fq::one());

        ys.iter_mut().zip(xs.iter()).for_each(|(y, x)| {
            *y *= x;
        });

        ys.iter()
            .map(|e| {
                let mut bytes = [0u8; 32];
                e.serialize_compressed(&mut bytes[..])
                    .expect("could not serialize point into a 32 byte array");
                Fr::from_le_bytes_mod_order(&bytes)
            })
            .collect()
    }

    pub fn zero() -> Element {
        Element(EdwardsProjective::zero())
    }

    pub fn is_zero(&self) -> bool {
        *self == Element::zero()
    }

    pub(crate) fn subgroup_check(&self) -> bool {
        legendre_check_point(&self.0.x)
    }
}

// The lexographically largest value is defined to be the positive value
fn is_positive(coordinate: Fq) -> bool {
    coordinate > -coordinate
}

fn legendre_check_point(x: &Fq) -> bool {
    let res = Fq::one() - (BandersnatchConfig::COEFF_A * x.square());
    res.legendre().is_qr()
}

pub fn multi_scalar_mul(bases: &[Element], scalars: &[Fr]) -> Element {
    #[cfg(all(target_os = "zkvm", target_arch = "riscv32"))]
    {
        msm_bigint_wnaf_zkvm(bases, scalars)
    }

    #[cfg(not(all(target_os = "zkvm", target_arch = "riscv32")))]
    {
        let bases_inner: Vec<_> = bases.iter().map(|element| element.0).collect();

        // XXX: Converting all of these to affine hurts performance
        let bases = EdwardsProjective::batch_convert_to_mul_base(&bases_inner);

        let result = EdwardsProjective::msm(&bases, scalars)
            .expect("number of bases should equal number of scalars");

        Element(result)
    }
}

#[allow(dead_code)]
pub fn multi_scalar_mul_based_on_scalar_mul(bases: &[Element], scalars: &[Fr]) -> Element {
    let mut result = Element::zero();
    for (base, scalar) in bases.iter().zip(scalars.iter()) {
        result = result + scalar_mul(base, scalar);
    }
    result
}

pub fn scalar_mul(base: &Element, scalar: &Fr) -> Element {
    #[cfg(all(target_os = "zkvm", target_arch = "riscv32"))]
    {
        return scalar_mul_zkvm(base, scalar);
    }

    #[cfg(not(all(target_os = "zkvm", target_arch = "riscv32")))]
    {
        scalar_mul_com(base, scalar)
    }
}

pub fn scalar_mul_com(base: &Element, scalar: &Fr) -> Element {
    // 经典的二进制展开算法（从低位到高位扫描）
    let mut result = Element::zero(); // 初始化为无穷远点
    let mut temp = base.clone(); // 当前倍点

    // 将标量转换为大整数表示
    let scalar_bigint = scalar.into_bigint();

    // 获取标量的位数（256位）
    let scalar_bits = scalar_bigint.to_bytes_le(); // 使用小端字节序

    // 从最低位到最高位逐位处理
    for (byte_index, &byte) in scalar_bits.iter().enumerate() {
        for bit_index in 0..8 {
            // 计算当前位在整个256位中的位置
            let bit_position = byte_index * 8 + bit_index;

            // 如果已经处理完所有有效位，则退出
            if bit_position >= 256 {
                break;
            }

            // 检查当前位是否为1
            if (byte >> bit_index) & 1 != 0 {
                result = result + temp.clone();
            }

            // 如果不是最高位，则将temp加倍
            if bit_position < 255 {
                temp = temp + temp;
            }
        }
    }

    result
}
#[allow(dead_code)]
pub fn test_scalar_mul_large_risc0() {
    // 测试大数标量乘法
    let base = Element::prime_subgroup_generator();
    let scalar = Fr::from(8u64);
    let result_scalar_mul = scalar_mul(&base, &scalar);

    // 使用 multi_scalar_mul 进行计算
    let bases = vec![base.clone()];
    let scalars = vec![scalar];
    let result_multi_scalar_mul = multi_scalar_mul(&bases, &scalars);

    // 验证两种方法的结果是否相同
    assert_eq!(
        result_scalar_mul, result_multi_scalar_mul,
        "scalar_mul and multi_scalar_mul should produce the same result"
    );

    let expected_bytes = result_multi_scalar_mul.to_bytes_uncompressed();
    let expected_hex_string: String = expected_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    println!("expected (hex): {}", expected_hex_string);
    let result_bytes = result_scalar_mul.to_bytes_uncompressed();
    let result_hex_string: String = result_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    println!("result (hex): {}", result_hex_string);
    println!(
        "scalar_mul and multi_scalar_mul produce the same result: {}",
        result_scalar_mul == result_multi_scalar_mul
    );
}
#[allow(dead_code)]
pub fn correctness_for_debug_risc0() {
    let basis_num = 8;
    let mut basic_crs = Vec::with_capacity(basis_num);
    for i in 0..basis_num {
        basic_crs.push(Element::prime_subgroup_generator() * Fr::from((i + 1) as u64));
    }
    let scalar = Fr::from_str(
        "13108968793781547619861935127046491459309155893440570251786403306729687672800",
    )
    .unwrap();

    // 创建测试标量
    let mut scalars = Vec::with_capacity(basis_num);
    // for i in 0..basis_num {
    //     scalars.push(Fr::from((i + 1) as u64));
    // }
    for i in 0..basis_num {
        scalars.push(scalar - Fr::from(i as u64));
    }

    // 使用 multi_scalar_mul 进行计算
    let result = multi_scalar_mul(&basic_crs, &scalars);
    println!("{:?}", result);
}
#[allow(dead_code)]
pub(crate) fn msm_bigint_wnaf(bases: &[Element], scalars: &[Fr]) -> Element {
    #[cfg(all(target_os = "zkvm", target_arch = "riscv32"))]
    {
        msm_bigint_wnaf_zkvm(bases, scalars)
    }

    #[cfg(not(all(target_os = "zkvm", target_arch = "riscv32")))]
    {
        msm_bigint_wnaf_com(bases, scalars)
    }
}
#[allow(dead_code)]
pub(crate) fn msm_bigint_wnaf_com(bases: &[Element], scalars: &[Fr]) -> Element {
    let size = core::cmp::min(bases.len(), scalars.len());
    let scalars = &scalars[..size];
    let bases = &bases[..size];

    // 将 Fr 转为 BigInt，供 make_digits 使用
    let bigints: Vec<_> = scalars.iter().map(|s| s.into_bigint()).collect();

    // 选择窗口大小 c
    let c = if size < 32 {
        3
    } else {
        ln_without_floats(size) + 2
    };

    // 按标量比特宽度切分 wNAF 窗口
    let num_bits = Fr::MODULUS_BIT_SIZE as usize;
    let digits_count = num_bits.div_ceil(c);

    // 用 BigInt 展开 wNAF 数位
    let scalar_digits = bigints
        .iter()
        .flat_map(|b| make_digits(b, c, num_bits))
        .collect::<Vec<_>>();

    let zero = Element::zero();

    // 对每个窗口独立累加对应桶
    let window_sums: Vec<_> = (0..digits_count)
        .into_iter()
        .map(|i| {
            let mut buckets = vec![zero; 1 << c];

            for (digits, base) in scalar_digits.chunks(digits_count).zip(bases) {
                let d = digits[i];
                if d > 0 {
                    buckets[(d - 1) as usize] += *base;
                } else if d < 0 {
                    buckets[(-d - 1) as usize] += -*base;
                }
            }

            // 反向前缀和
            let mut running_sum = Element::zero();
            let mut res = Element::zero();
            for b in buckets.into_iter().rev() {
                running_sum += b;
                res += running_sum;
            }
            res
        })
        .collect();

    // 最低窗的和
    let lowest = *window_sums.first().unwrap();

    // 从高到低窗回代，每窗做 c 次倍点
    lowest
        + window_sums[1..]
            .iter()
            .rev()
            .fold(Element::zero(), |mut total, sum_i| {
                total += *sum_i;
                for _ in 0..c {
                    total = Element(total.0 + total.0);
                }
                total
            })
}

/// floor(log2(n)) 的无浮点实现（n>0）
#[allow(dead_code)]
#[inline]
fn ln_without_floats(n: usize) -> usize {
    // SAFETY: n>0 时合法；上层已保证 size>0
    usize::BITS as usize - 1 - n.leading_zeros() as usize
}

/// 从标量大整数构造 wNAF 数位（来自 gemini 实现，做了内联）
fn make_digits(a: &impl BigInteger, w: usize, num_bits: usize) -> impl Iterator<Item = i64> + '_ {
    let scalar = a.as_ref();
    let radix: u64 = 1 << w;
    let window_mask: u64 = radix - 1;

    let mut carry = 0u64;
    let num_bits = if num_bits == 0 {
        a.num_bits() as usize
    } else {
        num_bits
    };
    let digits_count = num_bits.div_ceil(w);

    (0..digits_count).map(move |i| {
        let bit_offset = i * w;
        let u64_idx = bit_offset / 64;
        let bit_idx = bit_offset % 64;

        let bit_buf = if bit_idx < 64 - w || u64_idx == scalar.len() - 1 {
            scalar[u64_idx] >> bit_idx
        } else {
            (scalar[u64_idx] >> bit_idx) | (scalar[1 + u64_idx] << (64 - bit_idx))
        };

        let coef = carry + (bit_buf & window_mask); // [0, 2^w)
        carry = (coef + radix / 2) >> w;

        let mut digit = (coef as i64) - (carry << w) as i64;
        if i == digits_count - 1 {
            digit += (carry << w) as i64;
        }
        digit
    })
}
#[allow(dead_code)]
pub fn test_msm_bigint_wnaf_basic() {
    // 测试基本的 wNAF MSM 实现
    let base1 = Element::prime_subgroup_generator();
    let base2 = base1 + base1;
    let scalar1 = Fr::from(3u64);
    let scalar2 = Fr::from(4u64);

    let bases = vec![base1.clone(), base2.clone()];
    let scalars = vec![scalar1, scalar2];

    let result_wnaf = msm_bigint_wnaf(&bases, &scalars);
    let result_arkworks = multi_scalar_mul(&bases, &scalars);

    assert_eq!(
        result_wnaf, result_arkworks,
        "wNAF MSM should match arkworks MSM"
    );
    println!(
        "test_msm_bigint_wnaf_basic is ok,result is{:?}",
        result_wnaf
    );
}

#[allow(dead_code)]
pub fn test_msm_bigint_wnaf_multiple_large() {
    // 测试多个大标量的 wNAF MSM
    let basis_num = 16;
    let mut bases = Vec::with_capacity(basis_num);
    let mut scalars = Vec::with_capacity(basis_num);

    let base_scalar = Fr::from_str(
        "13108968793781547619861935127046491459309155893440570251786403306729687672800",
    )
    .unwrap();

    for i in 0..basis_num {
        bases.push(Element::prime_subgroup_generator() * Fr::from((i + 1) as u64));
        scalars.push(base_scalar - Fr::from(i as u64));
    }

    let _result_wnaf = msm_bigint_wnaf(&bases, &scalars);
    // let result_arkworks = multi_scalar_mul_com(&bases, &scalars);
    //
    // assert_eq!(result_wnaf, result_arkworks);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_serialize::CanonicalSerialize;

    #[test]
    fn consistent_group_to_field() {
        // In python this is called commitment_to_field
        // print(commitment_to_field(Point(generator=True)).to_bytes(32, "little").hex())
        let expected = "d1e7de2aaea9603d5bc6c208d319596376556ecd8336671ba7670c2139772d14";

        let generator = Element::prime_subgroup_generator();
        let mut bytes = [0u8; 32];
        generator
            .map_to_scalar_field()
            .serialize_compressed(&mut bytes[..])
            .unwrap();
        assert_eq!(hex::encode(bytes), expected);
    }

    #[test]
    fn from_bytes_unchecked_uncompressed_roundtrip() {
        let generator = Element::prime_subgroup_generator();
        let bytes = generator.to_bytes_uncompressed();
        let element = Element::from_bytes_unchecked_uncompressed(bytes);

        assert_eq!(element, generator)
    }

    #[test]
    fn from_batch_map_to_scalar_field() {
        let mut points = Vec::new();
        for i in 0..10 {
            points.push(Element::prime_subgroup_generator() * Fr::from(i));
        }

        let got = Element::batch_map_to_scalar_field(&points);

        for i in 0..10 {
            let expected_i = points[i].map_to_scalar_field();
            assert_eq!(expected_i, got[i]);
        }
        for i in 0..10 {
            let expected_i = points[i].map_to_scalar_field();
            assert_eq!(expected_i, got[i]);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_ff::AdditiveGroup;

    // Two torsion point, *not*  point at infinity {0,-1,0,1}
    fn two_torsion() -> EdwardsProjective {
        EdwardsProjective::new_unchecked(Fq::zero(), -Fq::one(), Fq::zero(), Fq::one())
    }
    fn points_at_infinity() -> [EdwardsProjective; 2] {
        let d = BandersnatchConfig::COEFF_D;
        let a = BandersnatchConfig::COEFF_A;
        let sqrt_da = (d / a).sqrt().unwrap();

        let p1 = EdwardsProjective::new_unchecked(sqrt_da, Fq::zero(), Fq::one(), Fq::zero());
        let p2 = EdwardsProjective::new_unchecked(-sqrt_da, Fq::zero(), Fq::one(), Fq::zero());

        [p1, p2]
    }

    #[test]
    fn fixed_test_vectors() {
        let expected_bit_string = [
            "4a2c7486fd924882bf02c6908de395122843e3e05264d7991e18e7985dad51e9",
            "43aa74ef706605705989e8fd38df46873b7eae5921fbed115ac9d937399ce4d5",
            "5e5f550494159f38aa54d2ed7f11a7e93e4968617990445cc93ac8e59808c126",
            "0e7e3748db7c5c999a7bcd93d71d671f1f40090423792266f94cb27ca43fce5c",
            "14ddaa48820cb6523b9ae5fe9fe257cbbd1f3d598a28e670a40da5d1159d864a",
            "6989d1c82b2d05c74b62fb0fbdf8843adae62ff720d370e209a7b84e14548a7d",
            "26b8df6fa414bf348a3dc780ea53b70303ce49f3369212dec6fbe4b349b832bf",
            "37e46072db18f038f2cc7d3d5b5d1374c0eb86ca46f869d6a95fc2fb092c0d35",
            "2c1ce64f26e1c772282a6633fac7ca73067ae820637ce348bb2c8477d228dc7d",
            "297ab0f5a8336a7a4e2657ad7a33a66e360fb6e50812d4be3326fab73d6cee07",
            "5b285811efa7a965bd6ef5632151ebf399115fcc8f5b9b8083415ce533cc39ce",
            "1f939fa2fd457b3effb82b25d3fe8ab965f54015f108f8c09d67e696294ab626",
            "3088dcb4d3f4bacd706487648b239e0be3072ed2059d981fe04ce6525af6f1b8",
            "35fbc386a16d0227ff8673bc3760ad6b11009f749bb82d4facaea67f58fc60ed",
            "00f29b4f3255e318438f0a31e058e4c081085426adb0479f14c64985d0b956e0",
            "3fa4384b2fa0ecc3c0582223602921daaa893a97b64bdf94dcaa504e8b7b9e5f",
        ];

        let mut points = vec![];
        let mut point = Element::prime_subgroup_generator();
        for (i, _) in expected_bit_string.into_iter().enumerate() {
            let byts = hex::encode(point.to_bytes());
            assert_eq!(byts, expected_bit_string[i], "index {i} does not match");

            points.push(point);
            point = Element(point.0.double())
        }
    }

    #[test]
    fn ser_der_roundtrip() {
        let point = EdwardsProjective::generator();

        let two_torsion_point = two_torsion();

        let element1 = Element(point);
        let bytes1 = element1.to_bytes();

        let element2 = Element(point + two_torsion_point);
        let bytes2 = element2.to_bytes();

        assert_eq!(bytes1, bytes2);

        let got = Element::from_bytes(&bytes1).expect("points are in the valid subgroup");

        assert!(got == element1);
        assert!(got == element2);
    }
    #[test]
    fn check_infinity_does_not_pass_legendre() {
        // We cannot use the points at infinity themselves
        // as they have Z=0, which will panic when converting to
        // affine co-ordinates. So we create a point which is
        // the sum of the point at infinity and another point
        let point = points_at_infinity()[0];
        let gen = EdwardsProjective::generator();
        let gen2 = gen + gen + gen + gen;

        let res = point + gen + gen2;

        let element1 = Element(res);
        let bytes1 = element1.to_bytes();

        if Element::from_bytes(&bytes1).is_some() {
            panic!("point contains a point at infinity and should not have passed deserialization")
        }
    }

    #[test]
    fn two_torsion_correct() {
        let two_torsion_point = two_torsion();
        assert!(!two_torsion_point.is_zero());

        let result = two_torsion_point.double();
        assert!(result.is_zero());

        let [inf1, inf2] = points_at_infinity();
        assert!(!inf1.is_zero());
        assert!(!inf2.is_zero());

        assert!(inf1.double().is_zero());
        assert!(inf2.double().is_zero());
    }
}
