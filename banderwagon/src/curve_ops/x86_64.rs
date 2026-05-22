use ark_ed_on_bls12_381_bandersnatch::{EdwardsProjective, Fq};

pub(crate) fn add_affine_point(result: &mut EdwardsProjective, p2_x: &Fq, p2_y: &Fq) {
    use crate::scalar_multi_asm::*;

    let mut a = Fq::default();
    let mut b = Fq::default();
    let mut c = Fq::default();
    let mut d = Fq::default();

    mont_mul_asm(&mut a.0 .0, &result.x.0 .0, &p2_x.0 .0);
    mont_mul_asm(&mut b.0 .0, &result.y.0 .0, &p2_y.0 .0);
    mont_mul_asm(&mut c.0 .0, &p2_x.0 .0, &p2_y.0 .0);
    mont_mul_asm(&mut d.0 .0, &result.t.0 .0, &c.0 .0);

    mont_mul_asm(
        &mut c.0 .0,
        &d.0 .0,
        &[
            12167860994669987632u64,
            4043113551995129031u64,
            6052647550941614584u64,
            3904213385886034240u64,
        ],
    );
    mont_mul_asm(
        &mut d.0 .0,
        &(result.x + result.y).0 .0,
        &(p2_x + p2_y).0 .0,
    );
    let e = d - a - b;
    let f = result.z - c;
    let g = result.z + c;
    mont_mul_by5_asm(&mut a.0 .0);
    let h = b + a;
    mont_mul_asm(&mut result.x.0 .0, &e.0 .0, &f.0 .0);
    mont_mul_asm(&mut result.y.0 .0, &g.0 .0, &h.0 .0);
    mont_mul_asm(&mut result.t.0 .0, &e.0 .0, &h.0 .0);
    mont_mul_asm(&mut result.z.0 .0, &f.0 .0, &g.0 .0);
}
