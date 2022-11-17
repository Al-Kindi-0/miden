use std::collections::BTreeMap;

use super::build_test;
use super::Felt;
use air::FieldElement;
use air::StarkField;
use math::log2;
use rand_utils::rand_value;
use vm_core::QuadExtension;

mod channel;
pub use channel::*;

mod verifier_fri;
pub use verifier_fri::*;

type ExtElement = QuadExtension<Felt>;

#[test]
fn verify() {
    let source = "
        use.std::crypto::fri
        begin
            exec.fri::preprocess
            exec.fri::verify_fri
        end
        ";
    let trace_len_e = 10;
    let blowup_exp = 3;
    let depth = trace_len_e + blowup_exp;
    let domain_size = 1 << depth;
    let num_queries = 32;

    let (advice_provider, tape, alphas, commitments) =
        fri_prove_verify(trace_len_e, blowup_exp).expect("should not panic");
    //println!("head of tape is {:?}",Felt::from_mont(55834574835).as_int());
    //let (tape, set) = prepare_advice(depth, domain_size, num_queries, blowup_exp);
    let tape = prepare_advice_2(
        depth,
        domain_size,
        num_queries,
        blowup_exp,
        tape,
        alphas,
        commitments,
    );
    let advice_map: BTreeMap<[u8; 32], Vec<Felt>> = BTreeMap::from_iter(advice_provider.1);
    let test = build_test!(source, &[], &tape, advice_provider.0, advice_map);

    test.expect_stack(&[]);
}

#[test]
fn fold_2() {
    let source = "
        use.std::crypto::fri
        begin
            exec.fri::fold_2
        end";
    println!(
        "head of tape is {:?}",
        Felt::from_mont(6447149255697623253).as_int()
    );
    // --- simple case ----------------------------------------------------------------------------
    let b = ExtElement::new(
        Felt::new(11306949585462557770),
        Felt::new(11306949585462557770),
    );
    let a = ExtElement::new(
        Felt::new(2433767798173919658),
        Felt::new(2433767798173919658),
    );
    let c = ExtElement::new(
        Felt::new(4007042871203243940),
        Felt::new(3131225830454393212),
    );
    let d = ExtElement::new(Felt::new(9597810334906255130), Felt::new(0));
    let two = ExtElement::new(Felt::new(2), Felt::new(0));
    /*
    BaseElement(11306949585462557770), BaseElement(11306949585462557770), BaseElement(2433767798173919658), BaseElement(2433767798173919658), BaseElement(3131225830454393212), BaseElement(4007042871203243940), BaseElement(0), BaseElement(9597810334906255130) */
    let arr_a = vec![a];
    let arr_a = ExtElement::as_base_elements(&arr_a);
    let arr_b = vec![b];
    let arr_b = ExtElement::as_base_elements(&arr_b);
    let arr_c = vec![c];
    let arr_c = ExtElement::as_base_elements(&arr_c);
    let arr_d = vec![d];
    let arr_d = ExtElement::as_base_elements(&arr_d);

    let test = build_test!(
        source,
        &[
            arr_d[0].as_int(),
            arr_d[1].as_int(),
            arr_c[0].as_int(),
            arr_c[1].as_int(),
            arr_b[0].as_int(),
            arr_b[1].as_int(),
            arr_a[0].as_int(),
            arr_a[1].as_int()
        ]
    );
    let result = (a + b + ((a - b) * c / d)) / two;

    let arr_r = vec![result];
    let arr_r = ExtElement::as_base_elements(&arr_r);

    test.expect_stack(&[arr_r[1].as_int(), arr_r[0].as_int()]);

    // --- random values --------------------------------------------------------------------------
    let a = ExtElement::new(
        Felt::new(rand_value::<u64>()),
        Felt::new(rand_value::<u64>()),
    );
    let b = ExtElement::new(
        Felt::new(rand_value::<u64>()),
        Felt::new(rand_value::<u64>()),
    );
    let c = ExtElement::new(
        Felt::new(rand_value::<u64>()),
        Felt::new(rand_value::<u64>()),
    );
    let d = ExtElement::new(Felt::new(rand_value::<u64>()), Felt::new(0));

    let arr_a = vec![a];
    let arr_a = ExtElement::as_base_elements(&arr_a);
    let arr_b = vec![b];
    let arr_b = ExtElement::as_base_elements(&arr_b);
    let arr_c = vec![c];
    let arr_c = ExtElement::as_base_elements(&arr_c);
    let arr_d = vec![d];
    let arr_d = ExtElement::as_base_elements(&arr_d);

    let test = build_test!(
        source,
        &[
            arr_d[0].as_int(),
            arr_d[1].as_int(),
            arr_c[0].as_int(),
            arr_c[1].as_int(),
            arr_b[0].as_int(),
            arr_b[1].as_int(),
            arr_a[0].as_int(),
            arr_a[1].as_int()
        ]
    );
    let result = (a + b + ((a - b) * c / d)) / two;

    let arr_r = vec![result];
    let arr_r = ExtElement::as_base_elements(&arr_r);

    test.expect_stack(&[arr_r[1].as_int(), arr_r[0].as_int()]);
}

#[test]
fn next_pos_exp() {
    let source = "
        use.std::crypto::fri
        begin
            exec.fri::next_pos_exp
        end";

    let nor = Felt::new(18446744069414584320);
    let offset = Felt::new(7);
    // --- simple case 1----------------------------------------------------------------------------
    let poe = Felt::new(4);
    let b = Felt::new(0);

    let test = build_test!(source, &[poe.as_int(), poe.as_int(), b.as_int()]);

    test.expect_stack(&[(poe * poe).as_int(), (poe * offset).as_int()]);

    // --- simple case 2----------------------------------------------------------------------------
    let poe = Felt::new(4);
    let b = Felt::new(1);

    let test = build_test!(source, &[poe.as_int(), poe.as_int(), b.as_int()]);

    test.expect_stack(&[(poe * poe).as_int(), ((poe * offset) / nor).as_int()]);

    // --- random values 1--------------------------------------------------------------------------
    let poe = Felt::new(rand_value::<u64>());
    let b = Felt::new(0);

    let test = build_test!(source, &[poe.as_int(), poe.as_int(), b.as_int()]);

    test.expect_stack(&[(poe * poe).as_int(), (poe * offset).as_int()]);

    // --- random values 1--------------------------------------------------------------------------
    let poe = Felt::new(rand_value::<u64>());
    let b = Felt::new(1);

    let test = build_test!(source, &[poe.as_int(), poe.as_int(), b.as_int()]);

    test.expect_stack(&[(poe * poe).as_int(), ((poe * offset) / nor).as_int()]);
}

#[test]
fn prepare_next() {
    let source = "
        use.std::crypto::fri
        begin
            exec.fri::prepare_next
        end";

    // --- simple case 1----------------------------------------------------------------------------
    let d = Felt::new(1 << 12);
    let p = Felt::new(3874);
    let com = vec![Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(0)];
    let t_d = 12;
    let e0 = Felt::new(0);
    let e1 = Felt::new(0);
    let a0 = Felt::new(0);
    let a1 = Felt::new(0);
    let poe = Felt::new(1);
    let add_p = Felt::new(1 << 32);

    let test = build_test!(
        source,
        &[
            add_p.as_int(),
            poe.as_int(),
            d.as_int(),
            p.as_int(),
            e0.as_int(),
            e1.as_int(),
            t_d,
        ],
        &[
            a0.as_int(),
            a1.as_int(),
            com[0].as_int(),
            com[1].as_int(),
            com[2].as_int(),
            com[3].as_int(),
        ],
        vec![]
    );

    test.expect_stack(&[
        d.as_int(),
        p.as_int(),
        com[0].as_int(),
        com[1].as_int(),
        com[2].as_int(),
        com[3].as_int(),
        t_d,
        e1.as_int(),
        e0.as_int(),
        poe.as_int(),
        a1.as_int(),
        a0.as_int(),
        (add_p - Felt::new(2)).as_int(),
    ]);
}

// Helper functions

fn prepare_advice_2(
    depth: usize,
    domain_size: u32,
    num_queries: usize,
    blowup_exp: usize,
    tape_pre: Vec<u64>,
    alphas: Vec<u64>,
    com: Vec<u64>,
) -> Vec<u64> {
    let mut tape = vec![];
    //let com: Vec<u64> = COM.into_iter().flat_map(|a| a.into_iter()).collect();
    let domain_generator = Felt::get_root_of_unity(log2(domain_size as usize)).as_int();

    tape.push(depth as u64);
    tape.push(domain_generator);
    tape.push(domain_size as u64);
    tape.push(num_queries as u64);

    for i in (0..(depth - blowup_exp)).rev() {
        tape.extend_from_slice(&com[(4 * i)..(4 * i + 4)]);
        tape.extend_from_slice(&alphas[(4 * i)..(4 * i + 4)]);
    }

    tape.push(1007627512281099979);
    tape.push(10306770331341497425);
    tape.extend_from_slice(&tape_pre[..]);
    tape.extend_from_slice(&com[(com.len() - 4)..]);

    tape
}
