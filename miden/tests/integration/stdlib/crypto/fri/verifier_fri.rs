use std::{collections::BTreeMap, marker::PhantomData, mem};

use air::{Felt, FieldElement, StarkField};
use math::{fft, log2};
use miden::{AdviceSetError, Digest as MidenDigest};
use prover::AdviceSet;
use vm_core::utils::{group_vector_elements, RandomCoin};
use vm_core::ZERO;
use vm_core::{chiplets::hasher::Hasher as MidenHasher, QuadExtension};
use winter_fri::{
    folding::fold_positions, utils::map_positions_to_indexes, DefaultVerifierChannel, FriOptions,
    FriProof, VerifierChannel, VerifierError,
};
use winter_fri::{DefaultProverChannel, FriProver, FriVerifier};
use winter_prover::{
    crypto::{BatchMerkleProof, Digest, ElementHasher, Hasher},
    DeserializationError,
};
use winter_prover::{Deserializable, Serializable, SliceReader};
use winter_utils::AsBytes;

use super::channel::UnBatch;

use channel::MidenFriVerifierChannel;

type QuadExt = QuadExtension<Felt>;


pub fn fri_prove_verify_(
    trace_length_e: usize,
    lde_blowup_e: usize

) {
    let max_remainder_size_e = 3;
    let folding_factor_e = 1;
    let trace_length = 1 << trace_length_e;
    let lde_blowup = 1 << lde_blowup_e;
    let max_remainder_size = 1 << max_remainder_size_e;
    let folding_factor = 1 << folding_factor_e;


    let options = FriOptions::new(lde_blowup, folding_factor, max_remainder_size);
    let mut channel = build_prover_channel(trace_length, &options);
    let evaluations = build_evaluations(trace_length, lde_blowup);

    // instantiate the prover and generate the proof
    let mut prover = FriProver::new(options.clone());
    prover.build_layers(&mut channel, evaluations.clone());
    let positions = channel.draw_query_positions();
    let proof = prover.build_proof(&positions);

    // make sure the proof can be verified
    let commitments = channel.layer_commitments().to_vec();
    
    let max_degree = trace_length - 1;
    let result = verify_proof(
        proof.clone(),
        commitments.clone(),
        &evaluations,
        max_degree,
        trace_length * lde_blowup,
        &positions,
        &options,
    );

}

#[test]
fn fri_prove_verify() {
    let trace_length = 1 << 10;
    let lde_blowup = 8;

    let options = FriOptions::new(lde_blowup, 2, 8);
    let mut channel = build_prover_channel(trace_length, &options);
    let evaluations = build_evaluations(trace_length, lde_blowup);

    // instantiate the prover and generate the proof
    let mut prover = FriProver::new(options.clone());
    prover.build_layers(&mut channel, evaluations.clone());
    let positions = channel.draw_query_positions();
    let proof = prover.build_proof(&positions);

    // make sure the proof can be verified
    let commitments = channel.layer_commitments().to_vec();
    println!("commitments from prover {:?}",commitments);
    let max_degree = trace_length - 1;
    let result = verify_proof(
        proof.clone(),
        commitments.clone(),
        &evaluations,
        max_degree,
        trace_length * lde_blowup,
        &positions,
        &options,
    );
    let mut com = vec![];
    for c in commitments.iter() {
        let arr = c.as_elements();
        com.push(vec![
            arr[0].as_int(),
            arr[1].as_int(),
            arr[2].as_int(),
            arr[3].as_int(),
        ]);
    }
    println!("num of positions {:?}", positions.len());
    println!("commitment is {:?}", com);
    assert!(result.is_ok(), "{:}", result.err().unwrap());
}

// HELPER UTILS
// ================================================================================================

pub fn build_prover_channel(
    trace_length: usize,
    options: &FriOptions,
) -> DefaultProverChannel<Felt, QuadExt, MidenHasher> {
    DefaultProverChannel::new(trace_length * options.blowup_factor(), 32)
}

pub fn build_evaluations(trace_length: usize, lde_blowup: usize) -> Vec<QuadExt> {
    let mut p = (0..trace_length as u64)
        .map(|i| (i, i))
        .map(|(i, j)| QuadExt::new(i.into(), j.into()))
        .collect::<Vec<_>>();
    let domain_size = trace_length * lde_blowup;
    p.resize(domain_size, QuadExt::ZERO);

    let twiddles = fft::get_twiddles::<Felt>(domain_size);

    fft::evaluate_poly(&mut p, &twiddles);
    p
}

pub fn verify_proof(
    proof: FriProof,
    commitments: Vec<<MidenHasher as Hasher>::Digest>,
    evaluations: &[QuadExt],
    max_degree: usize,
    domain_size: usize,
    positions: &[usize],
    options: &FriOptions,
) -> Result<((Vec<AdviceSet>, Vec<([Felt; 4], Vec<Felt>)>), Vec<u64>), VerifierError> {

    let mut channel = MidenFriVerifierChannel::<QuadExt, MidenHasher>::new(
        proof,
        commitments.clone(),
        domain_size,
        options.folding_factor(),
    )
    .unwrap();
    let mut coin = RandomCoin::<Felt, MidenHasher>::new(&[]);

    let miden_verifier = MidenFriVerifier::new(&mut channel, &mut coin, options.clone(), max_degree)?;

    let queried_evaluations = positions
        .iter()
        .map(|&p| evaluations[p])
        .collect::<Vec<_>>();

    let result = miden_verifier.verify_fold_2_quad_ext(&mut channel, &queried_evaluations, &positions)?;
    
    Ok(result)
}

impl UnBatch<QuadExt> for MidenFriVerifierChannel<QuadExt, MidenHasher> {
    fn unbatch(
        &mut self,
        positions_: &[usize],
        domain_size: usize,
        folding_factor: usize,
        //layer_commitments: Vec<<<Self as VerifierChannel<QuadExt>>::Hasher as Hasher>::Digest>,
        layer_commitments: Vec<MidenDigest>,
    ) -> (Vec<AdviceSet>, Vec<([Felt; 4], Vec<Felt>)>) {
        let queries = self.layer_queries.clone();
        let mut current_domain_size = domain_size;
        let mut positions = positions_.to_vec();
        let depth = layer_commitments.len() - 1;
        //let mut result: Vec<Vec<(usize, Vec<MidenDigest>, [QuadExt; N])>> = Vec::new();
        //let mut advice = AdviceProvider::<Self::Hasher,QuadExt,N>::new();

        let mut adv_key_map = vec![];
        let mut sets = vec![];
        for i in 0..(depth ) {
            println!("current domain size is {:?}", current_domain_size);
            let mut folded_positions =
                fold_positions(&positions, current_domain_size, folding_factor);
            println!("position original is {:?}", positions);
            println!("position folded is {:?}", folded_positions);
            //let mut position_indexes = map_positions_to_indexes(
            //&folded_positions,
            //current_domain_size,
            //folding_factor,
            //self.num_partitions,
            //);

            let layer_proofs = self.layer_proofs.remove(0);

            let mut unbatched_proof = layer_proofs.into_paths(&folded_positions).unwrap();
            let x = group_vector_elements::<QuadExt, 2>(queries[i].clone());
            assert_eq!(x.len(), unbatched_proof.len());

            let nodes: Vec<[Felt; 4]> = unbatched_proof
                .iter_mut()
                .map(|list| {
                    let node = list.remove(0);
                    let node = node.as_elements().to_owned();
                    [node[0], node[1], node[2], node[3]]
                })
                .collect();

            let paths = unbatched_proof
                .iter()
                .map(|list| {
                    list.iter()
                        .map(|digest| {
                            let node = digest.as_elements();
                            let node = [node[0], node[1], node[2], node[3]];
                            node
                        })
                        .collect()
                })
                .collect();

            let new_set = AdviceSet::new_merkle_path_set(
                folded_positions.iter_mut().map(|a| *a as u64).collect(),
                nodes.clone(),
                paths,
                (depth + 3 - i) as u32,
            )
            .expect("Should not fail");

            sets.push(new_set);

            let _empty: () = nodes
                .into_iter()
                .zip(x.iter())
                .map(|(a, b)| {
                    let value = QuadExt::as_base_elements(b).to_owned();
                    adv_key_map.push((a.to_owned(), value));
                })
                .collect();

            //let partial_result = {
            //let mut partial_result: Vec<_> = Vec::new();
            //for j in 0..unbatched_proof.len() {
            //let tmp = (folded_positions[j], unbatched_proof[j].clone(), x[j]);
            //partial_result.push(tmp);
            //}
            //partial_result
            //};
            //result.push(partial_result);
            mem::swap(&mut positions, &mut folded_positions);
            current_domain_size = current_domain_size / folding_factor;
        }
        /*
        let mut final_result: Vec<Vec<(Vec<<MidenHasher as Hasher>::Digest>, [QuadExt; N])>> =
            Vec::new();
        for p in positions_.iter() {
            let mut current_domain_size = domain_size;
            let current_position = p;

            let query_across_layers = {
                let mut query_across_layers: Vec<(
                    Vec<<MidenHasher as Hasher>::Digest>,
                    [QuadExt; N],
                )> = Vec::new();
                for i in 0..depth {
                    current_domain_size = current_domain_size / folding_factor;
                    let current_position = current_position % current_domain_size;
                    let queries_current_layer = result[i].clone();

                    let single_query = queries_current_layer
                        .iter()
                        .find(|(i, _, _)| *i == current_position)
                        .unwrap();
                    let path = (*single_query).1.clone();
                    let values = single_query.2;

                    //advice.add(layer_commitments[i], current_position, &path, &values);
                    //println!("current position is {:?}, current domain size is {:?}",current_position, current_domain_size);
                    query_across_layers.push((path, values));
                }
                query_across_layers
            };
            final_result.push(query_across_layers);
        }

        assert!(final_result.len() == (*positions_).len());
        assert!(final_result[0].len() == depth);
        */

        (sets, adv_key_map)
    }
}


pub struct MidenFriVerifier {
    max_poly_degree: usize,
    domain_size: usize,
    domain_generator: Felt,
    layer_commitments: Vec<MidenDigest>,
    layer_alphas: Vec<QuadExt>,
    options: FriOptions,
    num_partitions: usize,
    _channel: PhantomData<MidenFriVerifierChannel<QuadExt, MidenHasher>>,
}

impl MidenFriVerifier {
    pub fn new(
        channel: &mut MidenFriVerifierChannel<QuadExt, MidenHasher>,
        public_coin: &mut RandomCoin<Felt, MidenHasher>,
        options: FriOptions,
        max_poly_degree: usize,
    ) -> Result<Self, VerifierError> {
        // infer evaluation domain info
        let domain_size = max_poly_degree.next_power_of_two() * options.blowup_factor();
        let domain_generator = Felt::get_root_of_unity(log2(domain_size));

        let num_partitions = channel.read_fri_num_partitions();

        // read layer commitments from the channel and use them to build a list of alphas
        let layer_commitments = channel.read_fri_layer_commitments();
        println!("layer commitments verifier {:?}",layer_commitments);
        let mut layer_alphas = Vec::with_capacity(layer_commitments.len());
        let mut max_degree_plus_1 = max_poly_degree + 1;
        for (depth, commitment) in layer_commitments.iter().enumerate() {
            public_coin.reseed(*commitment);
            let alpha = public_coin.draw().map_err(VerifierError::PublicCoinError)?;
            layer_alphas.push(alpha);

            // make sure the degree can be reduced by the folding factor at all layers
            // but the remainder layer
            if depth != layer_commitments.len() - 1
                && max_degree_plus_1 % options.folding_factor() != 0
            {
                return Err(VerifierError::DegreeTruncation(
                    max_degree_plus_1 - 1,
                    options.folding_factor(),
                    depth,
                ));
            }
            max_degree_plus_1 /= options.folding_factor();
        }

        Ok(MidenFriVerifier {
            max_poly_degree,
            domain_size,
            domain_generator,
            layer_commitments,
            layer_alphas,
            options,
            num_partitions,
            _channel: PhantomData,
        })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns maximum degree of a polynomial accepted by this verifier.
    pub fn max_poly_degree(&self) -> usize {
        self.max_poly_degree
    }

    /// Returns size of the domain over which a polynomial commitment checked by this verifier
    /// has been evaluated.
    ///
    /// The domain size can be computed by rounding `max_poly_degree` to the next power of two
    /// and multiplying the result by the `blowup_factor` from the protocol options.
    pub fn domain_size(&self) -> usize {
        self.domain_size
    }

    /// Returns number of partitions used during FRI proof generation.
    ///
    /// For non-distributed proof generation, number of partitions is usually set to 1.
    pub fn num_partitions(&self) -> usize {
        self.num_partitions
    }

    /// Returns protocol configuration options for this verifier.
    pub fn options(&self) -> &FriOptions {
        &self.options
    }

    fn verify_fold_2_quad_ext(
        &self,
        channel: &mut MidenFriVerifierChannel<QuadExt, MidenHasher>,
        evaluations: &[QuadExt],
        positions: &[usize],
    ) -> Result<((Vec<AdviceSet>, Vec<([Felt; 4], Vec<Felt>)>), Vec<u64>), VerifierError>
    
    {
        // 1 ----- verify the recursive components of the FRI proof -----------------------------------
        let positions = positions.to_vec();
        let evaluations = evaluations.to_vec();
        let mut final_pos_eval: Vec<(usize, QuadExt)> = vec![];
        let advice_provider = channel.unbatch(
            &positions,
            self.domain_size(),
            2,
            self.layer_commitments.clone(),
        );

        let mut d_generator;
        let mut full_tape = vec![];
        for (index, &position) in positions.iter().enumerate() {
            d_generator = self.domain_generator;
            let (cur_pos, evaluation, partial_tape) = iterate_query_fold_2_quad_ext(
                &self.layer_alphas,
                &advice_provider.0,
                &advice_provider.1,
                position,
                self.options.num_fri_layers(self.domain_size()),
                self.domain_size(),
                &evaluations[index],
                &mut d_generator,
            )?;
            full_tape.extend_from_slice(&partial_tape[..]);

            final_pos_eval.push((cur_pos, evaluation));
        }

        //eprintln!("ALL evaluations {:?}", total_evaluations);

        // 2 ----- verify the remainder of the FRI proof ----------------------------------------------

        // read the remainder from the channel and make sure it matches with the columns
        // of the previous layer
        let remainder_commitment = self.layer_commitments.last().unwrap();
        let remainder = channel.read_remainder::<2>(remainder_commitment)?;
        for (pos, eval) in final_pos_eval.iter() {
            if remainder[*pos] != *eval {
                assert!(false);
                return Err(VerifierError::InvalidRemainderFolding);
            }
        }

        Ok((advice_provider,full_tape))
    }
}

fn iterate_query_fold_2_quad_ext(
    layer_alphas: &Vec<QuadExt>,
    m_path_sets: &Vec<AdviceSet>,
    key_val_map: &Vec<([Felt; 4], Vec<Felt>)>,
    position: usize,
    number_of_layers: usize,
    initial_domain_size: usize,
    evaluation: &QuadExt,
    domain_generator: &mut Felt,
) -> Result<(usize, QuadExtension<Felt>, Vec<u64>), VerifierError> {
    let mut cur_pos = position;
    let mut evaluation = *evaluation;
    let mut domain_size = initial_domain_size;
    let domain_offset = Felt::GENERATOR;
    

    let initial_domain_generator = *domain_generator;
    let norm_cst = initial_domain_generator.exp((initial_domain_size as u64 / 2).into());
    let mut init_exp = initial_domain_generator.exp((position as u64).into());

    let arr1 = vec![evaluation];
    let a1 = QuadExt::as_base_elements(&arr1);

    let t_d = log2(domain_size) as u64;
    let mut partial_tap = vec![
        a1[0].as_int(),
        a1[1].as_int(),
        (position as u64).into(),
        (0 as u64).into(),
    ];

    let mut alphas = vec![];
    //println!("partial_tap so far {:?}", partial_tap);
    for depth in 0..(number_of_layers   ) {
        println!("current depth is {:?}",depth);
        let target_domain_size = domain_size / 2;

        let folded_pos = cur_pos % target_domain_size;
        // Assumes the num_partitions == 1
        let position_index = folded_pos;

        let tree_depth = log2(target_domain_size) + 1;

        let query_nodes = m_path_sets[depth]
            .get_node(tree_depth, position_index as u64)
            .unwrap();
        let query_values = &key_val_map
            .iter()
            .filter(|a| a.0[0] == query_nodes[0]).next()
            .expect("must contain the leaf values").1;
        let query_values = [QuadExt::new(query_values[0], query_values[1]),QuadExt::new(query_values[2], query_values[3])];

        let query_value = query_values[cur_pos / target_domain_size];

        //println!("evaluation is {:?} and query value is {:?}", evaluation, query_value);
        if evaluation != query_value {
            
            assert!(false);
            return Err(VerifierError::InvalidLayerFolding(depth));
        }
        let ar = vec![query_values[0], query_values[1]];
        let a_ = QuadExt::as_base_elements(&ar);
        //println!("query values {:?}",(a_[0].as_int(),a_[1].as_int(),a_[2].as_int(),a_[3].as_int(),));

        #[rustfmt::skip]
        let xs_original = (*domain_generator).exp((folded_pos as u64).into()) * (domain_offset);

        let xs = {
            if cur_pos / target_domain_size == 1 {
                init_exp / norm_cst
            } else {
                init_exp
            }
        } * domain_offset;
        //println!("the offset is {:?}",domain_offset.as_int());

        //println!("left {:?}", xs_original.as_int());
        //println!("right {:?}", xs);
        let y = Felt::get_root_of_unity(1);
        //println!("norm_cst {:?}", norm_cst.as_int());
        //println!("norm_cst_2 {:?}", y.inv().as_int());

        init_exp = init_exp * init_exp;

        evaluation = {
            let f_minus_x = query_values[1];
            let f_x = query_values[0];
            let x_star = QuadExt::from(xs);
            let alpha = layer_alphas[depth];

            //println!("a is {:?}",to_base(&f_x));
            //println!("b is {:?}",to_base(&f_minus_x));
            //println!("c is {:?}",to_base(&alpha));
            //println!("d is {:?}",to_base(&x_star));

            let result =
                (f_x + f_minus_x + ((f_x - f_minus_x) * alpha / x_star)) / QuadExt::ONE.double();
            result
        };
        let arr = vec![evaluation];
        let a = QuadExt::as_base_elements(&arr);
        //println!("evaluaiton fri is {:?}",(a[1].as_int(),a[0].as_int()));

        let arr = vec![layer_alphas[depth]];
        let a = QuadExt::as_base_elements(&arr);
        alphas.push(a[0].as_int());
        alphas.push(a[1].as_int());
        alphas.push(a[1].as_int());
        alphas.push(a[1].as_int());
        //println!("alpha is {:?}",(a[0].as_int(),a[1].as_int()));
        let arr = query_values;
        let a = QuadExt::as_base_elements(&arr); //TODO: this is redundant, remove
        partial_tap.push(a[0].as_int());
        partial_tap.push(a[1].as_int());
        partial_tap.push(a[2].as_int());
        partial_tap.push(a[3].as_int());

        //domain_generator_old = *domain_generator;
        // update variables for the next iteration of the loop
        *domain_generator = (*domain_generator).exp((2 as u32).into());
        cur_pos = folded_pos;
        domain_size /= 2;
    }
    /*
    println!(
        "For query at p={:?} the evaluations are {:?} and xs is",
        cur_pos,evaluations,
    ); */
    //println!("layer alphas are {:?}", alphas);

    Ok((cur_pos, evaluation, partial_tap))
}
