//! This module is automatically generated during build time and should not be modified manually.

/// An array of modules defined in Miden standard library.
///
/// Entries in the array are tuples containing module namespace and module parsed+serialized.
#[rustfmt::skip]
pub const MODULES: [(&str, vm_assembly::ProcedureId, &str, &[u8]); 14] = [
("std::sys",vm_assembly::ProcedureId([108, 156, 72, 120, 241, 17, 15, 48, 166, 221, 38, 219, 215, 149, 220, 31, 0, 39, 175, 30, 100, 43, 252, 186]),"#! Removes elements deep in the stack until the depth of the stack is exactly 16. The elements
#! are removed in such a way that the top 16 elements of the stack remain unchanged. If the stack
#! would otherwise contain more than 16 elements at the end of execution, then adding a call to this 
#! function at the end will reduce the size of the public inputs that are shared with the verifier.
#! Input: Stack with 16 or more elements.
#! Output: Stack with only the original top 16 elements.
export.truncate_stack.4
    loc_storew.0
    dropw
    loc_storew.1
    dropw
    loc_storew.2
    dropw
    loc_storew.3
    dropw
    sdepth
    neq.16
    while.true
        dropw
        sdepth
        neq.16
    end
    loc_loadw.3
    swapw.3
    loc_loadw.2
    swapw.2
    loc_loadw.1
    swapw.1
    loc_loadw.0
end
",&[1, 0, 14, 116, 114, 117, 110, 99, 97, 116, 101, 95, 115, 116, 97, 99, 107, 218, 1, 82, 101, 109, 111, 118, 101, 115, 32, 101, 108, 101, 109, 101, 110, 116, 115, 32, 100, 101, 101, 112, 32, 105, 110, 32, 116, 104, 101, 32, 115, 116, 97, 99, 107, 32, 117, 110, 116, 105, 108, 32, 116, 104, 101, 32, 100, 101, 112, 116, 104, 32, 111, 102, 32, 116, 104, 101, 32, 115, 116, 97, 99, 107, 32, 105, 115, 32, 101, 120, 97, 99, 116, 108, 121, 32, 49, 54, 46, 32, 84, 104, 101, 32, 101, 108, 101, 109, 101, 110, 116, 115, 10, 97, 114, 101, 32, 114, 101, 109, 111, 118, 101, 100, 32, 105, 110, 32, 115, 117, 99, 104, 32, 97, 32, 119, 97, 121, 32, 116, 104, 97, 116, 32, 116, 104, 101, 32, 116, 111, 112, 32, 49, 54, 32, 101, 108, 101, 109, 101, 110, 116, 115, 32, 111, 102, 32, 116, 104, 101, 32, 115, 116, 97, 99, 107, 32, 114, 101, 109, 97, 105, 110, 32, 117, 110, 99, 104, 97, 110, 103, 101, 100, 46, 32, 73, 102, 32, 116, 104, 101, 32, 115, 116, 97, 99, 107, 10, 119, 111, 117, 108, 100, 32, 111, 116, 104, 101, 114, 119, 105, 115, 101, 32, 99, 111, 110, 116, 97, 105, 110, 32, 109, 111, 114, 101, 32, 116, 104, 97, 110, 32, 49, 54, 32, 101, 108, 101, 109, 101, 110, 116, 115, 32, 97, 116, 32, 116, 104, 101, 32, 101, 110, 100, 32, 111, 102, 32, 101, 120, 101, 99, 117, 116, 105, 111, 110, 44, 32, 116, 104, 101, 110, 32, 97, 100, 100, 105, 110, 103, 32, 97, 32, 99, 97, 108, 108, 32, 116, 111, 32, 116, 104, 105, 115, 10, 102, 117, 110, 99, 116, 105, 111, 110, 32, 97, 116, 32, 116, 104, 101, 32, 101, 110, 100, 32, 119, 105, 108, 108, 32, 114, 101, 100, 117, 99, 101, 32, 116, 104, 101, 32, 115, 105, 122, 101, 32, 111, 102, 32, 116, 104, 101, 32, 112, 117, 98, 108, 105, 99, 32, 105, 110, 112, 117, 116, 115, 32, 116, 104, 97, 116, 32, 97, 114, 101, 32, 115, 104, 97, 114, 101, 100, 32, 119, 105, 116, 104, 32, 116, 104, 101, 32, 118, 101, 114, 105, 102, 105, 101, 114, 46, 10, 73, 110, 112, 117, 116, 58, 32, 83, 116, 97, 99, 107, 32, 119, 105, 116, 104, 32, 49, 54, 32, 111, 114, 32, 109, 111, 114, 101, 32, 101, 108, 101, 109, 101, 110, 116, 115, 46, 10, 79, 117, 116, 112, 117, 116, 58, 32, 83, 116, 97, 99, 107, 32, 119, 105, 116, 104, 32, 111, 110, 108, 121, 32, 116, 104, 101, 32, 111, 114, 105, 103, 105, 110, 97, 108, 32, 116, 111, 112, 32, 49, 54, 32, 101, 108, 101, 109, 101, 110, 116, 115, 46, 1, 4, 0, 18, 0, 200, 0, 0, 0, 0, 0, 0, 0, 0, 108, 200, 1, 0, 0, 0, 0, 0, 0, 0, 108, 200, 2, 0, 0, 0, 0, 0, 0, 0, 108, 200, 3, 0, 0, 0, 0, 0, 0, 0, 108, 187, 24, 16, 0, 0, 0, 0, 0, 0, 0, 255, 3, 0, 108, 187, 24, 16, 0, 0, 0, 0, 0, 0, 0, 194, 3, 0, 0, 0, 0, 0, 0, 0, 147, 194, 2, 0, 0, 0, 0, 0, 0, 0, 146, 194, 1, 0, 0, 0, 0, 0, 0, 0, 145, 194, 0, 0, 0, 0, 0, 0, 0, 0]),
("std::crypto::dsa::falcon",vm_assembly::ProcedureId([189, 139, 200, 202, 100, 233, 83, 114, 77, 58, 86, 188, 150, 133, 31, 254, 25, 201, 51, 28, 11, 81, 40, 75]),"use.std::math::poly512

#! Given an element on stack top, this routine normalizes that element in 
#! interval (-q/2, q/2] | q = 12289
#!
#! Imagine, a is the provided element, which needs to be normalized
#!
#! b = normalize(a)
#!   = (a + (q >> 1)) % q - (q >> 1) | a ∈ [0, q), q = 12289
#!
#! Note, normalization requires that we can represent the number as signed integer,
#! which is not allowed inside Miden VM stack. But we can ignore the sign of integer and only
#! store the absolute value as field element. This can be safely done because after normalization
#! anyway `b` will be squared ( for computing norm of a vector i.e. polynomial, where b is a coefficient ).
#! That means we can just drop the sign, and that's what is done in this routine.
#!
#! To be more concrete, normalization of 12166 ( = a ) should result into -123, but absolute value 
#! 123 will be kept on stack. While normalization of 21, should result into 21, which has absolute
#! value 21 --- that's what is kept on stack.
#!
#! Expected stack state :
#!
#! [a, ...]
#!
#! After normalization ( represented using unsigned integer i.e. Miden field element ) stack looks like
#!
#! [b, ...]
proc.normalize
    dup
    push.6144
    gt

    if.true
        push.6144
        add

        exec.poly512::mod_12289

        dup
        push.6144
        gte

        if.true
            push.6144
            sub
        else
            push.6144
            swap
            sub
        end
    end
end

#! Given four elements from Falcon prime field, on stack top, this routine 
#! normalizes each of them, using above defined `normalize()` routine.
#!
#! Expected stack state :
#!
#! [a0, a1, a2, a3, ...]
#!
#! Output stack state :
#!
#! [b0, b1, b2, b3, ...]
#!
#! b`i` = normalize(a`i`) | i ∈ [0..4)
proc.normalize_word
    exec.normalize

    swap
    exec.normalize
    swap

    movup.2
    exec.normalize
    movdn.2

    movup.3
    exec.normalize
    movdn.3
end

#! Given a degree 512 polynomial on stack, using its starting (absolute) memory address, 
#! this routine normalizes each coefficient of the polynomial, using above defined 
#! `normalize()` routine
#!
#! Imagine, f is the given polynomial of degree 512. It can be normalized using
#!
#! g = [normalize(f[i]) for i in range(512)]
#!
#! Expected stack state :
#!
#! [f_start_addr, g_start_addr, ...] | next 127 absolute addresses can be computed using `INCR` instruction
#!
#! Post normalization stack state looks like
#!
#! [ ... ]
#!
#! Note, input polynomial which is provided using memory addresses, is not mutated.
export.normalize_poly512
    push.0.0.0.0

    repeat.128
        dup.4
        mem_loadw

        exec.normalize_word

        dup.5
        mem_storew

        movup.5
        add.1
        movdn.5

        movup.4
        add.1
        movdn.4
    end

    dropw
    drop
    drop
end

#! Given four elements on stack top, this routine computes squared norm of that
#! vector ( read polynomial ) with four coefficients.
#!
#! Imagine, given vector is f, which is described as
#!
#! f = [a0, a1, a2, a3]
#!
#! Norm of that vector is
#!
#! √(a0 ^ 2 + a1 ^ 2 + a2 ^ 2 + a3 ^ 2)
#!
#! But we need squared norm, which is just skipping the final square root operation.
#!
#! Expected stack state :
#!
#! [a0, a1, a2, a3, ...]
#!
#! Final stack state :
#!
#! [b, ...] | b = a0 ^ 2 + a1 ^ 2 + a2 ^ 2 + a3 ^ 2
proc.squared_norm_word
    dup
    mul

    swap
    dup
    mul

    add

    swap
    dup
    mul

    add

    swap
    dup
    mul

    add
end

#! Given a degree 512 polynomial in coefficient form, as starting (absolute) memory address 
#! on stack, this routine computes squared norm of that vector, using following formula
#!
#! Say, f = [a0, a1, a2, ..., a510, a511]
#!      g = sq_norm(f) = a0 ^ 2 + a1 ^ 2 + ... + a510 ^ 2 + a511 ^ 2
#!
#! Expected input stack state :
#!
#! [f_start_addr, ...] | f_addr`i` holds f[(i << 2) .. ((i+1) << 2)]
#!
#! Consecutive 127 addresses on stack can be computed using `INCR` instruction, because memory 
#! addresses are consecutive i.e. monotonically increasing by 1.
#!
#! Final stack state :
#!
#! [g, ...] | g = sq_norm(f)
export.squared_norm_poly512
    push.0.0.0.0.0

    repeat.128
        dup.5
        mem_loadw

        exec.squared_norm_word
        add

        swap
        add.1
        swap

        push.0.0.0.0
    end

    dropw
    swap
    drop
end

#! Falcon-512 Digital Signature Verification routine
#!
#! Given four degree-511 polynomials, using initial absolute memory addresses on stack, 
#! this routine checks whether it's a valid Falcon signature or not.
#!
#! Four degree-511 polynomials, which are provided ( in order )
#!
#! f = [f0, f1, ..., f510, f511] -> decompressed Falcon-512 signature
#! g = [g0, g1, ..., g510, g511] -> public key used for signing input message
#! h = [h0, h1, ..., h510, h511] -> input message hashed using SHAKE256 XOF and converted to polynomial
#! k = [k0, k1, ..., k510, k511] -> [abs(i) for i in f] | abs(a) = a < 0 ? 0 - a : a
#!
#! Each of these polynomials are represented using starting absolute memory address. Contiguous 127 
#! memory addresses can be computed by repeated application of INCR instruction ( read add.1 ) on previous
#! absolute memory address.
#!
#! f`i` holds f[(i << 2) .. ((i+1) << 2)] | i ∈ [0..128)
#! g`i` holds g[(i << 2) .. ((i+1) << 2)] | i ∈ [0..128)
#! h`i` holds h[(i << 2) .. ((i+1) << 2)] | i ∈ [0..128)
#! k`i` holds k[(i << 2) .. ((i+1) << 2)] | i ∈ [0..128)
#!
#! Expected stack state :
#!
#! [f_start_addr, g_start_addr, h_start_addr, k_start_addr, ...]
#!
#! After execution of verification routine, stack looks like
#!
#! [ ... ]
#!
#! If verification fails, program panics, due to failure in assertion !
#!
#! Note, input memory addresses are considered to be immutable.
export.verify.257
    locaddr.0
    movdn.2
    exec.poly512::mul_zq

    locaddr.128
    locaddr.0
    exec.poly512::neg_zq

    locaddr.0
    swap
    locaddr.128
    exec.poly512::add_zq

    locaddr.128
    locaddr.0
    exec.normalize_poly512

    # compute squared norm of s0

    locaddr.128
    exec.squared_norm_poly512

    locaddr.256
    mem_store
    drop

    # compute squared norm of s1 ( where s1 is provided as polynomial
    # with coefficients represented using absolute value i.e. signs are ignored )

    exec.squared_norm_poly512

    locaddr.256
    mem_load
    add

    # check that norm of the signature is small enough

    push.34034726 # constant sig_bound for Falcon-512 signature
    lte
    assert
end
",&[6, 0, 9, 110, 111, 114, 109, 97, 108, 105, 122, 101, 0, 0, 0, 0, 0, 4, 0, 110, 185, 1, 0, 24, 0, 0, 0, 0, 0, 0, 28, 253, 7, 0, 185, 1, 0, 24, 0, 0, 0, 0, 0, 0, 3, 212, 85, 132, 203, 155, 10, 43, 66, 153, 188, 247, 113, 182, 11, 149, 253, 89, 63, 20, 200, 120, 146, 57, 157, 137, 110, 185, 1, 0, 24, 0, 0, 0, 0, 0, 0, 29, 253, 2, 0, 185, 1, 0, 24, 0, 0, 0, 0, 0, 0, 5, 3, 0, 185, 1, 0, 24, 0, 0, 0, 0, 0, 0, 130, 5, 0, 0, 14, 110, 111, 114, 109, 97, 108, 105, 122, 101, 95, 119, 111, 114, 100, 0, 0, 0, 0, 0, 10, 0, 211, 0, 0, 130, 211, 0, 0, 130, 149, 211, 0, 0, 165, 150, 211, 0, 0, 166, 17, 110, 111, 114, 109, 97, 108, 105, 122, 101, 95, 112, 111, 108, 121, 53, 49, 50, 53, 2, 71, 105, 118, 101, 110, 32, 97, 32, 100, 101, 103, 114, 101, 101, 32, 53, 49, 50, 32, 112, 111, 108, 121, 110, 111, 109, 105, 97, 108, 32, 111, 110, 32, 115, 116, 97, 99, 107, 44, 32, 117, 115, 105, 110, 103, 32, 105, 116, 115, 32, 115, 116, 97, 114, 116, 105, 110, 103, 32, 40, 97, 98, 115, 111, 108, 117, 116, 101, 41, 32, 109, 101, 109, 111, 114, 121, 32, 97, 100, 100, 114, 101, 115, 115, 44, 10, 116, 104, 105, 115, 32, 114, 111, 117, 116, 105, 110, 101, 32, 110, 111, 114, 109, 97, 108, 105, 122, 101, 115, 32, 101, 97, 99, 104, 32, 99, 111, 101, 102, 102, 105, 99, 105, 101, 110, 116, 32, 111, 102, 32, 116, 104, 101, 32, 112, 111, 108, 121, 110, 111, 109, 105, 97, 108, 44, 32, 117, 115, 105, 110, 103, 32, 97, 98, 111, 118, 101, 32, 100, 101, 102, 105, 110, 101, 100, 10, 96, 110, 111, 114, 109, 97, 108, 105, 122, 101, 40, 41, 96, 32, 114, 111, 117, 116, 105, 110, 101, 10, 73, 109, 97, 103, 105, 110, 101, 44, 32, 102, 32, 105, 115, 32, 116, 104, 101, 32, 103, 105, 118, 101, 110, 32, 112, 111, 108, 121, 110, 111, 109, 105, 97, 108, 32, 111, 102, 32, 100, 101, 103, 114, 101, 101, 32, 53, 49, 50, 46, 32, 73, 116, 32, 99, 97, 110, 32, 98, 101, 32, 110, 111, 114, 109, 97, 108, 105, 122, 101, 100, 32, 117, 115, 105, 110, 103, 10, 103, 32, 61, 32, 91, 110, 111, 114, 109, 97, 108, 105, 122, 101, 40, 102, 91, 105, 93, 41, 32, 102, 111, 114, 32, 105, 32, 105, 110, 32, 114, 97, 110, 103, 101, 40, 53, 49, 50, 41, 93, 10, 69, 120, 112, 101, 99, 116, 101, 100, 32, 115, 116, 97, 99, 107, 32, 115, 116, 97, 116, 101, 32, 58, 10, 91, 102, 95, 115, 116, 97, 114, 116, 95, 97, 100, 100, 114, 44, 32, 103, 95, 115, 116, 97, 114, 116, 95, 97, 100, 100, 114, 44, 32, 46, 46, 46, 93, 32, 124, 32, 110, 101, 120, 116, 32, 49, 50, 55, 32, 97, 98, 115, 111, 108, 117, 116, 101, 32, 97, 100, 100, 114, 101, 115, 115, 101, 115, 32, 99, 97, 110, 32, 98, 101, 32, 99, 111, 109, 112, 117, 116, 101, 100, 32, 117, 115, 105, 110, 103, 32, 96, 73, 78, 67, 82, 96, 32, 105, 110, 115, 116, 114, 117, 99, 116, 105, 111, 110, 10, 80, 111, 115, 116, 32, 110, 111, 114, 109, 97, 108, 105, 122, 97, 116, 105, 111, 110, 32, 115, 116, 97, 99, 107, 32, 115, 116, 97, 116, 101, 32, 108, 111, 111, 107, 115, 32, 108, 105, 107, 101, 10, 91, 32, 46, 46, 46, 32, 93, 10, 78, 111, 116, 101, 44, 32, 105, 110, 112, 117, 116, 32, 112, 111, 108, 121, 110, 111, 109, 105, 97, 108, 32, 119, 104, 105, 99, 104, 32, 105, 115, 32, 112, 114, 111, 118, 105, 100, 101, 100, 32, 117, 115, 105, 110, 103, 32, 109, 101, 109, 111, 114, 121, 32, 97, 100, 100, 114, 101, 115, 115, 101, 115, 44, 32, 105, 115, 32, 110, 111, 116, 32, 109, 117, 116, 97, 116, 101, 100, 46, 1, 0, 0, 5, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254, 36, 0, 11, 0, 114, 191, 211, 1, 0, 115, 198, 152, 3, 168, 151, 3, 167, 108, 107, 107, 17, 115, 113, 117, 97, 114, 101, 100, 95, 110, 111, 114, 109, 95, 119, 111, 114, 100, 0, 0, 0, 0, 0, 14, 0, 110, 7, 130, 110, 7, 3, 130, 110, 7, 3, 130, 110, 7, 3, 20, 115, 113, 117, 97, 114, 101, 100, 95, 110, 111, 114, 109, 95, 112, 111, 108, 121, 53, 49, 50, 56, 2, 71, 105, 118, 101, 110, 32, 97, 32, 100, 101, 103, 114, 101, 101, 32, 53, 49, 50, 32, 112, 111, 108, 121, 110, 111, 109, 105, 97, 108, 32, 105, 110, 32, 99, 111, 101, 102, 102, 105, 99, 105, 101, 110, 116, 32, 102, 111, 114, 109, 44, 32, 97, 115, 32, 115, 116, 97, 114, 116, 105, 110, 103, 32, 40, 97, 98, 115, 111, 108, 117, 116, 101, 41, 32, 109, 101, 109, 111, 114, 121, 32, 97, 100, 100, 114, 101, 115, 115, 10, 111, 110, 32, 115, 116, 97, 99, 107, 44, 32, 116, 104, 105, 115, 32, 114, 111, 117, 116, 105, 110, 101, 32, 99, 111, 109, 112, 117, 116, 101, 115, 32, 115, 113, 117, 97, 114, 101, 100, 32, 110, 111, 114, 109, 32, 111, 102, 32, 116, 104, 97, 116, 32, 118, 101, 99, 116, 111, 114, 44, 32, 117, 115, 105, 110, 103, 32, 102, 111, 108, 108, 111, 119, 105, 110, 103, 32, 102, 111, 114, 109, 117, 108, 97, 10, 83, 97, 121, 44, 32, 102, 32, 61, 32, 91, 97, 48, 44, 32, 97, 49, 44, 32, 97, 50, 44, 32, 46, 46, 46, 44, 32, 97, 53, 49, 48, 44, 32, 97, 53, 49, 49, 93, 10, 103, 32, 61, 32, 115, 113, 95, 110, 111, 114, 109, 40, 102, 41, 32, 61, 32, 97, 48, 32, 94, 32, 50, 32, 43, 32, 97, 49, 32, 94, 32, 50, 32, 43, 32, 46, 46, 46, 32, 43, 32, 97, 53, 49, 48, 32, 94, 32, 50, 32, 43, 32, 97, 53, 49, 49, 32, 94, 32, 50, 10, 69, 120, 112, 101, 99, 116, 101, 100, 32, 105, 110, 112, 117, 116, 32, 115, 116, 97, 99, 107, 32, 115, 116, 97, 116, 101, 32, 58, 10, 91, 102, 95, 115, 116, 97, 114, 116, 95, 97, 100, 100, 114, 44, 32, 46, 46, 46, 93, 32, 124, 32, 102, 95, 97, 100, 100, 114, 96, 105, 96, 32, 104, 111, 108, 100, 115, 32, 102, 91, 40, 105, 32, 60, 60, 32, 50, 41, 32, 46, 46, 32, 40, 40, 105, 43, 49, 41, 32, 60, 60, 32, 50, 41, 93, 10, 67, 111, 110, 115, 101, 99, 117, 116, 105, 118, 101, 32, 49, 50, 55, 32, 97, 100, 100, 114, 101, 115, 115, 101, 115, 32, 111, 110, 32, 115, 116, 97, 99, 107, 32, 99, 97, 110, 32, 98, 101, 32, 99, 111, 109, 112, 117, 116, 101, 100, 32, 117, 115, 105, 110, 103, 32, 96, 73, 78, 67, 82, 96, 32, 105, 110, 115, 116, 114, 117, 99, 116, 105, 111, 110, 44, 32, 98, 101, 99, 97, 117, 115, 101, 32, 109, 101, 109, 111, 114, 121, 10, 97, 100, 100, 114, 101, 115, 115, 101, 115, 32, 97, 114, 101, 32, 99, 111, 110, 115, 101, 99, 117, 116, 105, 118, 101, 32, 105, 46, 101, 46, 32, 109, 111, 110, 111, 116, 111, 110, 105, 99, 97, 108, 108, 121, 32, 105, 110, 99, 114, 101, 97, 115, 105, 110, 103, 32, 98, 121, 32, 49, 46, 10, 70, 105, 110, 97, 108, 32, 115, 116, 97, 99, 107, 32, 115, 116, 97, 116, 101, 32, 58, 10, 91, 103, 44, 32, 46, 46, 46, 93, 32, 124, 32, 103, 32, 61, 32, 115, 113, 95, 110, 111, 114, 109, 40, 102, 41, 1, 0, 0, 5, 0, 185, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254, 71, 0, 8, 0, 115, 191, 211, 3, 0, 3, 130, 3, 130, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 108, 130, 107, 6, 118, 101, 114, 105, 102, 121, 37, 5, 70, 97, 108, 99, 111, 110, 45, 53, 49, 50, 32, 68, 105, 103, 105, 116, 97, 108, 32, 83, 105, 103, 110, 97, 116, 117, 114, 101, 32, 86, 101, 114, 105, 102, 105, 99, 97, 116, 105, 111, 110, 32, 114, 111, 117, 116, 105, 110, 101, 10, 71, 105, 118, 101, 110, 32, 102, 111, 117, 114, 32, 100, 101, 103, 114, 101, 101, 45, 53, 49, 49, 32, 112, 111, 108, 121, 110, 111, 109, 105, 97, 108, 115, 44, 32, 117, 115, 105, 110, 103, 32, 105, 110, 105, 116, 105, 97, 108, 32, 97, 98, 115, 111, 108, 117, 116, 101, 32, 109, 101, 109, 111, 114, 121, 32, 97, 100, 100, 114, 101, 115, 115, 101, 115, 32, 111, 110, 32, 115, 116, 97, 99, 107, 44, 10, 116, 104, 105, 115, 32, 114, 111, 117, 116, 105, 110, 101, 32, 99, 104, 101, 99, 107, 115, 32, 119, 104, 101, 116, 104, 101, 114, 32, 105, 116, 39, 115, 32, 97, 32, 118, 97, 108, 105, 100, 32, 70, 97, 108, 99, 111, 110, 32, 115, 105, 103, 110, 97, 116, 117, 114, 101, 32, 111, 114, 32, 110, 111, 116, 46, 10, 70, 111, 117, 114, 32, 100, 101, 103, 114, 101, 101, 45, 53, 49, 49, 32, 112, 111, 108, 121, 110, 111, 109, 105, 97, 108, 115, 44, 32, 119, 104, 105, 99, 104, 32, 97, 114, 101, 32, 112, 114, 111, 118, 105, 100, 101, 100, 32, 40, 32, 105, 110, 32, 111, 114, 100, 101, 114, 32, 41, 10, 102, 32, 61, 32, 91, 102, 48, 44, 32, 102, 49, 44, 32, 46, 46, 46, 44, 32, 102, 53, 49, 48, 44, 32, 102, 53, 49, 49, 93, 32, 45, 62, 32, 100, 101, 99, 111, 109, 112, 114, 101, 115, 115, 101, 100, 32, 70, 97, 108, 99, 111, 110, 45, 53, 49, 50, 32, 115, 105, 103, 110, 97, 116, 117, 114, 101, 10, 103, 32, 61, 32, 91, 103, 48, 44, 32, 103, 49, 44, 32, 46, 46, 46, 44, 32, 103, 53, 49, 48, 44, 32, 103, 53, 49, 49, 93, 32, 45, 62, 32, 112, 117, 98, 108, 105, 99, 32, 107, 101, 121, 32, 117, 115, 101, 100, 32, 102, 111, 114, 32, 115, 105, 103, 110, 105, 110, 103, 32, 105, 110, 112, 117, 116, 32, 109, 101, 115, 115, 97, 103, 101, 10, 104, 32, 61, 32, 91, 104, 48, 44, 32, 104, 49, 44, 32, 46, 46, 46, 44, 32, 104, 53, 49, 48, 44, 32, 104, 53, 49, 49, 93, 32, 45, 62, 32, 105, 110, 112, 117, 116, 32, 109, 101, 115, 115, 97, 103, 101, 32, 104, 97, 115, 104, 101, 100, 32, 117, 115, 105, 110, 103, 32, 83, 72, 65, 75, 69, 50, 53, 54, 32, 88, 79, 70, 32, 97, 110, 100, 32, 99, 111, 110, 118, 101, 114, 116, 101, 100, 32, 116, 111, 32, 112, 111, 108, 121, 110, 111, 109, 105, 97, 108, 10, 107, 32, 61, 32, 91, 107, 48, 44, 32, 107, 49, 44, 32, 46, 46, 46, 44, 32, 107, 53, 49, 48, 44, 32, 107, 53, 49, 49, 93, 32, 45, 62, 32, 91, 97, 98, 115, 40, 105, 41, 32, 102, 111, 114, 32, 105, 32, 105, 110, 32, 102, 93, 32, 124, 32, 97, 98, 115, 40, 97, 41, 32, 61, 32, 97, 32, 60, 32, 48, 32, 63, 32, 48, 32, 45, 32, 97, 32, 58, 32, 97, 10, 69, 97, 99, 104, 32, 111, 102, 32, 116, 104, 101, 115, 101, 32, 112, 111, 108, 121, 110, 111, 109, 105, 97, 108, 115, 32, 97, 114, 101, 32, 114, 101, 112, 114, 101, 115, 101, 110, 116, 101, 100, 32, 117, 115, 105, 110, 103, 32, 115, 116, 97, 114, 116, 105, 110, 103, 32, 97, 98, 115, 111, 108, 117, 116, 101, 32, 109, 101, 109, 111, 114, 121, 32, 97, 100, 100, 114, 101, 115, 115, 46, 32, 67, 111, 110, 116, 105, 103, 117, 111, 117, 115, 32, 49, 50, 55, 10, 109, 101, 109, 111, 114, 121, 32, 97, 100, 100, 114, 101, 115, 115, 101, 115, 32, 99, 97, 110, 32, 98, 101, 32, 99, 111, 109, 112, 117, 116, 101, 100, 32, 98, 121, 32, 114, 101, 112, 101, 97, 116, 101, 100, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 32, 111, 102, 32, 73, 78, 67, 82, 32, 105, 110, 115, 116, 114, 117, 99, 116, 105, 111, 110, 32, 40, 32, 114, 101, 97, 100, 32, 97, 100, 100, 46, 49, 32, 41, 32, 111, 110, 32, 112, 114, 101, 118, 105, 111, 117, 115, 10, 97, 98, 115, 111, 108, 117, 116, 101, 32, 109, 101, 109, 111, 114, 121, 32, 97, 100, 100, 114, 101, 115, 115, 46, 10, 102, 96, 105, 96, 32, 104, 111, 108, 100, 115, 32, 102, 91, 40, 105, 32, 60, 60, 32, 50, 41, 32, 46, 46, 32, 40, 40, 105, 43, 49, 41, 32, 60, 60, 32, 50, 41, 93, 32, 124, 32, 105, 32, 226, 136, 136, 32, 91, 48, 46, 46, 49, 50, 56, 41, 10, 103, 96, 105, 96, 32, 104, 111, 108, 100, 115, 32, 103, 91, 40, 105, 32, 60, 60, 32, 50, 41, 32, 46, 46, 32, 40, 40, 105, 43, 49, 41, 32, 60, 60, 32, 50, 41, 93, 32, 124, 32, 105, 32, 226, 136, 136, 32, 91, 48, 46, 46, 49, 50, 56, 41, 10, 104, 96, 105, 96, 32, 104, 111, 108, 100, 115, 32, 104, 91, 40, 105, 32, 60, 60, 32, 50, 41, 32, 46, 46, 32, 40, 40, 105, 43, 49, 41, 32, 60, 60, 32, 50, 41, 93, 32, 124, 32, 105, 32, 226, 136, 136, 32, 91, 48, 46, 46, 49, 50, 56, 41, 10, 107, 96, 105, 96, 32, 104, 111, 108, 100, 115, 32, 107, 91, 40, 105, 32, 60, 60, 32, 50, 41, 32, 46, 46, 32, 40, 40, 105, 43, 49, 41, 32, 60, 60, 32, 50, 41, 93, 32, 124, 32, 105, 32, 226, 136, 136, 32, 91, 48, 46, 46, 49, 50, 56, 41, 10, 69, 120, 112, 101, 99, 116, 101, 100, 32, 115, 116, 97, 99, 107, 32, 115, 116, 97, 116, 101, 32, 58, 10, 91, 102, 95, 115, 116, 97, 114, 116, 95, 97, 100, 100, 114, 44, 32, 103, 95, 115, 116, 97, 114, 116, 95, 97, 100, 100, 114, 44, 32, 104, 95, 115, 116, 97, 114, 116, 95, 97, 100, 100, 114, 44, 32, 107, 95, 115, 116, 97, 114, 116, 95, 97, 100, 100, 114, 44, 32, 46, 46, 46, 93, 10, 65, 102, 116, 101, 114, 32, 101, 120, 101, 99, 117, 116, 105, 111, 110, 32, 111, 102, 32, 118, 101, 114, 105, 102, 105, 99, 97, 116, 105, 111, 110, 32, 114, 111, 117, 116, 105, 110, 101, 44, 32, 115, 116, 97, 99, 107, 32, 108, 111, 111, 107, 115, 32, 108, 105, 107, 101, 10, 91, 32, 46, 46, 46, 32, 93, 10, 73, 102, 32, 118, 101, 114, 105, 102, 105, 99, 97, 116, 105, 111, 110, 32, 102, 97, 105, 108, 115, 44, 32, 112, 114, 111, 103, 114, 97, 109, 32, 112, 97, 110, 105, 99, 115, 44, 32, 100, 117, 101, 32, 116, 111, 32, 102, 97, 105, 108, 117, 114, 101, 32, 105, 110, 32, 97, 115, 115, 101, 114, 116, 105, 111, 110, 32, 33, 10, 78, 111, 116, 101, 44, 32, 105, 110, 112, 117, 116, 32, 109, 101, 109, 111, 114, 121, 32, 97, 100, 100, 114, 101, 115, 115, 101, 115, 32, 97, 114, 101, 32, 99, 111, 110, 115, 105, 100, 101, 114, 101, 100, 32, 116, 111, 32, 98, 101, 32, 105, 109, 109, 117, 116, 97, 98, 108, 101, 46, 1, 1, 1, 25, 0, 186, 0, 0, 0, 0, 0, 0, 0, 0, 165, 212, 198, 4, 141, 102, 17, 204, 28, 154, 71, 189, 42, 106, 248, 32, 176, 63, 110, 187, 169, 166, 97, 67, 211, 29, 186, 128, 0, 0, 0, 0, 0, 0, 0, 186, 0, 0, 0, 0, 0, 0, 0, 0, 212, 155, 180, 67, 30, 194, 168, 239, 166, 191, 42, 172, 120, 205, 218, 138, 159, 213, 146, 128, 132, 109, 111, 94, 112, 186, 0, 0, 0, 0, 0, 0, 0, 0, 130, 186, 128, 0, 0, 0, 0, 0, 0, 0, 212, 146, 126, 125, 245, 167, 6, 77, 144, 105, 242, 2, 197, 171, 93, 11, 100, 207, 223, 103, 221, 8, 17, 80, 124, 186, 128, 0, 0, 0, 0, 0, 0, 0, 186, 0, 0, 0, 0, 0, 0, 0, 0, 211, 2, 0, 186, 128, 0, 0, 0, 0, 0, 0, 0, 211, 4, 0, 186, 0, 1, 0, 0, 0, 0, 0, 0, 195, 107, 211, 4, 0, 186, 0, 1, 0, 0, 0, 0, 0, 0, 189, 3, 185, 1, 38, 84, 7, 2, 0, 0, 0, 0, 27, 0]),
("std::crypto::hashes::sha256",vm_assembly::ProcedureId([133, 1, 193, 139, 249, 107, 201, 66, 165, 23, 211, 154, 221, 104, 154, 149, 124, 222, 95, 77, 74, 205, 105, 176]),"#! Given [x, ...] on stack top, this routine computes [y, ...]
#! such that y = σ_0(x), as defined in SHA specification
#!
#! See https://github.com/itzmeanjan/merklize-sha/blob/8a2c006/include/sha2.hpp#L73-L79
proc.small_sigma_0
    dup
    u32unchecked_rotr.7

    swap

    dup
    u32unchecked_rotr.18

    swap

    u32unchecked_shr.3

    u32checked_xor
    u32checked_xor
end

#! Given [x, ...] on stack top, this routine computes [y, ...]
#! such that y = σ_1(x), as defined in SHA specification
#!
#! See https://github.com/itzmeanjan/merklize-sha/blob/8a2c006/include/sha2.hpp#L81-L87
proc.small_sigma_1
    dup
    u32unchecked_rotr.17

    swap

    dup
    u32unchecked_rotr.19

    swap

    u32unchecked_shr.10

    u32checked_xor
    u32checked_xor
end

#! Given [x, ...] on stack top, this routine computes [y, ...]
#! such that y = Σ_0(x), as defined in SHA specification
#!
#! See https://github.com/itzmeanjan/merklize-sha/blob/8a2c006/include/sha2.hpp#L57-L63
proc.cap_sigma_0
    dup
    u32unchecked_rotr.2

    swap

    dup
    u32unchecked_rotr.13

    swap

    u32unchecked_rotr.22

    u32checked_xor
    u32checked_xor
end

#! Given [x, ...] on stack top, this routine computes [y, ...]
#! such that y = Σ_1(x), as defined in SHA specification
#!
#! See https://github.com/itzmeanjan/merklize-sha/blob/8a2c006/include/sha2.hpp#L65-L71
proc.cap_sigma_1
    dup
    u32unchecked_rotr.6

    swap

    dup
    u32unchecked_rotr.11

    swap

    u32unchecked_rotr.25

    u32checked_xor
    u32checked_xor
end

#! Given [x, y, z, ...] on stack top, this routine computes [o, ...]
#! such that o = ch(x, y, z), as defined in SHA specification
#!
#! See https://github.com/itzmeanjan/merklize-sha/blob/8a2c006/include/sha2.hpp#L37-L45
proc.ch
    swap
    dup.1
    u32checked_and

    swap
    u32checked_not

    movup.2
    u32checked_and

    u32checked_xor
end

#! Given [x, y, z, ...] on stack top, this routine computes [o, ...]
#! such that o = maj(x, y, z), as defined in SHA specification
#!
#! See https://github.com/itzmeanjan/merklize-sha/blob/8a2c006/include/sha2.hpp#L47-L55
proc.maj
    dup.1
    dup.1
    u32checked_and

    swap
    dup.3
    u32checked_and

    movup.2
    movup.3
    u32checked_and

    u32checked_xor
    u32checked_xor
end

#! Given [a, b, c, d, ...] on stack top, this routine reverses order of first 
#! four elements on stack top such that final stack state looks like [d, c, b, a, ...]
proc.rev_element_order
    swap
    movup.2
    movup.3
end

#! Given [a, b, c, d, ...] on stack top, this routine computes next message schedule word
#! using following formula
#!
#! t0 = small_sigma_1(a) + b
#! t1 = small_sigma_0(c) + d
#! return t0 + t1
#!
#! If to be computed message schedule word has index i ∈ [16, 64), then 
#! a, b, c, d will have following indices in message schedule
#!
#! a = msg[i - 2]
#! b = msg[i - 7]
#! c = msg[i - 15]
#! d = msg[i - 16]
proc.compute_message_schedule_word
    exec.small_sigma_1
    movup.2
    exec.small_sigma_0

    u32overflowing_add3
    drop
    u32wrapping_add
end

#! Given eight working variables of SHA256 ( i.e. hash state ), a 32 -bit round constant & 
#! 32 -bit message word on stack top, this routine consumes constant & message word into 
#! hash state.
#!
#! Expected stack state looks like
#!
#! [a, b, c, d, e, f, g, h, CONST_i, WORD_i] | i ∈ [0, 64)
#!
#! After finishing execution, stack looks like
#!
#! [a', b', c', d', e', f', g', h']
#!
#! See https://github.com/itzmeanjan/merklize-sha/blob/8a2c006/include/sha2_256.hpp#L165-L175
proc.consume_message_word
    dup.6
    dup.6
    dup.6
    exec.ch

    movup.9
    movup.10

    u32overflowing_add3
    drop

    dup.5
    exec.cap_sigma_1

    movup.9
    u32overflowing_add3
    drop

    dup.3
    dup.3
    dup.3
    exec.maj

    dup.2
    exec.cap_sigma_0

    u32wrapping_add

    movup.5
    dup.2
    u32wrapping_add
    movdn.5

    u32wrapping_add
end

#! Given 32 -bytes hash state ( in terms of 8 SHA256 words ) and 64 -bytes input 
#! message ( in terms of 16 SHA256 words ) on stack top, this routine computes
#! whole message schedule of 64 message words and consumes them into hash state.
#!
#! Expected stack state:
#!
#! [state0, state1, state2, state3, state4, state5, state6, state7, msg0, msg1, msg2, msg3, msg4, msg5, msg6, msg7, msg8, msg9, msg10, msg11, msg12, msg13, msg14, msg15]
#!
#! Final stack state after completion of execution
#!
#! [state0', state1', state2', state3', state4', state5', state6', state7']
#!
#! Note, each SHA256 word is 32 -bit wide
#!
#! See https://github.com/itzmeanjan/merklize-sha/blob/8a2c006/include/sha2.hpp#L89-L113
#! & https://github.com/itzmeanjan/merklize-sha/blob/8a2c006/include/sha2_256.hpp#L148-L187 ( loop body execution when i = 0 )
proc.prepare_message_schedule_and_consume.2
    loc_storew.0
    dropw
    loc_storew.1
    dropw

    dup.15
    dup.15

    dup.11
    swap
    dup.4
    dup.4
    movdn.3
    movdn.2
    exec.compute_message_schedule_word # computed msg[16]

    swap
    dup.12
    swap
    dup.5
    dup.5
    movdn.3
    movdn.2
    exec.compute_message_schedule_word # computed msg[17]

    dup.1
    dup.14
    swap
    dup.7
    dup.7
    movdn.3
    movdn.2
    exec.compute_message_schedule_word # computed msg[18]

    dup.15
    dup.2
    dup.9
    dup.9
    movdn.3
    movdn.2
    exec.compute_message_schedule_word # computed msg[19]

    swapw

    push.0x428a2f98
    push.0.0.0.0
    loc_loadw.1
    push.0.0.0.0
    loc_loadw.0
    exec.consume_message_word # consume msg[0]

    push.0x71374491
    movdn.8
    exec.consume_message_word # consume msg[1]

    push.0xb5c0fbcf
    movdn.8
    exec.consume_message_word # consume msg[2]

    push.0xe9b5dba5
    movdn.8
    exec.consume_message_word # consume msg[3]

    loc_storew.0
    dropw
    loc_storew.1
    dropw

    dup.15
    dup.15
    dup.15

    dup.4
    dup.9
    dup.9
    movdn.3
    movdn.2
    exec.compute_message_schedule_word # computed msg[20]

    swap
    dup.3
    dup.10
    dup.10
    movdn.3
    movdn.2
    exec.compute_message_schedule_word # computed msg[21]

    movup.2
    dup.2
    dup.11
    dup.11
    movdn.3
    movdn.2
    exec.compute_message_schedule_word # computed msg[22]

    dup.6
    dup.2
    dup.13
    dup.13
    movdn.3
    movdn.2
    exec.compute_message_schedule_word # computed msg[23]

    movupw.2

    push.0x3956c25b
    push.0.0.0.0
    loc_loadw.1
    push.0.0.0.0
    loc_loadw.0
    exec.consume_message_word # consume msg[4]

    push.0x59f111f1
    movdn.8
    exec.consume_message_word # consume msg[5]

    push.0x923f82a4
    movdn.8
    exec.consume_message_word # consume msg[6]

    push.0xab1c5ed5
    movdn.8
    exec.consume_message_word # consume msg[7]

    loc_storew.0
    dropw
    loc_storew.1
    dropw

    dup.6
    dup.2
    dup.11
    dup.11
    movdn.3
    movdn.2
    exec.compute_message_schedule_word # computed msg[24]

    dup.6
    dup.2
    dup.13
    dup.13
    movdn.3
    movdn.2
    exec.compute_message_schedule_word # computed msg[25]

    dup.6
    dup.2
    dup.15
    dup.15
    movdn.3
    movdn.2
    exec.compute_message_schedule_word # computed msg[26]

    dup.15
    dup.15
    swap
    dup.8
    dup.4
    exec.compute_message_schedule_word # computed msg[27]

    movupw.3

    push.0xd807aa98
    push.0.0.0.0
    loc_loadw.1
    push.0.0.0.0
    loc_loadw.0
    exec.consume_message_word # consume msg[8]

    push.0x12835b01
    movdn.8
    exec.consume_message_word # consume msg[9]

    push.0x243185be
    movdn.8
    exec.consume_message_word # consume msg[10]

    push.0x550c7dc3
    movdn.8
    exec.consume_message_word # consume msg[11]

    loc_storew.0
    dropw
    loc_storew.1
    dropw

    movupw.3
    movupw.3

    dup.14
    dup.10
    dup.7
    dup.7
    movdn.3
    movdn.2
    exec.compute_message_schedule_word # computed msg[28]

    dup.14
    dup.10
    dup.9
    dup.9
    movdn.3
    movdn.2
    exec.compute_message_schedule_word # computed msg[29]

    dup.14
    dup.2
    dup.11
    dup.11
    movdn.3
    movdn.2
    exec.compute_message_schedule_word # computed msg[30]

    dup.14
    dup.2
    dup.8
    dup.13
    movdn.3
    movdn.2
    exec.compute_message_schedule_word # computed msg[31]

    movupw.2

    push.0x72be5d74
    push.0.0.0.0
    loc_loadw.1
    push.0.0.0.0
    loc_loadw.0
    exec.consume_message_word # consume msg[12]

    push.0x80deb1fe
    movdn.8
    exec.consume_message_word # consume msg[13]

    push.0x9bdc06a7
    movdn.8
    exec.consume_message_word # consume msg[14]

    push.0xc19bf174
    movdn.8
    exec.consume_message_word # consume msg[15]

    loc_storew.0
    dropw
    loc_storew.1
    dropw

    movupw.3

    dup.14
    dup.6
    dup.13
    dup.13
    movdn.3
    movdn.3
    exec.compute_message_schedule_word # computed msg[32]

    dup.14
    dup.6
    dup.13
    dup.13
    movdn.3
    movdn.3
    exec.compute_message_schedule_word # computed msg[33]

    dup.14
    dup.2
    dup.13
    dup.13
    movdn.3
    movdn.3
    exec.compute_message_schedule_word # computed msg[34]

    dup.10
    dup.2
    dup.8
    dup.14
    movdn.3
    movdn.2
    exec.compute_message_schedule_word # computed msg[35]

    movupw.3
    exec.rev_element_order

    push.0xe49b69c1
    push.0.0.0.0
    loc_loadw.1
    push.0.0.0.0
    loc_loadw.0
    exec.consume_message_word # consume msg[16]

    push.0xefbe4786
    movdn.8
    exec.consume_message_word # consume msg[17]

    push.0x0fc19dc6
    movdn.8
    exec.consume_message_word # consume msg[18]

    push.0x240ca1cc
    movdn.8
    exec.consume_message_word # consume msg[19]

    loc_storew.0
    dropw
    loc_storew.1
    dropw

    movupw.3

    dup.14
    dup.6
    dup.13
    dup.13
    movdn.3
    movdn.3
    exec.compute_message_schedule_word # computed msg[36]

    dup.14
    dup.6
    dup.13
    dup.13
    movdn.3
    movdn.3
    exec.compute_message_schedule_word # computed msg[37]

    dup.14
    dup.2
    dup.13
    dup.13
    movdn.3
    movdn.3
    exec.compute_message_schedule_word # computed msg[38]

    dup.10
    dup.2
    dup.8
    dup.14
    movdn.3
    movdn.2
    exec.compute_message_schedule_word # computed msg[39]

    movupw.3
    exec.rev_element_order

    push.0x2de92c6f
    push.0.0.0.0
    loc_loadw.1
    push.0.0.0.0
    loc_loadw.0
    exec.consume_message_word # consume msg[20]

    push.0x4a7484aa
    movdn.8
    exec.consume_message_word # consume msg[21]

    push.0x5cb0a9dc
    movdn.8
    exec.consume_message_word # consume msg[22]

    push.0x76f988da
    movdn.8
    exec.consume_message_word # consume msg[23]

    loc_storew.0
    dropw
    loc_storew.1
    dropw

    movupw.3

    dup.14
    dup.6
    dup.13
    dup.13
    movdn.3
    movdn.3
    exec.compute_message_schedule_word # computed msg[40]

    dup.14
    dup.6
    dup.13
    dup.13
    movdn.3
    movdn.3
    exec.compute_message_schedule_word # computed msg[41]

    dup.14
    dup.2
    dup.13
    dup.13
    movdn.3
    movdn.3
    exec.compute_message_schedule_word # computed msg[42]

    dup.10
    dup.2
    dup.13
    dup.9
    movdn.3
    movdn.3
    exec.compute_message_schedule_word # computed msg[43]

    movupw.3
    exec.rev_element_order

    push.0x983e5152
    push.0.0.0.0
    loc_loadw.1
    push.0.0.0.0
    loc_loadw.0
    exec.consume_message_word # consume msg[24]

    push.0xa831c66d
    movdn.8
    exec.consume_message_word # consume msg[25]

    push.0xb00327c8
    movdn.8
    exec.consume_message_word # consume msg[26]

    push.0xbf597fc7
    movdn.8
    exec.consume_message_word # consume msg[27]

    loc_storew.0
    dropw
    loc_storew.1
    dropw

    movupw.3

    dup.14
    dup.6
    dup.13
    dup.13
    movdn.3
    movdn.3
    exec.compute_message_schedule_word # computed msg[44]

    dup.14
    dup.6
    dup.13
    dup.13
    movdn.3
    movdn.3
    exec.compute_message_schedule_word # computed msg[45]

    dup.14
    dup.2
    dup.13
    dup.13
    movdn.3
    movdn.3
    exec.compute_message_schedule_word # computed msg[46]

    dup.10
    dup.2
    dup.8
    dup.14
    movdn.3
    movdn.2
    exec.compute_message_schedule_word # computed msg[47]

    movupw.3
    exec.rev_element_order

    push.0xc6e00bf3
    push.0.0.0.0
    loc_loadw.1
    push.0.0.0.0
    loc_loadw.0
    exec.consume_message_word # consume msg[28]

    push.0xd5a79147
    movdn.8
    exec.consume_message_word # consume msg[29]

    push.0x06ca6351
    movdn.8
    exec.consume_message_word # consume msg[30]

    push.0x14292967
    movdn.8
    exec.consume_message_word # consume msg[31]

    loc_storew.0
    dropw
    loc_storew.1
    dropw

    movupw.3

    dup.14
    dup.6
    dup.13
    dup.13
    movdn.3
    movdn.3
    exec.compute_message_schedule_word # computed msg[48]

    dup.14
    dup.6
    dup.13
    dup.13
    movdn.3
    movdn.3
    exec.compute_message_schedule_word # computed msg[49]

    dup.14
    dup.2
    dup.13
    dup.13
    movdn.3
    movdn.3
    exec.compute_message_schedule_word # computed msg[50]

    dup.10
    dup.2
    dup.8
    dup.14
    movdn.3
    movdn.2
    exec.compute_message_schedule_word # computed msg[51]

    movupw.3
    exec.rev_element_order

    push.0x27b70a85
    push.0.0.0.0
    loc_loadw.1
    push.0.0.0.0
    loc_loadw.0
    exec.consume_message_word # consume msg[32]

    push.0x2e1b2138
    movdn.8
    exec.consume_message_word # consume msg[33]

    push.0x4d2c6dfc
    movdn.8
    exec.consume_message_word # consume msg[34]

    push.0x53380d13
    movdn.8
    exec.consume_message_word # consume msg[35]

    loc_storew.0
    dropw
    loc_storew.1
    dropw

    movupw.3

    dup.14
    dup.6
    dup.13
    dup.13
    movdn.3
    movdn.3
    exec.compute_message_schedule_word # computed msg[52]

    dup.14
    dup.6
    dup.13
    dup.13
    movdn.3
    movdn.3
    exec.compute_message_schedule_word # computed msg[53]

    dup.14
    dup.2
    dup.13
    dup.13
    movdn.3
    movdn.3
    exec.compute_message_schedule_word # computed msg[54]

    dup.10
    dup.2
    dup.8
    dup.14
    movdn.3
    movdn.2
    exec.compute_message_schedule_word # computed msg[55]

    movupw.3
    exec.rev_element_order

    push.0x650a7354
    push.0.0.0.0
    loc_loadw.1
    push.0.0.0.0
    loc_loadw.0
    exec.consume_message_word # consume msg[36]

    push.0x766a0abb
    movdn.8
    exec.consume_message_word # consume msg[37]

    push.0x81c2c92e
    movdn.8
    exec.consume_message_word # consume msg[38]

    push.0x92722c85
    movdn.8
    exec.consume_message_word # consume msg[39]

    loc_storew.0
    dropw
    loc_storew.1
    dropw

    movupw.3

    dup.14
    dup.6
    dup.13
    dup.13
    movdn.3
    movdn.3
    exec.compute_message_schedule_word # computed msg[56]

    dup.14
    dup.6
    dup.13
    dup.13
    movdn.3
    movdn.3
    exec.compute_message_schedule_word # computed msg[57]

    dup.14
    dup.2
    dup.13
    dup.13
    movdn.3
    movdn.3
    exec.compute_message_schedule_word # computed msg[58]

    dup.10
    dup.2
    dup.8
    dup.14
    movdn.3
    movdn.2
    exec.compute_message_schedule_word # computed msg[59]

    movupw.3
    exec.rev_element_order

    push.0xa2bfe8a1
    push.0.0.0.0
    loc_loadw.1
    push.0.0.0.0
    loc_loadw.0
    exec.consume_message_word # consume msg[40]

    push.0xa81a664b
    movdn.8
    exec.consume_message_word # consume msg[41]

    push.0xc24b8b70
    movdn.8
    exec.consume_message_word # consume msg[42]

    push.0xc76c51a3
    movdn.8
    exec.consume_message_word # consume msg[43]

    loc_storew.0
    dropw
    loc_storew.1
    dropw

    movupw.3

    dup.14
    dup.6
    dup.13
    dup.13
    movdn.3
    movdn.3
    exec.compute_message_schedule_word # computed msg[60]

    dup.14
    dup.6
    dup.13
    dup.13
    movdn.3
    movdn.3
    exec.compute_message_schedule_word # computed msg[61]

    dup.14
    dup.2
    dup.13
    dup.13
    movdn.3
    movdn.3
    exec.compute_message_schedule_word # computed msg[62]

    dup.10
    dup.2
    dup.8
    dup.14
    movdn.3
    movdn.2
    exec.compute_message_schedule_word # computed msg[63]

    movupw.3
    exec.rev_element_order

    push.0xd192e819
    push.0.0.0.0
    loc_loadw.1
    push.0.0.0.0
    loc_loadw.0
    exec.consume_message_word # consume msg[44]

    push.0xd6990624
    movdn.8
    exec.consume_message_word # consume msg[45]

    push.0xf40e3585
    movdn.8
    exec.consume_message_word # consume msg[46]

    push.0x106aa070
    movdn.8
    exec.consume_message_word # consume msg[47]

    loc_storew.0
    dropw
    loc_storew.1
    dropw

    movupw.2
    movupw.3
    movupw.3

    exec.rev_element_order

    push.0x19a4c116
    push.0.0.0.0
    loc_loadw.1
    push.0.0.0.0
    loc_loadw.0
    exec.consume_message_word # consume msg[48]

    push.0x1e376c08
    movdn.8
    exec.consume_message_word # consume msg[49]

    push.0x2748774c
    movdn.8
    exec.consume_message_word # consume msg[50]

    push.0x34b0bcb5
    movdn.8
    exec.consume_message_word # consume msg[51]

    movupw.2
    exec.rev_element_order
    movdnw.2

    push.0x391c0cb3
    movdn.8
    exec.consume_message_word # consume msg[52]

    push.0x4ed8aa4a
    movdn.8
    exec.consume_message_word # consume msg[53]

    push.0x5b9cca4f
    movdn.8
    exec.consume_message_word # consume msg[54]

    push.0x682e6ff3
    movdn.8
    exec.consume_message_word # consume msg[55]

    movupw.2
    exec.rev_element_order
    movdnw.2

    push.0x748f82ee
    movdn.8
    exec.consume_message_word # consume msg[56]

    push.0x78a5636f
    movdn.8
    exec.consume_message_word # consume msg[57]

    push.0x84c87814
    movdn.8
    exec.consume_message_word # consume msg[58]

    push.0x8cc70208
    movdn.8
    exec.consume_message_word # consume msg[59]

    movupw.2
    exec.rev_element_order
    movdnw.2

    push.0x90befffa
    movdn.8
    exec.consume_message_word # consume msg[60]

    push.0xa4506ceb
    movdn.8
    exec.consume_message_word # consume msg[61]

    push.0xbef9a3f7
    movdn.8
    exec.consume_message_word # consume msg[62]

    push.0xc67178f2
    movdn.8
    exec.consume_message_word # consume msg[63]

    push.0x6a09e667
    u32wrapping_add

    swap
    push.0xbb67ae85
    u32wrapping_add
    swap

    movup.2
    push.0x3c6ef372
    u32wrapping_add
    movdn.2

    movup.3
    push.0xa54ff53a
    u32wrapping_add
    movdn.3

    movup.4
    push.0x510e527f
    u32wrapping_add
    movdn.4

    movup.5
    push.0x9b05688c
    u32wrapping_add
    movdn.5

    movup.6
    push.0x1f83d9ab
    u32wrapping_add
    movdn.6

    movup.7
    push.0x5be0cd19
    u32wrapping_add
    movdn.7
end

#! Given 32 -bytes hash state ( in terms of 8 SHA256 words ) and precomputed message 
#! schedule of padding bytes ( in terms of 64 message words ), this routine consumes
#! that into hash state, leaving final hash state, which is 32 -bytes SHA256 digest.
#!
#! Note, in SHA256 2-to-1 hashing, 64 -bytes are padded, which is processed as second message
#! block ( each SHA256 message block is 64 -bytes wide ). That message block is used for generating 
#! message schedule of 64 SHA256 words. That's exactly what can be precomputed & is consumed here 
#! ( in this routine ) into provided hash state.
#!
#! Expected stack state:
#!
#! [state0, state1, state2, state3, state4, state5, state6, state7, ...]
#!
#! Final stack state after completion of execution
#!
#! [state0', state1', state2', state3', state4', state5', state6', state7']
#!
#! Note, each SHA256 word is 32 -bit wide
#!
#! See https://github.com/itzmeanjan/merklize-sha/blob/8a2c006/include/sha2_256.hpp#L148-L187 ( loop 
#! body execution when i = 1 i.e. consuming padding bytes )
proc.consume_padding_message_schedule
    dupw.1
    dupw.1

    push.2147483648
    movdn.8
    push.0x428a2f98
    movdn.8
    exec.consume_message_word # consume msg[0]

    push.0
    movdn.8
    push.0x71374491
    movdn.8
    exec.consume_message_word # consume msg[1]

    push.0
    movdn.8
    push.0xb5c0fbcf
    movdn.8
    exec.consume_message_word # consume msg[2]

    push.0
    movdn.8
    push.0xe9b5dba5
    movdn.8
    exec.consume_message_word # consume msg[3]

    push.0
    movdn.8
    push.0x3956c25b
    movdn.8
    exec.consume_message_word # consume msg[4]

    push.0
    movdn.8
    push.0x59f111f1
    movdn.8
    exec.consume_message_word # consume msg[5]

    push.0
    movdn.8
    push.0x923f82a4
    movdn.8
    exec.consume_message_word # consume msg[6]

    push.0
    movdn.8
    push.0xab1c5ed5
    movdn.8
    exec.consume_message_word # consume msg[7]

    push.0
    movdn.8
    push.0xd807aa98
    movdn.8
    exec.consume_message_word # consume msg[8]

    push.0
    movdn.8
    push.0x12835b01
    movdn.8
    exec.consume_message_word # consume msg[9]

    push.0
    movdn.8
    push.0x243185be
    movdn.8
    exec.consume_message_word # consume msg[10]

    push.0
    movdn.8
    push.0x550c7dc3
    movdn.8
    exec.consume_message_word # consume msg[11]

    push.0
    movdn.8
    push.0x72be5d74
    movdn.8
    exec.consume_message_word # consume msg[12]

    push.0
    movdn.8
    push.0x80deb1fe
    movdn.8
    exec.consume_message_word # consume msg[13]

    push.0
    movdn.8
    push.0x9bdc06a7
    movdn.8
    exec.consume_message_word # consume msg[14]

    push.512
    movdn.8
    push.0xc19bf174
    movdn.8
    exec.consume_message_word # consume msg[15]

    push.2147483648
    movdn.8
    push.0xe49b69c1
    movdn.8
    exec.consume_message_word # consume msg[16]

    push.20971520
    movdn.8
    push.0xefbe4786
    movdn.8
    exec.consume_message_word # consume msg[17]

    push.2117632
    movdn.8
    push.0x0fc19dc6
    movdn.8
    exec.consume_message_word # consume msg[18]

    push.20616
    movdn.8
    push.0x240ca1cc
    movdn.8
    exec.consume_message_word # consume msg[19]

    push.570427392
    movdn.8
    push.0x2de92c6f
    movdn.8
    exec.consume_message_word # consume msg[20]

    push.575995924
    movdn.8
    push.0x4a7484aa
    movdn.8
    exec.consume_message_word # consume msg[21]

    push.84449090
    movdn.8
    push.0x5cb0a9dc
    movdn.8
    exec.consume_message_word # consume msg[22]

    push.2684354592
    movdn.8
    push.0x76f988da
    movdn.8
    exec.consume_message_word # consume msg[23]

    push.1518862336
    movdn.8
    push.0x983e5152
    movdn.8
    exec.consume_message_word # consume msg[24]

    push.6067200
    movdn.8
    push.0xa831c66d
    movdn.8
    exec.consume_message_word # consume msg[25]

    push.1496221
    movdn.8
    push.0xb00327c8
    movdn.8
    exec.consume_message_word # consume msg[26]

    push.4202700544
    movdn.8
    push.0xbf597fc7
    movdn.8
    exec.consume_message_word # consume msg[27]

    push.3543279056
    movdn.8
    push.0xc6e00bf3
    movdn.8
    exec.consume_message_word # consume msg[28]

    push.291985753
    movdn.8
    push.0xd5a79147
    movdn.8
    exec.consume_message_word # consume msg[29]

    push.4142317530
    movdn.8
    push.0x06ca6351
    movdn.8
    exec.consume_message_word # consume msg[30]

    push.3003913545
    movdn.8
    push.0x14292967
    movdn.8
    exec.consume_message_word # consume msg[31]

    push.145928272
    movdn.8
    push.0x27b70a85
    movdn.8
    exec.consume_message_word # consume msg[32]

    push.2642168871
    movdn.8
    push.0x2e1b2138
    movdn.8
    exec.consume_message_word # consume msg[33]

    push.216179603
    movdn.8
    push.0x4d2c6dfc
    movdn.8
    exec.consume_message_word # consume msg[34]

    push.2296832490
    movdn.8
    push.0x53380d13
    movdn.8
    exec.consume_message_word # consume msg[35]

    push.2771075893
    movdn.8
    push.0x650a7354
    movdn.8
    exec.consume_message_word # consume msg[36]

    push.1738633033
    movdn.8
    push.0x766a0abb
    movdn.8
    exec.consume_message_word # consume msg[37]

    push.3610378607
    movdn.8
    push.0x81c2c92e
    movdn.8
    exec.consume_message_word # consume msg[38]

    push.1324035729
    movdn.8
    push.0x92722c85
    movdn.8
    exec.consume_message_word # consume msg[39]

    push.1572820453
    movdn.8
    push.0xa2bfe8a1
    movdn.8
    exec.consume_message_word # consume msg[40]

    push.2397971253
    movdn.8
    push.0xa81a664b
    movdn.8
    exec.consume_message_word # consume msg[41]

    push.3803995842
    movdn.8
    push.0xc24b8b70
    movdn.8
    exec.consume_message_word # consume msg[42]

    push.2822718356
    movdn.8
    push.0xc76c51a3
    movdn.8
    exec.consume_message_word # consume msg[43]

    push.1168996599
    movdn.8
    push.0xd192e819
    movdn.8
    exec.consume_message_word # consume msg[44]

    push.921948365
    movdn.8
    push.0xd6990624
    movdn.8
    exec.consume_message_word # consume msg[45]

    push.3650881000
    movdn.8
    push.0xf40e3585
    movdn.8
    exec.consume_message_word # consume msg[46]

    push.2958106055
    movdn.8
    push.0x106aa070
    movdn.8
    exec.consume_message_word # consume msg[47]

    push.1773959876
    movdn.8
    push.0x19a4c116
    movdn.8
    exec.consume_message_word # consume msg[48]

    push.3172022107
    movdn.8
    push.0x1e376c08
    movdn.8
    exec.consume_message_word # consume msg[49]

    push.3820646885
    movdn.8
    push.0x2748774c
    movdn.8
    exec.consume_message_word # consume msg[50]

    push.991993842
    movdn.8
    push.0x34b0bcb5
    movdn.8
    exec.consume_message_word # consume msg[51]

    push.419360279
    movdn.8
    push.0x391c0cb3
    movdn.8
    exec.consume_message_word # consume msg[52]

    push.3797604839
    movdn.8
    push.0x4ed8aa4a
    movdn.8
    exec.consume_message_word # consume msg[53]

    push.322392134
    movdn.8
    push.0x5b9cca4f
    movdn.8
    exec.consume_message_word # consume msg[54]

    push.85264541
    movdn.8
    push.0x682e6ff3
    movdn.8
    exec.consume_message_word # consume msg[55]

    push.1326255876
    movdn.8
    push.0x748f82ee
    movdn.8
    exec.consume_message_word # consume msg[56]

    push.640108622
    movdn.8
    push.0x78a5636f
    movdn.8
    exec.consume_message_word # consume msg[57]

    push.822159570
    movdn.8
    push.0x84c87814
    movdn.8
    exec.consume_message_word # consume msg[58]

    push.3328750644
    movdn.8
    push.0x8cc70208
    movdn.8
    exec.consume_message_word # consume msg[59]

    push.1107837388
    movdn.8
    push.0x90befffa
    movdn.8
    exec.consume_message_word # consume msg[60]

    push.1657999800
    movdn.8
    push.0xa4506ceb
    movdn.8
    exec.consume_message_word # consume msg[61]

    push.3852183409
    movdn.8
    push.0xbef9a3f7
    movdn.8
    exec.consume_message_word # consume msg[62]

    push.2242356356
    movdn.8
    push.0xc67178f2
    movdn.8
    exec.consume_message_word # consume msg[63]

    movup.8
    u32wrapping_add

    swap
    movup.8
    u32wrapping_add
    swap

    movup.2
    movup.8
    u32wrapping_add
    movdn.2

    movup.3
    movup.8
    u32wrapping_add
    movdn.3

    movup.4
    movup.8
    u32wrapping_add
    movdn.4

    movup.5
    movup.8
    u32wrapping_add
    movdn.5

    movup.6
    movup.8
    u32wrapping_add
    movdn.6

    movup.7
    movup.8
    u32wrapping_add
    movdn.7
end

#! Given 64 -bytes input, this routine computes 32 -bytes SAH256 digest
#!
#! Expected stack state:
#!
#! [m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15] | m[0,16) = 32 -bit word
#!
#! Note, each SHA256 word is 32 -bit wide, so that's how input is expected.
#! If you've 64 -bytes, consider packing 4 consecutive bytes into single word, 
#! maintaining big endian byte order.
#!
#! Final stack state:
#!
#! [dig0, dig1, dig2, dig3, dig4, dig5, dig6, dig7]
#!
#! SHA256 digest is represented in terms of eight 32 -bit words ( big endian byte order ).
export.hash
    push.0x5be0cd19.0x1f83d9ab.0x9b05688c.0x510e527f
    push.0xa54ff53a.0x3c6ef372.0xbb67ae85.0x6a09e667

    exec.prepare_message_schedule_and_consume
    exec.consume_padding_message_schedule
end
",&[12, 0, 13, 115, 109, 97, 108, 108, 95, 115, 105, 103, 109, 97, 95, 48, 0, 0, 0, 0, 0, 9, 0, 110, 86, 7, 130, 110, 86, 18, 130, 78, 3, 73, 73, 13, 115, 109, 97, 108, 108, 95, 115, 105, 103, 109, 97, 95, 49, 0, 0, 0, 0, 0, 9, 0, 110, 86, 17, 130, 110, 86, 19, 130, 78, 10, 73, 73, 11, 99, 97, 112, 95, 115, 105, 103, 109, 97, 95, 48, 0, 0, 0, 0, 0, 9, 0, 110, 86, 2, 130, 110, 86, 13, 130, 86, 22, 73, 73, 11, 99, 97, 112, 95, 115, 105, 103, 109, 97, 95, 49, 0, 0, 0, 0, 0, 9, 0, 110, 86, 6, 130, 110, 86, 11, 130, 86, 25, 73, 73, 2, 99, 104, 0, 0, 0, 0, 0, 8, 0, 130, 111, 71, 130, 74, 149, 71, 73, 3, 109, 97, 106, 0, 0, 0, 0, 0, 11, 0, 111, 111, 71, 130, 113, 71, 149, 150, 71, 73, 73, 17, 114, 101, 118, 95, 101, 108, 101, 109, 101, 110, 116, 95, 111, 114, 100, 101, 114, 0, 0, 0, 0, 0, 3, 0, 130, 149, 150, 29, 99, 111, 109, 112, 117, 116, 101, 95, 109, 101, 115, 115, 97, 103, 101, 95, 115, 99, 104, 101, 100, 117, 108, 101, 95, 119, 111, 114, 100, 0, 0, 0, 0, 0, 6, 0, 211, 1, 0, 149, 211, 0, 0, 43, 107, 39, 20, 99, 111, 110, 115, 117, 109, 101, 95, 109, 101, 115, 115, 97, 103, 101, 95, 119, 111, 114, 100, 0, 0, 0, 0, 0, 25, 0, 116, 116, 116, 211, 4, 0, 156, 157, 43, 107, 115, 211, 3, 0, 156, 43, 107, 113, 113, 113, 211, 5, 0, 112, 211, 2, 0, 39, 152, 112, 39, 168, 39, 36, 112, 114, 101, 112, 97, 114, 101, 95, 109, 101, 115, 115, 97, 103, 101, 95, 115, 99, 104, 101, 100, 117, 108, 101, 95, 97, 110, 100, 95, 99, 111, 110, 115, 117, 109, 101, 0, 0, 0, 2, 0, 185, 2, 200, 0, 0, 0, 0, 0, 0, 0, 0, 108, 200, 1, 0, 0, 0, 0, 0, 0, 0, 108, 125, 125, 121, 130, 114, 114, 166, 165, 211, 7, 0, 130, 122, 130, 115, 115, 166, 165, 211, 7, 0, 111, 124, 130, 117, 117, 166, 165, 211, 7, 0, 125, 112, 119, 119, 166, 165, 211, 7, 0, 145, 185, 1, 152, 47, 138, 66, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 1, 0, 0, 0, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 0, 0, 0, 0, 0, 0, 0, 0, 211, 8, 0, 185, 1, 145, 68, 55, 113, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 207, 251, 192, 181, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 165, 219, 181, 233, 0, 0, 0, 0, 171, 211, 8, 0, 200, 0, 0, 0, 0, 0, 0, 0, 0, 108, 200, 1, 0, 0, 0, 0, 0, 0, 0, 108, 125, 125, 125, 114, 119, 119, 166, 165, 211, 7, 0, 130, 113, 120, 120, 166, 165, 211, 7, 0, 149, 112, 121, 121, 166, 165, 211, 7, 0, 116, 112, 123, 123, 166, 165, 211, 7, 0, 163, 185, 1, 91, 194, 86, 57, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 1, 0, 0, 0, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 0, 0, 0, 0, 0, 0, 0, 0, 211, 8, 0, 185, 1, 241, 17, 241, 89, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 164, 130, 63, 146, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 213, 94, 28, 171, 0, 0, 0, 0, 171, 211, 8, 0, 200, 0, 0, 0, 0, 0, 0, 0, 0, 108, 200, 1, 0, 0, 0, 0, 0, 0, 0, 108, 116, 112, 121, 121, 166, 165, 211, 7, 0, 116, 112, 123, 123, 166, 165, 211, 7, 0, 116, 112, 125, 125, 166, 165, 211, 7, 0, 125, 125, 130, 118, 114, 211, 7, 0, 164, 185, 1, 152, 170, 7, 216, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 1, 0, 0, 0, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 0, 0, 0, 0, 0, 0, 0, 0, 211, 8, 0, 185, 1, 1, 91, 131, 18, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 190, 133, 49, 36, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 195, 125, 12, 85, 0, 0, 0, 0, 171, 211, 8, 0, 200, 0, 0, 0, 0, 0, 0, 0, 0, 108, 200, 1, 0, 0, 0, 0, 0, 0, 0, 108, 164, 164, 124, 120, 117, 117, 166, 165, 211, 7, 0, 124, 120, 119, 119, 166, 165, 211, 7, 0, 124, 112, 121, 121, 166, 165, 211, 7, 0, 124, 112, 118, 123, 166, 165, 211, 7, 0, 163, 185, 1, 116, 93, 190, 114, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 1, 0, 0, 0, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 0, 0, 0, 0, 0, 0, 0, 0, 211, 8, 0, 185, 1, 254, 177, 222, 128, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 167, 6, 220, 155, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 116, 241, 155, 193, 0, 0, 0, 0, 171, 211, 8, 0, 200, 0, 0, 0, 0, 0, 0, 0, 0, 108, 200, 1, 0, 0, 0, 0, 0, 0, 0, 108, 164, 124, 116, 123, 123, 166, 166, 211, 7, 0, 124, 116, 123, 123, 166, 166, 211, 7, 0, 124, 112, 123, 123, 166, 166, 211, 7, 0, 120, 112, 118, 124, 166, 165, 211, 7, 0, 164, 211, 6, 0, 185, 1, 193, 105, 155, 228, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 1, 0, 0, 0, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 0, 0, 0, 0, 0, 0, 0, 0, 211, 8, 0, 185, 1, 134, 71, 190, 239, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 198, 157, 193, 15, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 204, 161, 12, 36, 0, 0, 0, 0, 171, 211, 8, 0, 200, 0, 0, 0, 0, 0, 0, 0, 0, 108, 200, 1, 0, 0, 0, 0, 0, 0, 0, 108, 164, 124, 116, 123, 123, 166, 166, 211, 7, 0, 124, 116, 123, 123, 166, 166, 211, 7, 0, 124, 112, 123, 123, 166, 166, 211, 7, 0, 120, 112, 118, 124, 166, 165, 211, 7, 0, 164, 211, 6, 0, 185, 1, 111, 44, 233, 45, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 1, 0, 0, 0, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 0, 0, 0, 0, 0, 0, 0, 0, 211, 8, 0, 185, 1, 170, 132, 116, 74, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 220, 169, 176, 92, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 218, 136, 249, 118, 0, 0, 0, 0, 171, 211, 8, 0, 200, 0, 0, 0, 0, 0, 0, 0, 0, 108, 200, 1, 0, 0, 0, 0, 0, 0, 0, 108, 164, 124, 116, 123, 123, 166, 166, 211, 7, 0, 124, 116, 123, 123, 166, 166, 211, 7, 0, 124, 112, 123, 123, 166, 166, 211, 7, 0, 120, 112, 123, 119, 166, 166, 211, 7, 0, 164, 211, 6, 0, 185, 1, 82, 81, 62, 152, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 1, 0, 0, 0, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 0, 0, 0, 0, 0, 0, 0, 0, 211, 8, 0, 185, 1, 109, 198, 49, 168, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 200, 39, 3, 176, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 199, 127, 89, 191, 0, 0, 0, 0, 171, 211, 8, 0, 200, 0, 0, 0, 0, 0, 0, 0, 0, 108, 200, 1, 0, 0, 0, 0, 0, 0, 0, 108, 164, 124, 116, 123, 123, 166, 166, 211, 7, 0, 124, 116, 123, 123, 166, 166, 211, 7, 0, 124, 112, 123, 123, 166, 166, 211, 7, 0, 120, 112, 118, 124, 166, 165, 211, 7, 0, 164, 211, 6, 0, 185, 1, 243, 11, 224, 198, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 1, 0, 0, 0, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 0, 0, 0, 0, 0, 0, 0, 0, 211, 8, 0, 185, 1, 71, 145, 167, 213, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 81, 99, 202, 6, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 103, 41, 41, 20, 0, 0, 0, 0, 171, 211, 8, 0, 200, 0, 0, 0, 0, 0, 0, 0, 0, 108, 200, 1, 0, 0, 0, 0, 0, 0, 0, 108, 164, 124, 116, 123, 123, 166, 166, 211, 7, 0, 124, 116, 123, 123, 166, 166, 211, 7, 0, 124, 112, 123, 123, 166, 166, 211, 7, 0, 120, 112, 118, 124, 166, 165, 211, 7, 0, 164, 211, 6, 0, 185, 1, 133, 10, 183, 39, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 1, 0, 0, 0, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 0, 0, 0, 0, 0, 0, 0, 0, 211, 8, 0, 185, 1, 56, 33, 27, 46, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 252, 109, 44, 77, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 19, 13, 56, 83, 0, 0, 0, 0, 171, 211, 8, 0, 200, 0, 0, 0, 0, 0, 0, 0, 0, 108, 200, 1, 0, 0, 0, 0, 0, 0, 0, 108, 164, 124, 116, 123, 123, 166, 166, 211, 7, 0, 124, 116, 123, 123, 166, 166, 211, 7, 0, 124, 112, 123, 123, 166, 166, 211, 7, 0, 120, 112, 118, 124, 166, 165, 211, 7, 0, 164, 211, 6, 0, 185, 1, 84, 115, 10, 101, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 1, 0, 0, 0, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 0, 0, 0, 0, 0, 0, 0, 0, 211, 8, 0, 185, 1, 187, 10, 106, 118, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 46, 201, 194, 129, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 133, 44, 114, 146, 0, 0, 0, 0, 171, 211, 8, 0, 200, 0, 0, 0, 0, 0, 0, 0, 0, 108, 200, 1, 0, 0, 0, 0, 0, 0, 0, 108, 164, 124, 116, 123, 123, 166, 166, 211, 7, 0, 124, 116, 123, 123, 166, 166, 211, 7, 0, 124, 112, 123, 123, 166, 166, 211, 7, 0, 120, 112, 118, 124, 166, 165, 211, 7, 0, 164, 211, 6, 0, 185, 1, 161, 232, 191, 162, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 1, 0, 0, 0, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 0, 0, 0, 0, 0, 0, 0, 0, 211, 8, 0, 185, 1, 75, 102, 26, 168, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 112, 139, 75, 194, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 163, 81, 108, 199, 0, 0, 0, 0, 171, 211, 8, 0, 200, 0, 0, 0, 0, 0, 0, 0, 0, 108, 200, 1, 0, 0, 0, 0, 0, 0, 0, 108, 164, 124, 116, 123, 123, 166, 166, 211, 7, 0, 124, 116, 123, 123, 166, 166, 211, 7, 0, 124, 112, 123, 123, 166, 166, 211, 7, 0, 120, 112, 118, 124, 166, 165, 211, 7, 0, 164, 211, 6, 0, 185, 1, 25, 232, 146, 209, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 1, 0, 0, 0, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 0, 0, 0, 0, 0, 0, 0, 0, 211, 8, 0, 185, 1, 36, 6, 153, 214, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 133, 53, 14, 244, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 112, 160, 106, 16, 0, 0, 0, 0, 171, 211, 8, 0, 200, 0, 0, 0, 0, 0, 0, 0, 0, 108, 200, 1, 0, 0, 0, 0, 0, 0, 0, 108, 163, 164, 164, 211, 6, 0, 185, 1, 22, 193, 164, 25, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 1, 0, 0, 0, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 0, 0, 0, 0, 0, 0, 0, 0, 211, 8, 0, 185, 1, 8, 108, 55, 30, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 76, 119, 72, 39, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 181, 188, 176, 52, 0, 0, 0, 0, 171, 211, 8, 0, 163, 211, 6, 0, 179, 185, 1, 179, 12, 28, 57, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 74, 170, 216, 78, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 79, 202, 156, 91, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 243, 111, 46, 104, 0, 0, 0, 0, 171, 211, 8, 0, 163, 211, 6, 0, 179, 185, 1, 238, 130, 143, 116, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 111, 99, 165, 120, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 20, 120, 200, 132, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 8, 2, 199, 140, 0, 0, 0, 0, 171, 211, 8, 0, 163, 211, 6, 0, 179, 185, 1, 250, 255, 190, 144, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 235, 108, 80, 164, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 247, 163, 249, 190, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 242, 120, 113, 198, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 103, 230, 9, 106, 0, 0, 0, 0, 39, 130, 185, 1, 133, 174, 103, 187, 0, 0, 0, 0, 39, 130, 149, 185, 1, 114, 243, 110, 60, 0, 0, 0, 0, 39, 165, 150, 185, 1, 58, 245, 79, 165, 0, 0, 0, 0, 39, 166, 151, 185, 1, 127, 82, 14, 81, 0, 0, 0, 0, 39, 167, 152, 185, 1, 140, 104, 5, 155, 0, 0, 0, 0, 39, 168, 153, 185, 1, 171, 217, 131, 31, 0, 0, 0, 0, 39, 169, 154, 185, 1, 25, 205, 224, 91, 0, 0, 0, 0, 39, 170, 32, 99, 111, 110, 115, 117, 109, 101, 95, 112, 97, 100, 100, 105, 110, 103, 95, 109, 101, 115, 115, 97, 103, 101, 95, 115, 99, 104, 101, 100, 117, 108, 101, 0, 0, 0, 0, 0, 96, 1, 127, 127, 185, 1, 0, 0, 0, 128, 0, 0, 0, 0, 171, 185, 1, 152, 47, 138, 66, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 0, 0, 0, 0, 0, 0, 0, 0, 171, 185, 1, 145, 68, 55, 113, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 0, 0, 0, 0, 0, 0, 0, 0, 171, 185, 1, 207, 251, 192, 181, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 0, 0, 0, 0, 0, 0, 0, 0, 171, 185, 1, 165, 219, 181, 233, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 0, 0, 0, 0, 0, 0, 0, 0, 171, 185, 1, 91, 194, 86, 57, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 0, 0, 0, 0, 0, 0, 0, 0, 171, 185, 1, 241, 17, 241, 89, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 0, 0, 0, 0, 0, 0, 0, 0, 171, 185, 1, 164, 130, 63, 146, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 0, 0, 0, 0, 0, 0, 0, 0, 171, 185, 1, 213, 94, 28, 171, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 0, 0, 0, 0, 0, 0, 0, 0, 171, 185, 1, 152, 170, 7, 216, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 0, 0, 0, 0, 0, 0, 0, 0, 171, 185, 1, 1, 91, 131, 18, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 0, 0, 0, 0, 0, 0, 0, 0, 171, 185, 1, 190, 133, 49, 36, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 0, 0, 0, 0, 0, 0, 0, 0, 171, 185, 1, 195, 125, 12, 85, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 0, 0, 0, 0, 0, 0, 0, 0, 171, 185, 1, 116, 93, 190, 114, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 0, 0, 0, 0, 0, 0, 0, 0, 171, 185, 1, 254, 177, 222, 128, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 0, 0, 0, 0, 0, 0, 0, 0, 171, 185, 1, 167, 6, 220, 155, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 0, 2, 0, 0, 0, 0, 0, 0, 171, 185, 1, 116, 241, 155, 193, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 0, 0, 0, 128, 0, 0, 0, 0, 171, 185, 1, 193, 105, 155, 228, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 0, 0, 64, 1, 0, 0, 0, 0, 171, 185, 1, 134, 71, 190, 239, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 0, 80, 32, 0, 0, 0, 0, 0, 171, 185, 1, 198, 157, 193, 15, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 136, 80, 0, 0, 0, 0, 0, 0, 171, 185, 1, 204, 161, 12, 36, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 0, 8, 0, 34, 0, 0, 0, 0, 171, 185, 1, 111, 44, 233, 45, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 20, 0, 85, 34, 0, 0, 0, 0, 171, 185, 1, 170, 132, 116, 74, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 66, 151, 8, 5, 0, 0, 0, 0, 171, 185, 1, 220, 169, 176, 92, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 32, 0, 0, 160, 0, 0, 0, 0, 171, 185, 1, 218, 136, 249, 118, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 0, 0, 136, 90, 0, 0, 0, 0, 171, 185, 1, 82, 81, 62, 152, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 0, 148, 92, 0, 0, 0, 0, 0, 171, 185, 1, 109, 198, 49, 168, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 157, 212, 22, 0, 0, 0, 0, 0, 171, 185, 1, 200, 39, 3, 176, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 0, 31, 128, 250, 0, 0, 0, 0, 171, 185, 1, 199, 127, 89, 191, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 208, 37, 50, 211, 0, 0, 0, 0, 171, 185, 1, 243, 11, 224, 198, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 89, 89, 103, 17, 0, 0, 0, 0, 171, 185, 1, 71, 145, 167, 213, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 218, 191, 230, 246, 0, 0, 0, 0, 171, 185, 1, 81, 99, 202, 6, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 73, 21, 12, 179, 0, 0, 0, 0, 171, 185, 1, 103, 41, 41, 20, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 80, 176, 178, 8, 0, 0, 0, 0, 171, 185, 1, 133, 10, 183, 39, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 39, 76, 124, 157, 0, 0, 0, 0, 171, 185, 1, 56, 33, 27, 46, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 147, 163, 226, 12, 0, 0, 0, 0, 171, 185, 1, 252, 109, 44, 77, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 234, 225, 230, 136, 0, 0, 0, 0, 171, 185, 1, 19, 13, 56, 83, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 53, 67, 43, 165, 0, 0, 0, 0, 171, 185, 1, 84, 115, 10, 101, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 73, 111, 161, 103, 0, 0, 0, 0, 171, 185, 1, 187, 10, 106, 118, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 111, 1, 50, 215, 0, 0, 0, 0, 171, 185, 1, 46, 201, 194, 129, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 145, 46, 235, 78, 0, 0, 0, 0, 171, 185, 1, 133, 44, 114, 146, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 229, 85, 191, 93, 0, 0, 0, 0, 171, 185, 1, 161, 232, 191, 162, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 53, 35, 238, 142, 0, 0, 0, 0, 171, 185, 1, 75, 102, 26, 168, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 194, 94, 188, 226, 0, 0, 0, 0, 171, 185, 1, 112, 139, 75, 194, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 148, 67, 63, 168, 0, 0, 0, 0, 171, 185, 1, 163, 81, 108, 199, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 247, 120, 173, 69, 0, 0, 0, 0, 171, 185, 1, 25, 232, 146, 209, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 205, 208, 243, 54, 0, 0, 0, 0, 171, 185, 1, 36, 6, 153, 214, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 232, 5, 156, 217, 0, 0, 0, 0, 171, 185, 1, 133, 53, 14, 244, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 199, 29, 81, 176, 0, 0, 0, 0, 171, 185, 1, 112, 160, 106, 16, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 196, 122, 188, 105, 0, 0, 0, 0, 171, 185, 1, 22, 193, 164, 25, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 91, 55, 17, 189, 0, 0, 0, 0, 171, 185, 1, 8, 108, 55, 30, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 229, 113, 186, 227, 0, 0, 0, 0, 171, 185, 1, 76, 119, 72, 39, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 242, 159, 32, 59, 0, 0, 0, 0, 171, 185, 1, 181, 188, 176, 52, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 23, 238, 254, 24, 0, 0, 0, 0, 171, 185, 1, 179, 12, 28, 57, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 231, 217, 90, 226, 0, 0, 0, 0, 171, 185, 1, 74, 170, 216, 78, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 70, 80, 55, 19, 0, 0, 0, 0, 171, 185, 1, 79, 202, 156, 91, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 157, 8, 21, 5, 0, 0, 0, 0, 171, 185, 1, 243, 111, 46, 104, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 4, 15, 13, 79, 0, 0, 0, 0, 171, 185, 1, 238, 130, 143, 116, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 78, 72, 39, 38, 0, 0, 0, 0, 171, 185, 1, 111, 99, 165, 120, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 210, 40, 1, 49, 0, 0, 0, 0, 171, 185, 1, 20, 120, 200, 132, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 52, 180, 104, 198, 0, 0, 0, 0, 171, 185, 1, 8, 2, 199, 140, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 204, 65, 8, 66, 0, 0, 0, 0, 171, 185, 1, 250, 255, 190, 144, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 184, 17, 211, 98, 0, 0, 0, 0, 171, 185, 1, 235, 108, 80, 164, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 113, 167, 155, 229, 0, 0, 0, 0, 171, 185, 1, 247, 163, 249, 190, 0, 0, 0, 0, 171, 211, 8, 0, 185, 1, 132, 164, 167, 133, 0, 0, 0, 0, 171, 185, 1, 242, 120, 113, 198, 0, 0, 0, 0, 171, 211, 8, 0, 155, 39, 130, 155, 39, 130, 149, 155, 39, 165, 150, 155, 39, 166, 151, 155, 39, 167, 152, 155, 39, 168, 153, 155, 39, 169, 154, 155, 39, 170, 4, 104, 97, 115, 104, 14, 2, 71, 105, 118, 101, 110, 32, 54, 52, 32, 45, 98, 121, 116, 101, 115, 32, 105, 110, 112, 117, 116, 44, 32, 116, 104, 105, 115, 32, 114, 111, 117, 116, 105, 110, 101, 32, 99, 111, 109, 112, 117, 116, 101, 115, 32, 51, 50, 32, 45, 98, 121, 116, 101, 115, 32, 83, 65, 72, 50, 53, 54, 32, 100, 105, 103, 101, 115, 116, 10, 69, 120, 112, 101, 99, 116, 101, 100, 32, 115, 116, 97, 99, 107, 32, 115, 116, 97, 116, 101, 58, 10, 91, 109, 48, 44, 32, 109, 49, 44, 32, 109, 50, 44, 32, 109, 51, 44, 32, 109, 52, 44, 32, 109, 53, 44, 32, 109, 54, 44, 32, 109, 55, 44, 32, 109, 56, 44, 32, 109, 57, 44, 32, 109, 49, 48, 44, 32, 109, 49, 49, 44, 32, 109, 49, 50, 44, 32, 109, 49, 51, 44, 32, 109, 49, 52, 44, 32, 109, 49, 53, 93, 32, 124, 32, 109, 91, 48, 44, 49, 54, 41, 32, 61, 32, 51, 50, 32, 45, 98, 105, 116, 32, 119, 111, 114, 100, 10, 78, 111, 116, 101, 44, 32, 101, 97, 99, 104, 32, 83, 72, 65, 50, 53, 54, 32, 119, 111, 114, 100, 32, 105, 115, 32, 51, 50, 32, 45, 98, 105, 116, 32, 119, 105, 100, 101, 44, 32, 115, 111, 32, 116, 104, 97, 116, 39, 115, 32, 104, 111, 119, 32, 105, 110, 112, 117, 116, 32, 105, 115, 32, 101, 120, 112, 101, 99, 116, 101, 100, 46, 10, 73, 102, 32, 121, 111, 117, 39, 118, 101, 32, 54, 52, 32, 45, 98, 121, 116, 101, 115, 44, 32, 99, 111, 110, 115, 105, 100, 101, 114, 32, 112, 97, 99, 107, 105, 110, 103, 32, 52, 32, 99, 111, 110, 115, 101, 99, 117, 116, 105, 118, 101, 32, 98, 121, 116, 101, 115, 32, 105, 110, 116, 111, 32, 115, 105, 110, 103, 108, 101, 32, 119, 111, 114, 100, 44, 10, 109, 97, 105, 110, 116, 97, 105, 110, 105, 110, 103, 32, 98, 105, 103, 32, 101, 110, 100, 105, 97, 110, 32, 98, 121, 116, 101, 32, 111, 114, 100, 101, 114, 46, 10, 70, 105, 110, 97, 108, 32, 115, 116, 97, 99, 107, 32, 115, 116, 97, 116, 101, 58, 10, 91, 100, 105, 103, 48, 44, 32, 100, 105, 103, 49, 44, 32, 100, 105, 103, 50, 44, 32, 100, 105, 103, 51, 44, 32, 100, 105, 103, 52, 44, 32, 100, 105, 103, 53, 44, 32, 100, 105, 103, 54, 44, 32, 100, 105, 103, 55, 93, 10, 83, 72, 65, 50, 53, 54, 32, 100, 105, 103, 101, 115, 116, 32, 105, 115, 32, 114, 101, 112, 114, 101, 115, 101, 110, 116, 101, 100, 32, 105, 110, 32, 116, 101, 114, 109, 115, 32, 111, 102, 32, 101, 105, 103, 104, 116, 32, 51, 50, 32, 45, 98, 105, 116, 32, 119, 111, 114, 100, 115, 32, 40, 32, 98, 105, 103, 32, 101, 110, 100, 105, 97, 110, 32, 98, 121, 116, 101, 32, 111, 114, 100, 101, 114, 32, 41, 46, 1, 0, 0, 4, 0, 185, 4, 25, 205, 224, 91, 0, 0, 0, 0, 171, 217, 131, 31, 0, 0, 0, 0, 140, 104, 5, 155, 0, 0, 0, 0, 127, 82, 14, 81, 0, 0, 0, 0, 185, 4, 58, 245, 79, 165, 0, 0, 0, 0, 114, 243, 110, 60, 0, 0, 0, 0, 133, 174, 103, 187, 0, 0, 0, 0, 103, 230, 9, 106, 0, 0, 0, 0, 211, 9, 0, 211, 10, 0]),
("std::crypto::hashes::blake3",vm_assembly::ProcedureId([125, 62, 90, 38, 42, 214, 31, 95, 122, 216, 196, 243, 27, 252, 211, 140, 67, 212, 156, 35, 144, 101, 113, 94]),"#! Initializes four memory addresses, provided for storing initial 4x4 blake3 
#! state matrix ( i.e. 16 elements each of 32 -bit ), for computing blake3 2-to-1 hash
#!
#! Expected stack state:
#!
#! [state_0_3_addr, state_4_7_addr, state_8_11_addr, state_12_15_addr]
#!
#! Note, state_`i`_`j`_addr -> absolute address of {state[i], state[i+1], state[i+2], state[i+3]} in memory | j = i+3
#!
#! Final stack state:
#!
#! [...]
#!
#! Initialized stack state is written back to provided memory addresses.
#!
#! Functionally this routine is equivalent to https://github.com/itzmeanjan/blake3/blob/f07d32e/include/blake3.hpp#!L1709-L1713
proc.initialize
    push.0xA54FF53A.0x3C6EF372.0xBB67AE85.0x6A09E667
    movup.4
    mem_storew
    dropw

    push.0x5BE0CD19.0x1F83D9AB.0x9B05688C.0x510E527F
    movup.4
    mem_storew
    dropw

    push.0xA54FF53A.0x3C6EF372.0xBB67AE85.0x6A09E667
    movup.4
    mem_storew
    dropw

    push.11.64.0.0
    movup.4
    mem_storew
    dropw
end

#! Permutes ordered message words, kept on stack top ( = sixteen 32 -bit BLAKE3 words )
#!
#! Expected stack top: 
#!
#! [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15]
#!
#! After permutation, stack top:
#!
#! [s2, s6, s3, s10, s7, s0, s4, s13, s1, s11, s12, s5, s9, s14, s15, s8]
#!
#! See https://github.com/itzmeanjan/blake3/blob/f07d32ec10cbc8a10663b7e6539e0b1dab3e453b/include/blake3.hpp#!L1623-L1639
#! and https://github.com/maticnetwork/miden/pull/313#!discussion_r922627984
proc.permute_msg_words
    movdn.7
    movup.5
    movdn.2
    movup.4
    movdn.7
    swapw.3
    swap
    movdn.7
    swapdw
    movup.2
    movdn.7
    swapw
    swapw.2
    movup.3
    movdn.6
    movdn.5
    movup.3
    swapw
    movup.3
    swapdw
end

#! Given blake3 state matrix on stack top ( in order ) as 16 elements ( each of 32 -bit ),
#! this routine computes output chaining value i.e. 2-to-1 hashing digest.
#!
#! Expected stack state:
#!
#! [state0, state1, state2, state3, state4, state5, state6, state7, state8, state9, state10, state11, state12, state13, state14, state15]
#!
#! After finalizing, stack should look like
#!
#! [dig0, dig1, dig2, dig3, dig4, dig5, dig6, dig7]
#!
#! See https://github.com/BLAKE3-team/BLAKE3/blob/da4c792/reference_impl/reference_impl.rs#!L116-L119 ,
#! you'll notice I've skipped executing second statement in loop body of above hyperlinked implementation,
#! that's because it doesn't dictate what output of 2-to-1 hash will be.
proc.finalize
    movup.8
    u32checked_xor

    swap
    movup.8
    u32checked_xor
    swap

    movup.2
    movup.8
    u32checked_xor
    movdn.2

    movup.3
    movup.8
    u32checked_xor
    movdn.3

    movup.4
    movup.8
    u32checked_xor
    movdn.4

    movup.5
    movup.8
    u32checked_xor
    movdn.5

    movup.6
    movup.8
    u32checked_xor
    movdn.6

    movup.7
    movup.8
    u32checked_xor
    movdn.7
end

#! Given blake3 state matrix ( total 16 elements, each of 32 -bit ) and 
#! 8 message words ( each of 32 -bit ), this routine performs column-wise mixing
#! of message words into blake3 hash state.
#!
#! Functionality wise this routine is equivalent to https://github.com/BLAKE3-team/BLAKE3/blob/da4c792/reference_impl/reference_impl.rs#!L55-L59
#!
#! Expected stack state:
#!
#! [state0_3_addr, state4_7_addr, state8_11_addr, state12_15_addr, m0, m1, m2, m3, m4, m5, m6, m7]
#!
#! Note, state_`i`_`j`_addr -> absolute address of {state[i], state[i+1], state[i+2], state[i+3]} in memory | j = i+3
#!
#! Meaning four consecutive blake3 state words can be read from memory easily.
#!
#! Final stack state:
#!
#! [state0, state1, state2, state3, state4, state5, state6, state7, state8, state9, state10, state11, state12, state13, state14, state15]
#!
#! i.e. whole blake3 state is placed on stack ( in order ).
proc.columnar_mixing.1
    swapw.2
    swapw

    movup.7
    movup.6
    movup.5
    movup.4

    loc_storew.0

    movup.9
    mem_loadw
    movup.8
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.8
    dup.5
    u32overflowing_add3
    drop

    swap
    movup.8
    dup.6
    u32overflowing_add3
    drop
    swap

    movup.2
    dup.6
    movup.9
    u32overflowing_add3
    drop
    movdn.2

    movup.3
    dup.7
    movup.9
    u32overflowing_add3
    drop
    movdn.3

    movup.9
    push.0.0.0.0
    movup.4
    mem_loadw

    dup.4
    u32checked_xor
    u32unchecked_rotr.16
    
    swap
    dup.5
    u32checked_xor
    u32unchecked_rotr.16
    swap

    movup.2
    dup.6
    u32checked_xor
    u32unchecked_rotr.16
    movdn.2

    movup.3
    dup.7
    u32checked_xor
    u32unchecked_rotr.16
    movdn.3

    movup.12
    push.0.0.0.0
    movup.4
    mem_loadw

    dup.4
    u32wrapping_add

    swap
    dup.5
    u32wrapping_add
    swap

    movup.2
    dup.6
    u32wrapping_add
    movdn.2

    movup.3
    dup.7
    u32wrapping_add
    movdn.3

    movupw.3

    dup.4
    u32checked_xor
    u32unchecked_rotr.12
    
    swap
    dup.5
    u32checked_xor
    u32unchecked_rotr.12
    swap

    movup.2
    dup.6
    u32checked_xor
    u32unchecked_rotr.12
    movdn.2

    movup.3
    dup.7
    u32checked_xor
    u32unchecked_rotr.12
    movdn.3

    movupw.3
    push.0.0.0.0
    loc_loadw.0
    swapw

    movup.4
    dup.8
    u32overflowing_add3
    drop

    swap
    movup.4
    dup.8
    u32overflowing_add3
    drop
    swap

    movup.2
    movup.4
    dup.8
    u32overflowing_add3
    drop
    movdn.2

    movup.3
    movup.4
    dup.8
    u32overflowing_add3
    drop
    movdn.3

    movupw.3

    dup.4
    u32checked_xor
    u32unchecked_rotr.8
    
    swap
    dup.5
    u32checked_xor
    u32unchecked_rotr.8
    swap

    movup.2
    dup.6
    u32checked_xor
    u32unchecked_rotr.8
    movdn.2

    movup.3
    dup.7
    u32checked_xor
    u32unchecked_rotr.8
    movdn.3

    movupw.3

    dup.4
    u32wrapping_add

    swap
    dup.5
    u32wrapping_add
    swap

    movup.2
    dup.6
    u32wrapping_add
    movdn.2

    movup.3
    dup.7
    u32wrapping_add
    movdn.3

    movupw.3

    dup.4
    u32checked_xor
    u32unchecked_rotr.7

    swap
    dup.5
    u32checked_xor
    u32unchecked_rotr.7
    swap

    movup.2
    dup.6
    u32checked_xor
    u32unchecked_rotr.7
    movdn.2

    movup.3
    dup.7
    u32checked_xor
    u32unchecked_rotr.7
    movdn.3

    movupw.3
end

#! Given blake3 state matrix ( total 16 elements, each of 32 -bit ) and 
#! 8 message words ( each of 32 -bit ), this routine performs diagonal-wise mixing
#! of message words into blake3 hash state.
#!
#! Functionality wise this routine is equivalent to https://github.com/BLAKE3-team/BLAKE3/blob/da4c792/reference_impl/reference_impl.rs#!L61-L64
#!
#! Expected stack state:
#!
#! [state0_3_addr, state4_7_addr, state8_11_addr, state12_15_addr, m0, m1, m2, m3, m4, m5, m6, m7]
#!
#! Note, state_`i`_`j`_addr -> absolute address of {state[i], state[i+1], state[i+2], state[i+3]} in memory | j = i+3
#!
#! Meaning four consecutive blake3 state words can be read from memory easily.
#!
#! Final stack state:
#!
#! [state0, state1, state2, state3, state4, state5, state6, state7, state8, state9, state10, state11, state12, state13, state14, state15]
#!
#! i.e. whole blake3 state is placed on stack ( in order ).
proc.diagonal_mixing.1
    swapw.2
    swapw

    movup.7
    movup.6
    movup.5
    movup.4

    loc_storew.0

    movup.9
    mem_loadw
    movup.8
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.8
    dup.6
    u32overflowing_add3
    drop

    swap
    movup.8
    dup.7
    u32overflowing_add3
    drop
    swap

    movup.2
    movup.8
    dup.8
    u32overflowing_add3
    drop
    movdn.2

    movup.3
    movup.8
    dup.5
    u32overflowing_add3
    drop
    movdn.3

    movup.9
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.3
    dup.4
    u32checked_xor
    u32unchecked_rotr.16
    movdn.3

    dup.5
    u32checked_xor
    u32unchecked_rotr.16

    swap
    dup.6
    u32checked_xor
    u32unchecked_rotr.16
    swap

    movup.2
    dup.7
    u32checked_xor
    u32unchecked_rotr.16
    movdn.2

    movup.12
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.2
    dup.7
    u32wrapping_add
    movdn.2

    movup.3
    dup.4
    u32wrapping_add
    movdn.3

    dup.5
    u32wrapping_add

    swap
    dup.6
    u32wrapping_add
    swap

    movupw.3

    swap
    dup.6
    u32checked_xor
    u32unchecked_rotr.12
    swap

    movup.2
    dup.7
    u32checked_xor
    u32unchecked_rotr.12
    movdn.2

    movup.3
    dup.4
    u32checked_xor
    u32unchecked_rotr.12
    movdn.3

    dup.5
    u32checked_xor
    u32unchecked_rotr.12

    movupw.3
    push.0.0.0.0
    loc_loadw.0
    swapw

    movup.4
    dup.9
    u32overflowing_add3
    drop

    swap
    movup.4
    dup.9
    u32overflowing_add3
    drop
    swap

    movup.2
    movup.4
    dup.9
    u32overflowing_add3
    drop
    movdn.2

    movup.3
    movup.4
    dup.5
    u32overflowing_add3
    drop
    movdn.3

    movupw.3

    movup.3
    dup.4
    u32checked_xor
    u32unchecked_rotr.8
    movdn.3

    dup.5
    u32checked_xor
    u32unchecked_rotr.8

    swap
    dup.6
    u32checked_xor
    u32unchecked_rotr.8
    swap

    movup.2
    dup.7
    u32checked_xor
    u32unchecked_rotr.8
    movdn.2

    movupw.3

    movup.2
    dup.7
    u32wrapping_add
    movdn.2

    movup.3
    dup.4
    u32wrapping_add
    movdn.3

    dup.5
    u32wrapping_add

    swap
    dup.6
    u32wrapping_add
    swap

    movupw.3

    swap
    dup.6
    u32checked_xor
    u32unchecked_rotr.7
    swap

    movup.2
    dup.7
    u32checked_xor
    u32unchecked_rotr.7
    movdn.2

    movup.3
    dup.4
    u32checked_xor
    u32unchecked_rotr.7
    movdn.3

    dup.5
    u32checked_xor
    u32unchecked_rotr.7

    movupw.3
end

#! Given blake3 state matrix ( total 16 elements, each of 32 -bit ) and 
#! 16 message words ( each of 32 -bit ), this routine applies single round of mixing
#! of message words into hash state i.e. msg_word[0..8] are mixed into hash state using
#! columnar mixing while remaining message words ( msg_word[8..16] ) are mixed into hash state
#! using diagonal mixing.
#!
#! Functionality wise this routine is equivalent to https://github.com/BLAKE3-team/BLAKE3/blob/da4c792/reference_impl/reference_impl.rs#!L54-L65
#!
#! Expected stack state:
#!
#! [state0_3_addr, state4_7_addr, state8_11_addr, state12_15_addr, m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15]
#!
#! Note, state_`i`_`j`_addr -> absolute address of {state[i], state[i+1], state[i+2], state[i+3]} in memory | j = i+3
#!
#! Meaning four consecutive blake3 state words can be read from memory easily.
#!
#! Final stack state:
#!
#! [...]
#!
#! i.e. mixed state matrix lives in memory addresses {state0_3_addr, state4_7_addr, state8_11_addr, state12_15_addr}, 
#! which were provided, on stack top, while invoking this routine.
proc.round.5
    loc_storew.0

    exec.columnar_mixing

    loc_storew.1
    dropw
    loc_storew.2
    dropw
    loc_storew.3
    dropw
    loc_storew.4
    dropw

    locaddr.4
    locaddr.3
    locaddr.2
    locaddr.1

    exec.diagonal_mixing

    push.0.0.0.0
    loc_loadw.0
    swapw
    movup.4
    mem_storew
    dropw

    repeat.3
        push.0
        movdn.3
        swapw
        movup.4
        mem_storew
        dropw
    end

    repeat.3
        drop
    end
end

#! Given blake3 state matrix ( total 16 elements, each of 32 -bit ) and a message block
#! i.e. 16 message words ( each of 32 -bit ), this routine applies 7 rounds of mixing
#! of (permuted) message words into hash state.
#!
#! Functionality wise this routine is equivalent to https://github.com/BLAKE3-team/BLAKE3/blob/da4c792/reference_impl/reference_impl.rs#!L75-L114
#!
#! Expected stack state:
#!
#! [state0_3_addr, state4_7_addr, state8_11_addr, state12_15_addr, m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15]
#!
#! Note, state_`i`_`j`_addr -> absolute address of {state[i], state[i+1], state[i+2], state[i+3]} in memory | j = i+3
#!
#! Meaning four consecutive blake3 state words can be read from memory easily.
#!
#! Final stack state:
#!
#! [...]
#!
#! i.e. 7 -round mixed state matrix lives in memory addresses {state0_3_addr, state4_7_addr, state8_11_addr, state12_15_addr}, 
#! which were provided, on stack top, while invoking this routine. So updated state matrix can be read by caller routine, by reading
#! the content of memory addresses where state was provided as routine input.
proc.compress.1
    loc_storew.0
    dropw

    # apply first 6 rounds of mixing
    repeat.6
        # round `i` | i ∈ [1..7)
        repeat.4
            dupw.3
        end

        push.0.0.0.0
        loc_loadw.0
        exec.round
        exec.permute_msg_words
    end

    # round 7 ( last round, so no message word permutation required )
    push.0.0.0.0
    loc_loadw.0
    exec.round
end

#! Blake3 2-to-1 hash function, which takes 64 -bytes input and produces 32 -bytes output digest
#!
#! Expected stack state:
#!
#! [msg0, msg1, msg2, msg3, msg4, msg5, msg6, msg7, msg8, msg9, msg10, msg11, msg12, msg13, msg14, msg15]
#!
#! msg`i` -> 32 -bit message word | i ∈ [0, 16)
#!
#! Output stack state:
#!
#! [dig0, dig1, dig2, dig3, dig4, dig5, dig6, dig7]
#!
#! dig`i` -> 32 -bit digest word | i ∈ [0, 8)
export.hash.4
    locaddr.3
    locaddr.2
    locaddr.1
    locaddr.0

    exec.initialize

    # Note, chunk compression routine needs to compress only one chunk with one message 
    # block ( = 64 -bytes ) because what we're doing here is 2-to-1 hashing i.e. 64 -bytes 
    # input being converted to 32 -bytes output

    locaddr.3
    locaddr.2
    locaddr.1
    locaddr.0

    exec.compress

    push.0.0.0.0
    loc_loadw.3
    push.0.0.0.0
    loc_loadw.2
    push.0.0.0.0
    loc_loadw.1
    push.0.0.0.0
    loc_loadw.0

    exec.finalize
end
",&[8, 0, 10, 105, 110, 105, 116, 105, 97, 108, 105, 122, 101, 0, 0, 0, 0, 0, 16, 0, 185, 4, 58, 245, 79, 165, 0, 0, 0, 0, 114, 243, 110, 60, 0, 0, 0, 0, 133, 174, 103, 187, 0, 0, 0, 0, 103, 230, 9, 106, 0, 0, 0, 0, 151, 198, 108, 185, 4, 25, 205, 224, 91, 0, 0, 0, 0, 171, 217, 131, 31, 0, 0, 0, 0, 140, 104, 5, 155, 0, 0, 0, 0, 127, 82, 14, 81, 0, 0, 0, 0, 151, 198, 108, 185, 4, 58, 245, 79, 165, 0, 0, 0, 0, 114, 243, 110, 60, 0, 0, 0, 0, 133, 174, 103, 187, 0, 0, 0, 0, 103, 230, 9, 106, 0, 0, 0, 0, 151, 198, 108, 185, 4, 11, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 198, 108, 17, 112, 101, 114, 109, 117, 116, 101, 95, 109, 115, 103, 95, 119, 111, 114, 100, 115, 0, 0, 0, 0, 0, 20, 0, 170, 152, 165, 151, 170, 147, 130, 170, 148, 149, 170, 145, 146, 150, 169, 168, 150, 145, 150, 148, 8, 102, 105, 110, 97, 108, 105, 122, 101, 0, 0, 0, 0, 0, 30, 0, 155, 73, 130, 155, 73, 130, 149, 155, 73, 165, 150, 155, 73, 166, 151, 155, 73, 167, 152, 155, 73, 168, 153, 155, 73, 169, 154, 155, 73, 170, 15, 99, 111, 108, 117, 109, 110, 97, 114, 95, 109, 105, 120, 105, 110, 103, 0, 0, 0, 1, 0, 174, 0, 146, 145, 154, 153, 152, 151, 200, 0, 0, 0, 0, 0, 0, 0, 0, 156, 191, 155, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 155, 115, 43, 107, 130, 155, 116, 43, 107, 130, 149, 116, 156, 43, 107, 165, 150, 117, 156, 43, 107, 166, 156, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 114, 73, 86, 16, 130, 115, 73, 86, 16, 130, 149, 116, 73, 86, 16, 165, 150, 117, 73, 86, 16, 166, 159, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 114, 39, 130, 115, 39, 130, 149, 116, 39, 165, 150, 117, 39, 166, 164, 114, 73, 86, 12, 130, 115, 73, 86, 12, 130, 149, 116, 73, 86, 12, 165, 150, 117, 73, 86, 12, 166, 164, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 0, 0, 0, 0, 0, 0, 0, 0, 145, 151, 118, 43, 107, 130, 151, 118, 43, 107, 130, 149, 151, 118, 43, 107, 165, 150, 151, 118, 43, 107, 166, 164, 114, 73, 86, 8, 130, 115, 73, 86, 8, 130, 149, 116, 73, 86, 8, 165, 150, 117, 73, 86, 8, 166, 164, 114, 39, 130, 115, 39, 130, 149, 116, 39, 165, 150, 117, 39, 166, 164, 114, 73, 86, 7, 130, 115, 73, 86, 7, 130, 149, 116, 73, 86, 7, 165, 150, 117, 73, 86, 7, 166, 164, 15, 100, 105, 97, 103, 111, 110, 97, 108, 95, 109, 105, 120, 105, 110, 103, 0, 0, 0, 1, 0, 174, 0, 146, 145, 154, 153, 152, 151, 200, 0, 0, 0, 0, 0, 0, 0, 0, 156, 191, 155, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 155, 116, 43, 107, 130, 155, 117, 43, 107, 130, 149, 155, 118, 43, 107, 165, 150, 155, 115, 43, 107, 166, 156, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 150, 114, 73, 86, 16, 166, 115, 73, 86, 16, 130, 116, 73, 86, 16, 130, 149, 117, 73, 86, 16, 165, 159, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 149, 117, 39, 165, 150, 114, 39, 166, 115, 39, 130, 116, 39, 130, 164, 130, 116, 73, 86, 12, 130, 149, 117, 73, 86, 12, 165, 150, 114, 73, 86, 12, 166, 115, 73, 86, 12, 164, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 0, 0, 0, 0, 0, 0, 0, 0, 145, 151, 119, 43, 107, 130, 151, 119, 43, 107, 130, 149, 151, 119, 43, 107, 165, 150, 151, 115, 43, 107, 166, 164, 150, 114, 73, 86, 8, 166, 115, 73, 86, 8, 130, 116, 73, 86, 8, 130, 149, 117, 73, 86, 8, 165, 164, 149, 117, 39, 165, 150, 114, 39, 166, 115, 39, 130, 116, 39, 130, 164, 130, 116, 73, 86, 7, 130, 149, 117, 73, 86, 7, 165, 150, 114, 73, 86, 7, 166, 115, 73, 86, 7, 164, 5, 114, 111, 117, 110, 100, 0, 0, 0, 5, 0, 23, 0, 200, 0, 0, 0, 0, 0, 0, 0, 0, 211, 3, 0, 200, 1, 0, 0, 0, 0, 0, 0, 0, 108, 200, 2, 0, 0, 0, 0, 0, 0, 0, 108, 200, 3, 0, 0, 0, 0, 0, 0, 0, 108, 200, 4, 0, 0, 0, 0, 0, 0, 0, 108, 186, 4, 0, 0, 0, 0, 0, 0, 0, 186, 3, 0, 0, 0, 0, 0, 0, 0, 186, 2, 0, 0, 0, 0, 0, 0, 0, 186, 1, 0, 0, 0, 0, 0, 0, 0, 211, 4, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 0, 0, 0, 0, 0, 0, 0, 0, 145, 151, 198, 108, 254, 190, 1, 6, 0, 185, 1, 0, 0, 0, 0, 0, 0, 0, 0, 166, 145, 151, 198, 108, 254, 198, 1, 1, 0, 107, 8, 99, 111, 109, 112, 114, 101, 115, 115, 0, 0, 0, 1, 0, 6, 0, 200, 0, 0, 0, 0, 0, 0, 0, 0, 108, 254, 205, 1, 5, 0, 254, 206, 1, 1, 0, 129, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 0, 0, 0, 0, 0, 0, 0, 0, 211, 5, 0, 211, 1, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 0, 0, 0, 0, 0, 0, 0, 0, 211, 5, 0, 4, 104, 97, 115, 104, 123, 1, 66, 108, 97, 107, 101, 51, 32, 50, 45, 116, 111, 45, 49, 32, 104, 97, 115, 104, 32, 102, 117, 110, 99, 116, 105, 111, 110, 44, 32, 119, 104, 105, 99, 104, 32, 116, 97, 107, 101, 115, 32, 54, 52, 32, 45, 98, 121, 116, 101, 115, 32, 105, 110, 112, 117, 116, 32, 97, 110, 100, 32, 112, 114, 111, 100, 117, 99, 101, 115, 32, 51, 50, 32, 45, 98, 121, 116, 101, 115, 32, 111, 117, 116, 112, 117, 116, 32, 100, 105, 103, 101, 115, 116, 10, 69, 120, 112, 101, 99, 116, 101, 100, 32, 115, 116, 97, 99, 107, 32, 115, 116, 97, 116, 101, 58, 10, 91, 109, 115, 103, 48, 44, 32, 109, 115, 103, 49, 44, 32, 109, 115, 103, 50, 44, 32, 109, 115, 103, 51, 44, 32, 109, 115, 103, 52, 44, 32, 109, 115, 103, 53, 44, 32, 109, 115, 103, 54, 44, 32, 109, 115, 103, 55, 44, 32, 109, 115, 103, 56, 44, 32, 109, 115, 103, 57, 44, 32, 109, 115, 103, 49, 48, 44, 32, 109, 115, 103, 49, 49, 44, 32, 109, 115, 103, 49, 50, 44, 32, 109, 115, 103, 49, 51, 44, 32, 109, 115, 103, 49, 52, 44, 32, 109, 115, 103, 49, 53, 93, 10, 109, 115, 103, 96, 105, 96, 32, 45, 62, 32, 51, 50, 32, 45, 98, 105, 116, 32, 109, 101, 115, 115, 97, 103, 101, 32, 119, 111, 114, 100, 32, 124, 32, 105, 32, 226, 136, 136, 32, 91, 48, 44, 32, 49, 54, 41, 10, 79, 117, 116, 112, 117, 116, 32, 115, 116, 97, 99, 107, 32, 115, 116, 97, 116, 101, 58, 10, 91, 100, 105, 103, 48, 44, 32, 100, 105, 103, 49, 44, 32, 100, 105, 103, 50, 44, 32, 100, 105, 103, 51, 44, 32, 100, 105, 103, 52, 44, 32, 100, 105, 103, 53, 44, 32, 100, 105, 103, 54, 44, 32, 100, 105, 103, 55, 93, 10, 100, 105, 103, 96, 105, 96, 32, 45, 62, 32, 51, 50, 32, 45, 98, 105, 116, 32, 100, 105, 103, 101, 115, 116, 32, 119, 111, 114, 100, 32, 124, 32, 105, 32, 226, 136, 136, 32, 91, 48, 44, 32, 56, 41, 1, 4, 0, 19, 0, 186, 3, 0, 0, 0, 0, 0, 0, 0, 186, 2, 0, 0, 0, 0, 0, 0, 0, 186, 1, 0, 0, 0, 0, 0, 0, 0, 186, 0, 0, 0, 0, 0, 0, 0, 0, 211, 0, 0, 186, 3, 0, 0, 0, 0, 0, 0, 0, 186, 2, 0, 0, 0, 0, 0, 0, 0, 186, 1, 0, 0, 0, 0, 0, 0, 0, 186, 0, 0, 0, 0, 0, 0, 0, 0, 211, 6, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 3, 0, 0, 0, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 2, 0, 0, 0, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 1, 0, 0, 0, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 0, 0, 0, 0, 0, 0, 0, 0, 211, 2, 0]),
("std::crypto::hashes::keccak256",vm_assembly::ProcedureId([202, 157, 243, 12, 53, 127, 247, 159, 253, 64, 111, 145, 36, 163, 43, 222, 73, 148, 214, 86, 121, 230, 153, 70]),"#! Keccak-p[1600, 24] permutation's θ step mapping function, which is implemented 
#! in terms of 32 -bit word size ( bit interleaved representation )
#!
#! See https://github.com/itzmeanjan/merklize-sha/blob/1d35aae9da7fed20127489f362b4bc93242a516c/include/sha3.hpp#L55-L98 for original implementation
#!
#! Expected stack state :
#!
#! [state_addr, ...]
#!
#! Final stack state :
#!
#! [ ... ]
#!
#! Whole keccak-p[1600, 24] state can be represented using fifty u32 elements i.e. 13 absolute memory addresses
#! s.t. last two elements of 12 -th ( when indexed from zero ) memory address are zeroed.
#!
#! Consecutive memory addresses can be computed by repeated application of `add.1`.
proc.theta.3
    dup
    locaddr.0
    mem_store
    drop

    # compute (S[0] ^ S[10] ^ S[20] ^ S[30] ^ S[40], S[1] ^ S[11] ^ S[21] ^ S[31] ^ S[41])

    # bring S[0], S[1]
    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.2
    drop
    movup.2
    drop

    movup.2
    add.2

    # bring S[10], S[11]
    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    drop
    drop

    movup.3
    u32checked_xor

    swap

    movup.3
    u32checked_xor

    swap

    movup.2
    add.3

    # bring S[20], S[21]
    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.2
    drop
    movup.2
    drop

    movup.3
    u32checked_xor

    swap

    movup.3
    u32checked_xor

    swap

    movup.2
    add.2

    # bring S[30], S[31]
    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    drop
    drop

    movup.3
    u32checked_xor

    swap

    movup.3
    u32checked_xor

    swap

    movup.2
    add.3

    # bring S[40], S[41]
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.2
    drop
    movup.2
    drop

    movup.2
    u32checked_xor

    swap

    movup.2
    u32checked_xor

    swap

    # stack = [c0, c1]
    # compute (S[2] ^ S[12] ^ S[22] ^ S[32] ^ S[42], S[3] ^ S[13] ^ S[23] ^ S[33] ^ S[43])

    locaddr.0
    mem_load
    
    # bring S[2], S[3]
    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    drop
    drop

    movup.2
    add.3

    # bring S[12], S[13]
    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.2
    drop
    movup.2
    drop

    movup.3
    u32checked_xor

    swap

    movup.3
    u32checked_xor

    swap

    movup.2
    add.2

    # bring S[22], S[23]
    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    drop
    drop

    movup.3
    u32checked_xor

    swap

    movup.3
    u32checked_xor

    swap

    movup.2
    add.3

    # bring S[32], S[33]
    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.2
    drop
    movup.2
    drop

    movup.3
    u32checked_xor

    swap

    movup.3
    u32checked_xor

    swap

    movup.2
    add.2

    # bring S[42], S[43]
    push.0.0.0.0
    movup.4
    mem_loadw

    drop
    drop

    movup.2
    u32checked_xor

    swap

    movup.2
    u32checked_xor

    swap

    movup.3
    movup.3

    # stack = [c0, c1, c2, c3]

    locaddr.1
    mem_storew
    dropw

    # compute (S[4] ^ S[14] ^ S[24] ^ S[34] ^ S[44], S[5] ^ S[15] ^ S[25] ^ S[35] ^ S[45])

    locaddr.0
    mem_load
    add.1

    # bring S[4], S[5]
    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.2
    drop
    movup.2
    drop

    movup.2
    add.2

    # bring S[14], S[15]
    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    drop
    drop

    movup.3
    u32checked_xor

    swap

    movup.3
    u32checked_xor

    swap

    movup.2
    add.3

    # bring S[24], S[25]
    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.2
    drop
    movup.2
    drop

    movup.3
    u32checked_xor

    swap

    movup.3
    u32checked_xor

    swap

    movup.2
    add.2

    # bring S[34], S[35]
    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    drop
    drop

    movup.3
    u32checked_xor

    swap

    movup.3
    u32checked_xor

    swap

    movup.2
    add.3

    # bring S[44], S[45]
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.2
    drop
    movup.2
    drop

    movup.2
    u32checked_xor

    swap

    movup.2
    u32checked_xor

    swap

    # stack = [c4, c5]
    # compute (S[6] ^ S[16] ^ S[26] ^ S[36] ^ S[46], S[7] ^ S[17] ^ S[27] ^ S[37] ^ S[47])

    locaddr.0
    mem_load
    add.1
    
    # bring S[6], S[7]
    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    drop
    drop

    movup.2
    add.3

    # bring S[16], S[17]
    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.2
    drop
    movup.2
    drop

    movup.3
    u32checked_xor

    swap

    movup.3
    u32checked_xor

    swap

    movup.2
    add.2

    # bring S[26], S[27]
    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    drop
    drop

    movup.3
    u32checked_xor

    swap

    movup.3
    u32checked_xor

    swap

    movup.2
    add.3

    # bring S[36], S[37]
    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.2
    drop
    movup.2
    drop

    movup.3
    u32checked_xor

    swap

    movup.3
    u32checked_xor

    swap

    movup.2
    add.2

    # bring S[46], S[47]
    push.0.0.0.0
    movup.4
    mem_loadw

    drop
    drop

    movup.2
    u32checked_xor

    swap

    movup.2
    u32checked_xor

    swap

    movup.3
    movup.3

    # stack = [c4, c5, c6, c7]

    locaddr.2
    mem_storew
    dropw

    # compute (S[8] ^ S[18] ^ S[28] ^ S[38] ^ S[48], S[9] ^ S[19] ^ S[29] ^ S[39] ^ S[49])

    locaddr.0
    mem_load
    add.2

    # bring S[8], S[9]
    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.2
    drop
    movup.2
    drop

    movup.2
    add.2

    # bring S[18], S[19]
    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    drop
    drop

    movup.3
    u32checked_xor

    swap

    movup.3
    u32checked_xor

    swap

    movup.2
    add.3

    # bring S[28], S[29]
    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.2
    drop
    movup.2
    drop

    movup.3
    u32checked_xor

    swap

    movup.3
    u32checked_xor

    swap

    movup.2
    add.2

    # bring S[38], S[39]
    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    drop
    drop

    movup.3
    u32checked_xor

    swap

    movup.3
    u32checked_xor

    swap

    movup.2
    add.3

    # bring S[48], S[49]
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.2
    drop
    movup.2
    drop

    movup.2
    u32checked_xor

    swap

    movup.2
    u32checked_xor

    swap

    # stack = [c8, c9]

    locaddr.2
    push.0.0.0.0
    movup.4
    mem_loadw
    locaddr.1
    push.0.0.0.0
    movup.4
    mem_loadw

    # stack = [c0, c1, c2, c3, c4, c5, c6, c7, c8, c9]

    dup.8
    dup.4
    u32unchecked_rotl.1
    u32checked_xor

    dup.10
    dup.4
    u32checked_xor

    dup.2
    dup.8
    u32unchecked_rotl.1
    u32checked_xor

    dup.4
    dup.8
    u32checked_xor

    movup.6
    dup.11
    u32unchecked_rotl.1
    u32checked_xor

    movup.7
    dup.10
    u32checked_xor

    movup.8
    movup.13
    u32unchecked_rotl.1
    u32checked_xor

    movup.9
    movup.12
    u32checked_xor

    movup.10
    movup.10
    u32unchecked_rotl.1
    u32checked_xor

    movup.10
    movup.10
    u32checked_xor

    # stack = [d9, d8, d7, d6, d5, d4, d3, d2, d1, d0]

    swap
    movup.2
    movup.3
    movup.4
    movup.5
    movup.6
    movup.7
    movup.8
    movup.9

    # stack = [d0, d1, d2, d3, d4, d5, d6, d7, d8, d9]

    locaddr.0
    mem_load

    # compute state[0..4)

    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    dup.5
    u32checked_xor

    swap
    dup.6
    u32checked_xor
    swap

    movup.2
    dup.7
    u32checked_xor
    movdn.2

    movup.3
    dup.8
    u32checked_xor
    movdn.3

    dup.4
    mem_storew
    dropw

    add.1

    # compute state[4..8)

    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    dup.9
    u32checked_xor

    swap
    dup.10
    u32checked_xor
    swap

    movup.2
    dup.11
    u32checked_xor
    movdn.2

    movup.3
    dup.12
    u32checked_xor
    movdn.3

    dup.4
    mem_storew
    dropw

    add.1

    # compute state[8..12)

    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    dup.13
    u32checked_xor

    swap
    dup.14
    u32checked_xor
    swap

    movup.2
    dup.5
    u32checked_xor
    movdn.2

    movup.3
    dup.6
    u32checked_xor
    movdn.3

    dup.4
    mem_storew
    dropw

    add.1

    # compute state[12..16)

    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    dup.7
    u32checked_xor

    swap
    dup.8
    u32checked_xor
    swap

    movup.2
    dup.9
    u32checked_xor
    movdn.2

    movup.3
    dup.10
    u32checked_xor
    movdn.3

    dup.4
    mem_storew
    dropw

    add.1

    # compute state[16..20)

    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    dup.11
    u32checked_xor

    swap
    dup.12
    u32checked_xor
    swap

    movup.2
    dup.13
    u32checked_xor
    movdn.2

    movup.3
    dup.14
    u32checked_xor
    movdn.3

    dup.4
    mem_storew
    dropw

    add.1

    # compute state[20..24)

    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    dup.5
    u32checked_xor

    swap
    dup.6
    u32checked_xor
    swap

    movup.2
    dup.7
    u32checked_xor
    movdn.2

    movup.3
    dup.8
    u32checked_xor
    movdn.3

    dup.4
    mem_storew
    dropw

    add.1

    # compute state[24..28)

    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    dup.9
    u32checked_xor

    swap
    dup.10
    u32checked_xor
    swap

    movup.2
    dup.11
    u32checked_xor
    movdn.2

    movup.3
    dup.12
    u32checked_xor
    movdn.3

    dup.4
    mem_storew
    dropw

    add.1

    # compute state[28..32)

    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    dup.13
    u32checked_xor

    swap
    dup.14
    u32checked_xor
    swap

    movup.2
    dup.5
    u32checked_xor
    movdn.2

    movup.3
    dup.6
    u32checked_xor
    movdn.3

    dup.4
    mem_storew
    dropw

    add.1

    # compute state[32..36)

    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    dup.7
    u32checked_xor

    swap
    dup.8
    u32checked_xor
    swap

    movup.2
    dup.9
    u32checked_xor
    movdn.2

    movup.3
    dup.10
    u32checked_xor
    movdn.3

    dup.4
    mem_storew
    dropw

    add.1

    # compute state[36..40)

    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    dup.11
    u32checked_xor

    swap
    dup.12
    u32checked_xor
    swap

    movup.2
    dup.13
    u32checked_xor
    movdn.2

    movup.3
    dup.14
    u32checked_xor
    movdn.3

    dup.4
    mem_storew
    dropw

    add.1

    # compute state[40..44)

    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.5
    u32checked_xor

    swap
    movup.5
    u32checked_xor
    swap

    movup.2
    movup.5
    u32checked_xor
    movdn.2

    movup.3
    movup.5
    u32checked_xor
    movdn.3

    dup.4
    mem_storew
    dropw

    add.1

    # compute state[44..48)

    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.5
    u32checked_xor

    swap
    movup.5
    u32checked_xor
    swap

    movup.2
    movup.5
    u32checked_xor
    movdn.2

    movup.3
    movup.5
    u32checked_xor
    movdn.3

    dup.4
    mem_storew
    dropw

    add.1

    # compute state[48..50)

    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.5
    u32checked_xor

    swap
    movup.5
    u32checked_xor
    swap

    movup.4
    mem_storew
    dropw
end

#! Keccak-p[1600, 24] permutation's ρ step mapping function, which is implemented 
#! in terms of 32 -bit word size ( bit interleaved representation )
#!
#! See https://github.com/itzmeanjan/merklize-sha/blob/1d35aae9da7fed20127489f362b4bc93242a516c/include/sha3.hpp#L115-L147 for original implementation
#!
#! Expected stack state :
#!
#! [state_addr, ...]
#!
#! Final stack state :
#!
#! [ ... ]
#!
#! Whole keccak-p[1600, 24] state can be represented using fifty u32 elements i.e. 13 absolute memory addresses
#! s.t. last two elements of 12 -th ( when indexed from zero ) memory address are zeroed.
#!
#! Consecutive memory addresses can be computed by repeated application of `add.1`.
proc.rho.1
    dup
    locaddr.0
    mem_store
    drop

    # rotate state[0..4)
    push.0.0.0.0
    dup.4
    mem_loadw

    movup.3
    u32unchecked_rotl.1
    movdn.2

    movup.4
    dup
    add.1
    movdn.5
    mem_storew

    # rotate state[4..8)
    dup.4
    mem_loadw

    u32unchecked_rotl.31
    swap
    u32unchecked_rotl.31
    swap

    movup.2
    u32unchecked_rotl.14
    movdn.2
    movup.3
    u32unchecked_rotl.14
    movdn.3

    movup.4
    dup
    add.1
    movdn.5
    mem_storew

    # rotate state[8..12)
    dup.4
    mem_loadw

    u32unchecked_rotl.13
    swap
    u32unchecked_rotl.14

    movup.2
    u32unchecked_rotl.18
    movdn.2
    movup.3
    u32unchecked_rotl.18
    movdn.3

    movup.4
    dup
    add.1
    movdn.5
    mem_storew

    # rotate state[12..16)
    dup.4
    mem_loadw

    u32unchecked_rotl.22
    swap
    u32unchecked_rotl.22
    swap

    movup.2
    u32unchecked_rotl.3
    movdn.2
    movup.3
    u32unchecked_rotl.3
    movdn.3

    movup.4
    dup
    add.1
    movdn.5
    mem_storew

    # rotate state[16..20)
    dup.4
    mem_loadw

    u32unchecked_rotl.27
    swap
    u32unchecked_rotl.28

    movup.2
    u32unchecked_rotl.10
    movdn.2
    movup.3
    u32unchecked_rotl.10
    movdn.3

    movup.4
    dup
    add.1
    movdn.5
    mem_storew

    # rotate state[20..24)
    dup.4
    mem_loadw

    u32unchecked_rotl.1
    swap
    u32unchecked_rotl.2

    movup.2
    u32unchecked_rotl.5
    movdn.2
    movup.3
    u32unchecked_rotl.5
    movdn.3

    movup.4
    dup
    add.1
    movdn.5
    mem_storew

    # rotate state[24..28)
    dup.4
    mem_loadw

    u32unchecked_rotl.21
    swap
    u32unchecked_rotl.22

    movup.2
    u32unchecked_rotl.12
    movdn.3
    movup.2
    u32unchecked_rotl.13
    movdn.2

    movup.4
    dup
    add.1
    movdn.5
    mem_storew

    # rotate state[28..32)
    dup.4
    mem_loadw

    u32unchecked_rotl.19
    swap
    u32unchecked_rotl.20

    movup.2
    u32unchecked_rotl.20
    movdn.3
    movup.2
    u32unchecked_rotl.21
    movdn.2

    movup.4
    dup
    add.1
    movdn.5
    mem_storew
     
    # rotate state[32..36)
    dup.4
    mem_loadw

    u32unchecked_rotl.22
    swap
    u32unchecked_rotl.23

    movup.2
    u32unchecked_rotl.7
    movdn.3
    movup.2
    u32unchecked_rotl.8
    movdn.2

    movup.4
    dup
    add.1
    movdn.5
    mem_storew

    # rotate state[36..40)
    dup.4
    mem_loadw

    u32unchecked_rotl.10
    swap
    u32unchecked_rotl.11

    movup.2
    u32unchecked_rotl.4
    movdn.2
    movup.3
    u32unchecked_rotl.4
    movdn.3

    movup.4
    dup
    add.1
    movdn.5
    mem_storew

    # rotate state[40..44)
    dup.4
    mem_loadw
    
    u32unchecked_rotl.9
    swap
    u32unchecked_rotl.9
    swap

    movup.2
    u32unchecked_rotl.1
    movdn.2
    movup.3
    u32unchecked_rotl.1
    movdn.3

    movup.4
    dup
    add.1
    movdn.5
    mem_storew

    # rotate state[44..48)
    dup.4
    mem_loadw

    u32unchecked_rotl.30
    swap
    u32unchecked_rotl.31

    movup.2
    u32unchecked_rotl.28
    movdn.2
    movup.3
    u32unchecked_rotl.28
    movdn.3

    movup.4
    dup
    add.1
    movdn.5
    mem_storew

    # rotate state[48..50)
    dup.4
    mem_loadw

    u32unchecked_rotl.7
    swap
    u32unchecked_rotl.7
    swap

    movup.4
    mem_storew
    dropw
end

#! Keccak-p[1600, 24] permutation's π step mapping function, which is implemented 
#! in terms of 32 -bit word size ( bit interleaved representation )
#!
#! See https://github.com/itzmeanjan/merklize-sha/blob/1d35aae9da7fed20127489f362b4bc93242a516c/include/sha3.hpp#L169-L207 for original implementation
#!
#! Expected stack state :
#!
#! [state_addr, ...]
#!
#! Final stack state :
#!
#! [ ... ]
#!
#! Whole keccak-p[1600, 24] state can be represented using fifty u32 elements i.e. 13 absolute memory addresses
#! s.t. last two elements of 12 -th ( when indexed from zero ) memory address are zeroed.
#!
#! Consecutive memory addresses can be computed by repeated application of `add.1`.
proc.pi.14
    dup
    locaddr.0
    mem_store
    drop

    locaddr.1
    swap
    push.0.0.0.0

    # place state[0..4) to desired location(s)
    dup.4
    mem_loadw

    push.0.0
    movdn.3
    movdn.3

    dup.7
    mem_storew

    drop
    drop
    movdn.3
    movdn.3

    dup.5
    add.5
    mem_storew

    # place state[4..8) to desired location(s)
    movup.4
    add.1
    movdn.4

    dup.4
    mem_loadw

    push.0.0
    movdn.3
    movdn.3

    dup.7
    add.10
    mem_storew

    drop
    drop

    dup.5
    add.2
    mem_storew

    # place state[8..12) to desired location(s)
    movup.4
    add.1
    movdn.4

    dup.4
    mem_loadw

    push.0.0

    dup.7
    add.7
    mem_storew

    movup.2
    drop
    movup.2
    drop

    movdn.3
    movdn.3

    dup.5
    add.8
    mem_storew

    # place state[12..16) to desired location(s)
    movup.4
    add.1
    movdn.4

    dup.4
    mem_loadw

    dup.5
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.2
    drop
    movup.2
    drop

    dup.7
    mem_storew

    dup.7
    add.5
    mem_loadw

    movup.2
    drop
    movup.2
    drop

    dup.5
    add.5
    mem_storew

    # place state[16..20) to desired location(s)
    movup.4
    add.1
    movdn.4

    dup.4
    mem_loadw

    dup.5
    add.10
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.2
    drop
    movup.2
    drop

    dup.7
    add.10
    mem_storew

    dropw

    push.0.0
    movdn.3
    movdn.3

    dup.5
    add.3
    mem_storew

    # place state[20..24) to desired location(s)
    movup.4
    add.1
    movdn.4

    dup.4
    mem_loadw

    dup.5
    add.3
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.2
    drop
    movup.2
    drop

    dup.7
    add.3
    mem_storew

    dup.7
    add.8
    mem_loadw

    movup.2
    drop
    movup.2
    drop

    dup.5
    add.8
    mem_storew

    # place state[24..28) to desired location(s)
    movup.4
    add.1
    movdn.4

    dup.4
    mem_loadw

    push.0.0
    movdn.3
    movdn.3

    dup.7
    add.1
    mem_storew

    drop
    drop
    movdn.3
    movdn.3

    dup.5
    add.6
    mem_storew

    # place state[28..32) to desired location(s)
    movup.4
    add.1
    movdn.4

    dup.4
    mem_loadw

    dup.5
    add.11
    mem_storew

    # place state[32..36) to desired location(s)
    movup.4
    add.1
    movdn.4

    dup.4
    mem_loadw

    push.0.0
    movdn.3
    movdn.3

    dup.7
    add.4
    mem_storew

    drop
    drop
    movdn.3
    movdn.3

    dup.5
    add.9
    mem_storew

    # place state[36..40) to desired location(s)
    movup.4
    add.1
    movdn.4

    dup.4
    mem_loadw

    dup.5
    add.1
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.2
    drop
    movup.2
    drop

    dup.7
    add.1
    mem_storew

    dup.7
    add.6
    mem_loadw

    movup.2
    drop
    movup.2
    drop

    dup.5
    add.6
    mem_storew

    # place state[40..44) to desired location(s)
    movup.4
    add.1
    movdn.4

    dup.4
    mem_loadw

    dup.5
    add.7
    push.0.0.0.0
    movup.4
    mem_loadw

    drop
    drop
    movup.3
    movup.3

    dup.7
    add.7
    mem_storew

    dropw

    push.0.0
    movdn.3
    movdn.3

    dup.5
    add.12
    mem_storew

    # place state[44..48) to desired location(s)
    movup.4
    add.1
    movdn.4

    dup.4
    mem_loadw

    dup.5
    add.4
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.2
    drop
    movup.2
    drop

    dup.7
    add.4
    mem_storew

    dup.7
    add.9
    mem_loadw

    movup.2
    drop
    movup.2
    drop

    dup.5
    add.9
    mem_storew

    # place state[48..50) to desired location(s)
    movup.4
    add.1
    movdn.4

    dup.4
    mem_loadw

    dup.5
    add.2
    push.0.0.0.0
    movup.4
    mem_loadw

    drop
    drop
    movdn.3
    movdn.3

    dup.7
    add.2
    mem_storew

    drop
    drop

    # memcpy
    movup.4
    drop
    locaddr.0
    mem_load
    movdn.4

    repeat.13
        dup.5
        mem_loadw

        dup.4
        mem_storew

        movup.4
        add.1
        movdn.4

        movup.5
        add.1
        movdn.5
    end

    dropw
    drop
    drop
end

#! Keccak-p[1600, 24] permutation's χ step mapping function, which is implemented 
#! in terms of 32 -bit word size ( bit interleaved representation )
#!
#! See https://github.com/itzmeanjan/merklize-sha/blob/1d35aae9da7fed20127489f362b4bc93242a516c/include/sha3.hpp#L233-L271 for original implementation
#!
#! Expected stack state :
#!
#! [state_addr, ...]
#!
#! Final stack state :
#!
#! [ ... ]
#!
#! Whole keccak-p[1600, 24] state can be represented using fifty u32 elements i.e. 13 absolute memory addresses
#! s.t. last two elements of 12 -th ( when indexed from zero ) memory address are zeroed.
#!
#! Consecutive memory addresses can be computed by repeated application of `add.1`.
proc.chi.4
    dup
    locaddr.0
    mem_store
    drop

    # process state[0..10)
    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    drop
    drop

    u32checked_not
    swap
    u32checked_not
    swap

    movup.2
    add.1
    dup
    movdn.3

    push.0.0.0.0
    movup.4
    mem_loadw

    dup.1
    dup.1

    movup.6
    u32checked_and

    swap

    movup.6
    u32checked_and

    swap

    movup.3
    u32checked_not
    movup.3
    u32checked_not

    movup.4
    u32checked_and
    swap
    movup.4
    u32checked_and
    swap

    movup.3
    movup.3

    locaddr.1
    mem_storew

    dup.4
    mem_loadw

    drop
    drop

    u32checked_not
    swap
    u32checked_not
    swap

    movup.2
    add.1
    dup
    movdn.3

    push.0.0.0.0
    movup.4
    mem_loadw

    movup.2
    drop
    movup.2
    drop

    dup.1
    dup.1

    movup.4
    u32checked_and
    swap
    movup.4
    u32checked_and
    swap

    movup.3
    movup.3

    movup.4
    sub.2
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.5
    u32checked_not
    movup.5
    u32checked_not

    dup.2
    u32checked_and
    swap
    dup.3
    u32checked_and
    swap

    movup.7
    movup.7

    locaddr.2
    mem_storew
    dropw

    u32checked_not
    swap
    u32checked_not
    swap

    movup.2
    u32checked_and
    swap
    movup.2
    u32checked_and
    swap

    locaddr.0
    mem_load

    push.0.0.0.0

    dup.4
    mem_loadw

    locaddr.1
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.4
    u32checked_xor

    swap
    movup.4
    u32checked_xor
    swap

    movup.2
    movup.4
    u32checked_xor
    movdn.2

    movup.3
    movup.4
    u32checked_xor
    movdn.3

    dup.4
    mem_storew

    movup.4
    add.1
    movdn.4

    dup.4
    mem_loadw

    locaddr.2
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.4
    u32checked_xor

    swap
    movup.4
    u32checked_xor
    swap

    movup.2
    movup.4
    u32checked_xor
    movdn.2

    movup.3
    movup.4
    u32checked_xor
    movdn.3

    dup.4
    mem_storew

    movup.4
    add.1
    movdn.4

    dup.4
    mem_loadw

    movup.5
    u32checked_xor
    swap
    movup.5
    u32checked_xor
    swap

    dup.4
    mem_storew

    # process state[10..20)
    movup.4
    add.1
    movdn.4

    dup.4
    mem_loadw

    u32checked_not
    swap
    u32checked_not
    swap

    dup.3
    dup.3

    movup.2
    u32checked_and
    swap
    movup.2
    u32checked_and
    swap

    push.0.0
    locaddr.1
    mem_storew

    movup.6
    add.1
    dup
    movdn.7

    mem_loadw

    movup.5
    movup.5

    u32checked_not
    swap
    u32checked_not
    swap

    dup.2
    u32checked_and
    swap
    dup.3
    u32checked_and
    swap

    movup.3
    movup.3

    u32checked_not
    swap
    u32checked_not
    swap

    dup.4
    u32checked_and
    swap
    dup.5
    u32checked_and
    swap

    movup.3
    movup.3

    locaddr.2
    mem_storew

    movup.6
    sub.2
    dup
    movdn.7

    mem_loadw

    drop
    drop

    dup.1
    dup.1

    movup.4
    u32checked_not
    movup.5
    u32checked_not
    swap

    movup.2
    u32checked_and
    swap
    movup.2
    u32checked_and
    swap

    movup.3
    movup.3

    movup.4
    add.1
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.2
    drop
    movup.2
    drop

    movup.3
    movup.3

    u32checked_not
    swap
    u32checked_not
    swap

    movup.2
    u32checked_and
    swap
    movup.2
    u32checked_and
    swap

    movup.3
    movup.3

    locaddr.3
    mem_storew

    locaddr.0
    mem_load
    add.2
    dup
    movdn.5

    mem_loadw

    push.0.0.0.0
    loc_loadw.1

    movup.4
    u32checked_xor

    swap
    movup.4
    u32checked_xor
    swap

    movup.2
    movup.4
    u32checked_xor
    movdn.2

    movup.3
    movup.4
    u32checked_xor
    movdn.3

    dup.4
    mem_storew

    movup.4
    add.1
    movdn.4

    dup.4
    mem_loadw

    push.0.0.0.0
    loc_loadw.2
    
    movup.4
    u32checked_xor

    swap
    movup.4
    u32checked_xor
    swap

    movup.2
    movup.4
    u32checked_xor
    movdn.2

    movup.3
    movup.4
    u32checked_xor
    movdn.3

    dup.4
    mem_storew

    movup.4
    add.1
    movdn.4

    dup.4
    mem_loadw

    push.0.0.0.0
    loc_loadw.3
    
    movup.4
    u32checked_xor

    swap
    movup.4
    u32checked_xor
    swap

    movup.2
    movup.4
    u32checked_xor
    movdn.2

    movup.3
    movup.4
    u32checked_xor
    movdn.3

    dup.4
    mem_storew

    # process state[20..30)
    movup.4
    add.1
    movdn.4

    dup.4
    mem_loadw

    drop
    drop

    u32checked_not
    swap
    u32checked_not
    swap

    movup.2
    add.1
    movdn.2

    dup.2
    push.0.0.0.0
    movup.4
    mem_loadw

    dup.1
    dup.1

    movup.6
    u32checked_and
    swap
    movup.6
    u32checked_and
    swap

    movup.3
    movup.3

    u32checked_not
    swap
    u32checked_not
    swap

    dup.4
    u32checked_and
    swap
    dup.5
    u32checked_and
    swap

    movup.3
    movup.3

    loc_storew.1

    movup.6
    add.1
    movdn.6

    dup.6
    mem_loadw

    movup.2
    drop
    movup.2
    drop

    dup.1
    dup.1

    movup.5
    movup.5

    u32checked_not
    swap
    u32checked_not
    swap

    movup.2
    u32checked_and
    swap
    movup.2
    u32checked_and
    swap

    movup.4
    sub.2
    movdn.4

    dup.4
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.7
    movup.7

    u32checked_not
    swap
    u32checked_not
    swap

    dup.3
    dup.3

    movup.2
    u32checked_and
    swap
    movup.2
    u32checked_and
    swap

    movup.7
    movup.7

    loc_storew.2
    dropw

    u32checked_not
    swap
    u32checked_not
    swap

    movup.2
    u32checked_and
    swap
    movup.2
    u32checked_and
    swap

    push.0.0
    movdn.3
    movdn.3

    loc_storew.3

    dup.4
    mem_loadw

    push.0.0.0.0
    loc_loadw.1

    movup.4
    u32checked_xor

    swap
    movup.4
    u32checked_xor
    swap

    movup.2
    movup.4
    u32checked_xor
    movdn.2

    movup.3
    movup.4
    u32checked_xor
    movdn.3

    dup.4
    mem_storew

    movup.4
    add.1
    movdn.4

    dup.4
    mem_loadw

    push.0.0.0.0
    loc_loadw.2

    movup.4
    u32checked_xor

    swap
    movup.4
    u32checked_xor
    swap

    movup.2
    movup.4
    u32checked_xor
    movdn.2

    movup.3
    movup.4
    u32checked_xor
    movdn.3

    dup.4
    mem_storew

    movup.4
    add.1
    movdn.4

    dup.4
    mem_loadw

    push.0.0.0.0
    loc_loadw.3

    movup.4
    u32checked_xor

    swap
    movup.4
    u32checked_xor
    swap

    movup.2
    movup.4
    u32checked_xor
    movdn.2

    movup.3
    movup.4
    u32checked_xor
    movdn.3

    dup.4
    mem_storew

    # process state[30..40)
    movup.4
    add.1
    movdn.4

    dup.4
    mem_loadw

    u32checked_not
    swap
    u32checked_not
    swap

    dup.3
    dup.3

    movup.2
    u32checked_and
    swap
    movup.2
    u32checked_and
    swap

    push.0.0
    loc_storew.1

    movup.6
    add.1
    movdn.6

    dup.6
    mem_loadw

    movup.5
    movup.5

    u32checked_not
    swap
    u32checked_not
    swap

    dup.3
    dup.3

    movup.2
    u32checked_and
    swap
    movup.2
    u32checked_and
    swap

    movup.3
    movup.3

    u32checked_not
    swap
    u32checked_not
    swap

    dup.5
    dup.5

    movup.2
    u32checked_and
    swap
    movup.2
    u32checked_and
    swap

    movup.3
    movup.3

    loc_storew.2

    movup.6
    sub.2
    movdn.6

    dup.6
    mem_loadw

    drop
    drop

    movup.3
    movup.3

    u32checked_not
    swap
    u32checked_not
    swap

    dup.3
    dup.3

    movup.2
    u32checked_and
    swap
    movup.2
    u32checked_and
    swap

    movup.4
    add.1
    movdn.4

    dup.4
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.2
    drop
    movup.2
    drop

    movup.5
    movup.5

    u32checked_not
    swap
    u32checked_not
    swap

    movup.2
    u32checked_and
    swap
    movup.2
    u32checked_and
    swap

    movup.3
    movup.3

    loc_storew.3

    movup.4
    sub.1
    movdn.4

    dup.4
    mem_loadw

    push.0.0.0.0
    loc_loadw.1

    movup.4
    u32checked_xor

    swap
    movup.4
    u32checked_xor
    swap

    movup.2
    movup.4
    u32checked_xor
    movdn.2

    movup.3
    movup.4
    u32checked_xor
    movdn.3

    dup.4
    mem_storew

    movup.4
    add.1
    movdn.4

    dup.4
    mem_loadw

    push.0.0.0.0
    loc_loadw.2

    movup.4
    u32checked_xor

    swap
    movup.4
    u32checked_xor
    swap

    movup.2
    movup.4
    u32checked_xor
    movdn.2

    movup.3
    movup.4
    u32checked_xor
    movdn.3

    dup.4
    mem_storew

    movup.4
    add.1
    movdn.4

    dup.4
    mem_loadw

    push.0.0.0.0
    loc_loadw.3

    movup.4
    u32checked_xor

    swap
    movup.4
    u32checked_xor
    swap

    movup.2
    movup.4
    u32checked_xor
    movdn.2

    movup.3
    movup.4
    u32checked_xor
    movdn.3

    dup.4
    mem_storew

    # process state[40..50)
    movup.4
    add.1
    movdn.4

    dup.4
    mem_loadw

    drop
    drop

    movup.2
    add.1
    movdn.2

    dup.2
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.5
    movup.5

    u32checked_not
    swap
    u32checked_not
    swap

    dup.3
    dup.3

    movup.2
    u32checked_and
    swap
    movup.2
    u32checked_and
    swap

    movup.3
    movup.3

    u32checked_not
    swap
    u32checked_not
    swap

    dup.5
    dup.5

    movup.2
    u32checked_and
    swap
    movup.2
    u32checked_and
    swap

    movup.3
    movup.3

    loc_storew.1

    movup.6
    add.1
    movdn.6

    dup.6
    mem_loadw

    movup.2
    drop
    movup.2
    drop

    movup.3
    movup.3

    u32checked_not
    swap
    u32checked_not
    swap

    dup.3
    dup.3

    movup.2
    u32checked_and
    swap
    movup.2
    u32checked_and
    swap

    movup.4
    sub.2
    movdn.4

    dup.4
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.7
    movup.7

    u32checked_not
    swap
    u32checked_not
    swap

    dup.3
    dup.3

    movup.2
    u32checked_and
    swap
    movup.2
    u32checked_and
    swap

    movup.7
    movup.7

    loc_storew.2
    dropw

    u32checked_not
    swap
    u32checked_not
    swap

    movup.2
    u32checked_and
    swap
    movup.2
    u32checked_and
    swap

    push.0.0
    movdn.3
    movdn.3

    loc_storew.3

    dup.4
    mem_loadw

    push.0.0.0.0
    loc_loadw.1

    movup.4
    u32checked_xor

    swap
    movup.4
    u32checked_xor
    swap

    movup.2
    movup.4
    u32checked_xor
    movdn.2

    movup.3
    movup.4
    u32checked_xor
    movdn.3

    dup.4
    mem_storew

    movup.4
    add.1
    movdn.4

    dup.4
    mem_loadw

    push.0.0.0.0
    loc_loadw.2

    movup.4
    u32checked_xor

    swap
    movup.4
    u32checked_xor
    swap

    movup.2
    movup.4
    u32checked_xor
    movdn.2

    movup.3
    movup.4
    u32checked_xor
    movdn.3

    dup.4
    mem_storew

    movup.4
    add.1
    movdn.4

    dup.4
    mem_loadw

    push.0.0.0.0
    loc_loadw.3

    movup.4
    u32checked_xor

    swap
    movup.4
    u32checked_xor
    swap

    movup.2
    movup.4
    u32checked_xor
    movdn.2

    movup.3
    movup.4
    u32checked_xor
    movdn.3

    dup.4
    mem_storew

    dropw
    drop
end

#! Keccak-p[1600, 24] permutation's ι ( iota ) function, which is
#! implemented in terms of 32 -bit word size ( bit interleaved form ); 
#! imagine https://github.com/itzmeanjan/merklize-sha/blob/1d35aae9da7fed20127489f362b4bc93242a516c/include/sha3.hpp#L288-L306
#! invoked with (c0, c1) as template arguments
#!
#! Expected stack state :
#!
#! [state_addr, c0, c1, ...]
#!
#! Final stack state :
#!
#! [ ... ]
#!
#! All this routine does is
#!
#! state[0] ^= c0
#! state[1] ^= c1
proc.iota
    dup
    push.0.0.0.0
    movup.4
    mem_loadw

    movup.5
    u32checked_xor

    swap

    movup.5
    u32checked_xor

    swap

    movup.4
    mem_storew
    dropw
end

#! Keccak-p[1600, 24] permutation round, without `iota` function ( all other 
#! functions i.e. `theta`, `rho`, `pi`, `chi` are applied in order )
#!
#! As `iota` function involves xoring constant factors with first lane of state array 
#! ( read state[0, 0] ), it's required to invoke them seperately after completion of
#! this procedure's execution.
#!
#! Expected stack state :
#!
#! [start_addr, ... ]
#!
#! After finishing execution, stack looks like
#!
#! [ ... ]
#!
#! Whole keccak-p[1600, 24] state can be represented using fifty u32 elements i.e. 13 absolute memory addresses
#! s.t. last two elements of 12 -th ( when indexed from zero ) memory address are zeroed.
#!
#! Consecutive memory addresses can be computed by repeated application of `add.1`.
#!
#! See https://github.com/itzmeanjan/merklize-sha/blob/1d35aae9da7fed20127489f362b4bc93242a516c/include/sha3.hpp#L325-L340
proc.round
    dup
    exec.theta

    dup
    exec.rho

    dup
    exec.pi

    exec.chi
end

#! Keccak-p[1600, 24] permutation, applying 24 rounds on state array of size  5 x 5 x 64, 
#! where each 64 -bit lane is represented in bit interleaved form ( in terms of two 32 -bit words ).
#!
#! Expected stack state :
#!
#! [start_addr, ... ]
#!
#! After finishing execution, stack looks like
#!
#! [ ... ]
#!
#! Whole keccak-p[1600, 24] state can be represented using fifty u32 elements i.e. 13 absolute memory addresses
#! s.t. last two elements of 12 -th ( when indexed from zero ) memory address are zeroed.
#!
#! Consecutive memory addresses can be computed by repeated application of `add.1`.
#!
#! See https://github.com/itzmeanjan/merklize-sha/blob/1d35aae9da7fed20127489f362b4bc93242a516c/include/sha3.hpp#L379-L427
proc.keccak_p
    # permutation round 1
    dup
    exec.round

    push.0.1
    dup.2
    exec.iota

    # permutation round 2
    dup
    exec.round

    push.137.0
    dup.2
    exec.iota

    # permutation round 3
    dup
    exec.round

    push.2147483787.0
    dup.2
    exec.iota

    # permutation round 4
    dup
    exec.round

    push.2147516544.0
    dup.2
    exec.iota

    # permutation round 5
    dup
    exec.round

    push.139.1
    dup.2
    exec.iota

    # permutation round 6
    dup
    exec.round

    push.32768.1
    dup.2
    exec.iota

    # permutation round 7
    dup
    exec.round

    push.2147516552.1
    dup.2
    exec.iota

    # permutation round 8
    dup
    exec.round

    push.2147483778.1
    dup.2
    exec.iota

    # permutation round 9
    dup
    exec.round

    push.11.0
    dup.2
    exec.iota

    # permutation round 10
    dup
    exec.round

    push.10.0
    dup.2
    exec.iota

    # permutation round 11
    dup
    exec.round

    push.32898.1
    dup.2
    exec.iota

    # permutation round 12
    dup
    exec.round

    push.32771.0
    dup.2
    exec.iota

    # permutation round 13
    dup
    exec.round

    push.32907.1
    dup.2
    exec.iota

    # permutation round 14
    dup
    exec.round

    push.2147483659.1
    dup.2
    exec.iota

    # permutation round 15
    dup
    exec.round

    push.2147483786.1
    dup.2
    exec.iota

    # permutation round 16
    dup
    exec.round

    push.2147483777.1
    dup.2
    exec.iota

    # permutation round 17
    dup
    exec.round

    push.2147483777.0
    dup.2
    exec.iota

    # permutation round 18
    dup
    exec.round

    push.2147483656.0
    dup.2
    exec.iota

    # permutation round 19
    dup
    exec.round

    push.131.0
    dup.2
    exec.iota

    # permutation round 20
    dup
    exec.round

    push.2147516419.0
    dup.2
    exec.iota

    # permutation round 21
    dup
    exec.round

    push.2147516552.1
    dup.2
    exec.iota

    # permutation round 22
    dup
    exec.round

    push.2147483784.0
    dup.2
    exec.iota

    # permutation round 23
    dup
    exec.round

    push.32768.1
    dup.2
    exec.iota

    # permutation round 24
    dup
    exec.round

    push.2147516546.0
    movup.2
    exec.iota
end

#! Given two 32 -bit unsigned integers ( standard form ), representing upper and lower
#! bits of a 64 -bit unsigned integer ( actually a keccak-[1600, 24] lane ),
#! this function converts them into bit interleaved representation, where two 32 -bit
#! unsigned integers ( even portion & then odd portion ) hold bits in even and odd
#! indices of 64 -bit unsigned integer ( remember it's represented in terms of
#! two 32 -bit elements )
#!
#! Input stack state :
#!
#! [hi, lo, ...]
#!
#! After application of bit interleaving, stack looks like
#!
#! [even, odd, ...]
#!
#! Read more about bit interleaved representation in section 2.1 of https://keccak.team/files/Keccak-implementation-3.2.pdf
#!
#! See https://github.com/itzmeanjan/merklize-sha/blob/1d35aae9da7fed20127489f362b4bc93242a516c/include/utils.hpp#L123-L149
#! for reference implementation in higher level language.
export.to_bit_interleaved
    push.0.0

    repeat.16
        u32unchecked_shr.1
        swap
        u32unchecked_shr.1
        swap

        # ---

        dup.3
        dup.3

        push.1
        u32checked_and
        swap
        push.1
        u32checked_and
        swap

        u32unchecked_shl.31
        swap
        u32unchecked_shl.15
        swap

        u32checked_xor
        u32checked_xor

        # ---

        dup.3
        dup.3

        push.2
        u32checked_and
        swap
        push.2
        u32checked_and
        swap

        u32unchecked_shl.30
        swap
        u32unchecked_shl.14
        swap

        movup.3
        u32checked_xor
        u32checked_xor
        swap

        # ---

        movup.2
        u32unchecked_shr.2
        movdn.2

        movup.3
        u32unchecked_shr.2
        movdn.3
    end

    movup.2
    drop
    movup.2
    drop
end

#! Given two 32 -bit unsigned integers ( in bit interleaved form ), representing even and odd
#! positioned bits of a 64 -bit unsigned integer ( actually a keccak-[1600, 24] lane ),
#! this function converts them into standard representation, where two 32 -bit
#! unsigned integers hold higher ( 32 -bit ) and lower ( 32 -bit ) bits of standard
#! representation of 64 -bit unsigned integer
#!
#! Input stack state :
#!
#! [even, odd, ...]
#!
#! After application of logic, stack looks like
#!
#! [hi, lo, ...]
#!
#! This function reverts the action done by `to_bit_interleaved` function implemented above.
#!
#! Read more about bit interleaved representation in section 2.1 of https://keccak.team/files/Keccak-implementation-3.2.pdf
#!
#! See https://github.com/itzmeanjan/merklize-sha/blob/1d35aae9da7fed20127489f362b4bc93242a516c/include/utils.hpp#L151-L175
#! for reference implementation in higher level language.
export.from_bit_interleaved
    push.0.0

    repeat.16
        u32unchecked_shr.2
        swap
        u32unchecked_shr.2
        swap

        # ---

        dup.3
        dup.3

        push.1
        u32checked_and
        swap
        push.1
        u32checked_and
        
        u32unchecked_shl.31
        swap
        u32unchecked_shl.30
        u32checked_xor

        movup.2
        u32checked_xor
        swap

        # ---

        dup.3
        dup.3

        push.65536
        u32checked_and
        swap
        push.65536
        u32checked_and

        u32unchecked_shl.15
        swap
        u32unchecked_shl.14
        u32checked_xor

        u32checked_xor

        # ---

        movup.2
        u32unchecked_shr.1
        movdn.2

        movup.3
        u32unchecked_shr.1
        movdn.3
    end

    movup.2
    drop
    movup.2
    drop
end

#! Given 64 -bytes input ( in terms of sixteen u32 elements on stack top ) to 2-to-1
#! keccak256 hash function, this function prepares 5 x 5 x 64 keccak-p[1600, 24] state
#! bit array such that each of twenty five 64 -bit wide lane is represented in bit
#! interleaved form, using two 32 -bit integers. After completion of execution of
#! this function, state array should live in allocated memory ( total fifty u32 elements, stored in
#! 13 consecutive memory addresses s.t. starting absolute address is provided ).
#!
#! Input stack state :
#!
#! [state_addr, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, ...]
#!
#! Note, state_addr is the starting absolute memory address where keccak-p[1600, 24] state
#! is kept. Consecutive addresses can be computed by repeated application of `add.1` instruction.
#!
#! Final stack state :
#!
#! [...]
#!
#! See https://github.com/itzmeanjan/merklize-sha/blob/1d35aae9da7fed20127489f362b4bc93242a516c/include/keccak_256.hpp#L73-L153
proc.to_state_array
    repeat.4
        movdn.4
        exec.to_bit_interleaved

        movup.3
        movup.3

        exec.to_bit_interleaved

        movup.3
        movup.3

        dup.4
        mem_storew
        dropw

        add.1
    end

    push.0.0.0.1
    dup.4
    mem_storew
    dropw

    add.1

    push.0.0.0.0
    dup.4
    mem_storew
    dropw

    add.1

    push.0.0.0.0
    dup.4
    mem_storew
    dropw

    add.1

    push.0.0.0.0
    dup.4
    mem_storew
    dropw

    add.1

    push.0.0.2147483648.0
    dup.4
    mem_storew
    dropw

    add.1

    push.0.0.0.0
    dup.4
    mem_storew
    dropw

    add.1

    push.0.0.0.0
    dup.4
    mem_storew
    dropw

    add.1

    push.0.0.0.0
    dup.4
    mem_storew
    dropw

    add.1

    push.0.0.0.0
    movup.4
    mem_storew
    dropw
end

#! Given 32 -bytes digest ( in terms of eight u32 elements on stack top ) in bit interleaved form,
#! this function attempts to convert those into standard representation, where eight u32 elements
#! live on stack top, each pair of them hold higher and lower bits of 64 -bit unsigned
#! integer ( lane of keccak-p[1600, 24] state array )
#!
#! Input stack state :
#!
#! [lane0_even, lane0_odd, lane1_even, lane1_odd, lane2_even, lane2_odd, lane3_even, lane3_odd, ...]
#!
#! Output stack state :
#!
#! [dig0_hi, dig0_lo, dig1_hi, dig1_lo, dig2_hi, dig2_lo, dig3_hi, dig3_lo, ...]
#!
#! See https://github.com/itzmeanjan/merklize-sha/blob/1d35aae9da7fed20127489f362b4bc93242a516c/include/keccak_256.hpp#L180-L209
proc.to_digest
    repeat.4
        movup.7
        movup.7

        exec.from_bit_interleaved
    end
end

#! Given 64 -bytes input, in terms of sixteen 32 -bit unsigned integers, where each pair
#! of them holding higher & lower 32 -bits of 64 -bit unsigned integer ( reinterpreted on
#! host CPU from little endian byte array ) respectively, this function computes 32 -bytes
#! keccak256 digest, held on stack top, represented in terms of eight 32 -bit unsigned integers,
#! where each pair of them keeps higher and lower 32 -bits of 64 -bit unsigned integer respectively
#!
#! Expected stack state :
#!
#! [iword0, iword1, iword2, iword3, iword4, iword5, iword6, iword7, 
#!  iword8, iword9, iword10, iword11, iword12, iword13, iword14, iword15, ... ]
#!
#! Final stack state :
#!
#! [oword0, oword1, oword2, oword3, oword4, oword5, oword6, oword7, ... ]
#!
#! See https://github.com/itzmeanjan/merklize-sha/blob/1d35aae9da7fed20127489f362b4bc93242a516c/include/keccak_256.hpp#L232-L257
export.hash.13
    # prapare keccak256 state from input message
    locaddr.0
    exec.to_state_array

    # apply keccak-p[1600, 24] permutation
    locaddr.0
    exec.keccak_p

    # prapare keccak256 digest from state
    push.0.0.0.0
    loc_loadw.1
    push.0.0.0.0
    loc_loadw.0
    exec.to_digest
end",&[12, 0, 5, 116, 104, 101, 116, 97, 0, 0, 0, 3, 0, 175, 2, 110, 186, 0, 0, 0, 0, 0, 0, 0, 0, 195, 107, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 149, 107, 149, 107, 149, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 107, 107, 150, 73, 130, 150, 73, 130, 149, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 149, 107, 149, 107, 150, 73, 130, 150, 73, 130, 149, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 107, 107, 150, 73, 130, 150, 73, 130, 149, 3, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 149, 107, 149, 107, 149, 73, 130, 149, 73, 130, 186, 0, 0, 0, 0, 0, 0, 0, 0, 189, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 107, 107, 149, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 149, 107, 149, 107, 150, 73, 130, 150, 73, 130, 149, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 107, 107, 150, 73, 130, 150, 73, 130, 149, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 149, 107, 149, 107, 150, 73, 130, 150, 73, 130, 149, 3, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 107, 107, 149, 73, 130, 149, 73, 130, 150, 150, 186, 1, 0, 0, 0, 0, 0, 0, 0, 198, 108, 186, 0, 0, 0, 0, 0, 0, 0, 0, 189, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 149, 107, 149, 107, 149, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 107, 107, 150, 73, 130, 150, 73, 130, 149, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 149, 107, 149, 107, 150, 73, 130, 150, 73, 130, 149, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 107, 107, 150, 73, 130, 150, 73, 130, 149, 3, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 149, 107, 149, 107, 149, 73, 130, 149, 73, 130, 186, 0, 0, 0, 0, 0, 0, 0, 0, 189, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 107, 107, 149, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 149, 107, 149, 107, 150, 73, 130, 150, 73, 130, 149, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 107, 107, 150, 73, 130, 150, 73, 130, 149, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 149, 107, 149, 107, 150, 73, 130, 150, 73, 130, 149, 3, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 107, 107, 149, 73, 130, 149, 73, 130, 150, 150, 186, 2, 0, 0, 0, 0, 0, 0, 0, 198, 108, 186, 0, 0, 0, 0, 0, 0, 0, 0, 189, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 149, 107, 149, 107, 149, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 107, 107, 150, 73, 130, 150, 73, 130, 149, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 149, 107, 149, 107, 150, 73, 130, 150, 73, 130, 149, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 107, 107, 150, 73, 130, 150, 73, 130, 149, 3, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 149, 107, 149, 107, 149, 73, 130, 149, 73, 130, 186, 2, 0, 0, 0, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 186, 1, 0, 0, 0, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 118, 114, 90, 1, 73, 120, 114, 73, 112, 118, 90, 1, 73, 114, 118, 73, 153, 121, 90, 1, 73, 154, 120, 73, 155, 160, 90, 1, 73, 156, 159, 73, 157, 157, 90, 1, 73, 157, 157, 73, 130, 149, 150, 151, 152, 153, 154, 155, 156, 186, 0, 0, 0, 0, 0, 0, 0, 0, 189, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 115, 73, 130, 116, 73, 130, 149, 117, 73, 165, 150, 118, 73, 166, 114, 198, 108, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 119, 73, 130, 120, 73, 130, 149, 121, 73, 165, 150, 122, 73, 166, 114, 198, 108, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 123, 73, 130, 124, 73, 130, 149, 115, 73, 165, 150, 116, 73, 166, 114, 198, 108, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 117, 73, 130, 118, 73, 130, 149, 119, 73, 165, 150, 120, 73, 166, 114, 198, 108, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 121, 73, 130, 122, 73, 130, 149, 123, 73, 165, 150, 124, 73, 166, 114, 198, 108, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 115, 73, 130, 116, 73, 130, 149, 117, 73, 165, 150, 118, 73, 166, 114, 198, 108, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 119, 73, 130, 120, 73, 130, 149, 121, 73, 165, 150, 122, 73, 166, 114, 198, 108, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 123, 73, 130, 124, 73, 130, 149, 115, 73, 165, 150, 116, 73, 166, 114, 198, 108, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 117, 73, 130, 118, 73, 130, 149, 119, 73, 165, 150, 120, 73, 166, 114, 198, 108, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 121, 73, 130, 122, 73, 130, 149, 123, 73, 165, 150, 124, 73, 166, 114, 198, 108, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 152, 73, 130, 152, 73, 130, 149, 152, 73, 165, 150, 152, 73, 166, 114, 198, 108, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 152, 73, 130, 152, 73, 130, 149, 152, 73, 165, 150, 152, 73, 166, 114, 198, 108, 3, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 152, 73, 130, 152, 73, 130, 151, 198, 108, 3, 114, 104, 111, 0, 0, 0, 1, 0, 203, 0, 110, 186, 0, 0, 0, 0, 0, 0, 0, 0, 195, 107, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 114, 191, 150, 90, 1, 165, 151, 110, 3, 168, 198, 114, 191, 90, 31, 130, 90, 31, 130, 149, 90, 14, 165, 150, 90, 14, 166, 151, 110, 3, 168, 198, 114, 191, 90, 13, 130, 90, 14, 149, 90, 18, 165, 150, 90, 18, 166, 151, 110, 3, 168, 198, 114, 191, 90, 22, 130, 90, 22, 130, 149, 90, 3, 165, 150, 90, 3, 166, 151, 110, 3, 168, 198, 114, 191, 90, 27, 130, 90, 28, 149, 90, 10, 165, 150, 90, 10, 166, 151, 110, 3, 168, 198, 114, 191, 90, 1, 130, 90, 2, 149, 90, 5, 165, 150, 90, 5, 166, 151, 110, 3, 168, 198, 114, 191, 90, 21, 130, 90, 22, 149, 90, 12, 166, 149, 90, 13, 165, 151, 110, 3, 168, 198, 114, 191, 90, 19, 130, 90, 20, 149, 90, 20, 166, 149, 90, 21, 165, 151, 110, 3, 168, 198, 114, 191, 90, 22, 130, 90, 23, 149, 90, 7, 166, 149, 90, 8, 165, 151, 110, 3, 168, 198, 114, 191, 90, 10, 130, 90, 11, 149, 90, 4, 165, 150, 90, 4, 166, 151, 110, 3, 168, 198, 114, 191, 90, 9, 130, 90, 9, 130, 149, 90, 1, 165, 150, 90, 1, 166, 151, 110, 3, 168, 198, 114, 191, 90, 30, 130, 90, 31, 149, 90, 28, 165, 150, 90, 28, 166, 151, 110, 3, 168, 198, 114, 191, 90, 7, 130, 90, 7, 130, 151, 198, 108, 2, 112, 105, 0, 0, 0, 14, 0, 25, 1, 110, 186, 0, 0, 0, 0, 0, 0, 0, 0, 195, 107, 186, 1, 0, 0, 0, 0, 0, 0, 0, 130, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 114, 191, 185, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 166, 166, 117, 198, 107, 107, 166, 166, 115, 3, 198, 151, 3, 167, 114, 191, 185, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 166, 166, 117, 3, 198, 107, 107, 115, 3, 198, 151, 3, 167, 114, 191, 185, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 117, 3, 198, 149, 107, 149, 107, 166, 166, 115, 3, 198, 151, 3, 167, 114, 191, 115, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 149, 107, 149, 107, 117, 198, 117, 3, 191, 149, 107, 149, 107, 115, 3, 198, 151, 3, 167, 114, 191, 115, 3, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 149, 107, 149, 107, 117, 3, 198, 108, 185, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 166, 166, 115, 3, 198, 151, 3, 167, 114, 191, 115, 3, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 149, 107, 149, 107, 117, 3, 198, 117, 3, 191, 149, 107, 149, 107, 115, 3, 198, 151, 3, 167, 114, 191, 185, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 166, 166, 117, 3, 198, 107, 107, 166, 166, 115, 3, 198, 151, 3, 167, 114, 191, 115, 3, 198, 151, 3, 167, 114, 191, 185, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 166, 166, 117, 3, 198, 107, 107, 166, 166, 115, 3, 198, 151, 3, 167, 114, 191, 115, 3, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 149, 107, 149, 107, 117, 3, 198, 117, 3, 191, 149, 107, 149, 107, 115, 3, 198, 151, 3, 167, 114, 191, 115, 3, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 107, 107, 150, 150, 117, 3, 198, 108, 185, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 166, 166, 115, 3, 198, 151, 3, 167, 114, 191, 115, 3, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 149, 107, 149, 107, 117, 3, 198, 117, 3, 191, 149, 107, 149, 107, 115, 3, 198, 151, 3, 167, 114, 191, 115, 3, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 107, 107, 166, 166, 117, 3, 198, 107, 107, 151, 107, 186, 0, 0, 0, 0, 0, 0, 0, 0, 189, 167, 254, 148, 4, 10, 0, 115, 191, 114, 198, 151, 3, 167, 152, 3, 168, 108, 107, 107, 3, 99, 104, 105, 0, 0, 0, 4, 0, 82, 3, 110, 186, 0, 0, 0, 0, 0, 0, 0, 0, 195, 107, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 107, 107, 74, 130, 74, 130, 149, 3, 110, 166, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 111, 111, 153, 71, 130, 153, 71, 130, 150, 74, 150, 74, 151, 71, 130, 151, 71, 130, 150, 150, 186, 1, 0, 0, 0, 0, 0, 0, 0, 198, 114, 191, 107, 107, 74, 130, 74, 130, 149, 3, 110, 166, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 149, 107, 149, 107, 111, 111, 151, 71, 130, 151, 71, 130, 150, 150, 151, 5, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 152, 74, 152, 74, 112, 71, 130, 113, 71, 130, 154, 154, 186, 2, 0, 0, 0, 0, 0, 0, 0, 198, 108, 74, 130, 74, 130, 149, 71, 130, 149, 71, 130, 186, 0, 0, 0, 0, 0, 0, 0, 0, 189, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 114, 191, 186, 1, 0, 0, 0, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 151, 73, 130, 151, 73, 130, 149, 151, 73, 165, 150, 151, 73, 166, 114, 198, 151, 3, 167, 114, 191, 186, 2, 0, 0, 0, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 151, 73, 130, 151, 73, 130, 149, 151, 73, 165, 150, 151, 73, 166, 114, 198, 151, 3, 167, 114, 191, 152, 73, 130, 152, 73, 130, 114, 198, 151, 3, 167, 114, 191, 74, 130, 74, 130, 113, 113, 149, 71, 130, 149, 71, 130, 185, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 186, 1, 0, 0, 0, 0, 0, 0, 0, 198, 153, 3, 110, 170, 191, 152, 152, 74, 130, 74, 130, 112, 71, 130, 113, 71, 130, 150, 150, 74, 130, 74, 130, 114, 71, 130, 115, 71, 130, 150, 150, 186, 2, 0, 0, 0, 0, 0, 0, 0, 198, 153, 5, 110, 170, 191, 107, 107, 111, 111, 151, 74, 152, 74, 130, 149, 71, 130, 149, 71, 130, 150, 150, 151, 3, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 149, 107, 149, 107, 150, 150, 74, 130, 74, 130, 149, 71, 130, 149, 71, 130, 150, 150, 186, 3, 0, 0, 0, 0, 0, 0, 0, 198, 186, 0, 0, 0, 0, 0, 0, 0, 0, 189, 3, 110, 168, 191, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 1, 0, 0, 0, 0, 0, 0, 0, 151, 73, 130, 151, 73, 130, 149, 151, 73, 165, 150, 151, 73, 166, 114, 198, 151, 3, 167, 114, 191, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 2, 0, 0, 0, 0, 0, 0, 0, 151, 73, 130, 151, 73, 130, 149, 151, 73, 165, 150, 151, 73, 166, 114, 198, 151, 3, 167, 114, 191, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 3, 0, 0, 0, 0, 0, 0, 0, 151, 73, 130, 151, 73, 130, 149, 151, 73, 165, 150, 151, 73, 166, 114, 198, 151, 3, 167, 114, 191, 107, 107, 74, 130, 74, 130, 149, 3, 165, 112, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 111, 111, 153, 71, 130, 153, 71, 130, 150, 150, 74, 130, 74, 130, 114, 71, 130, 115, 71, 130, 150, 150, 200, 1, 0, 0, 0, 0, 0, 0, 0, 153, 3, 169, 116, 191, 149, 107, 149, 107, 111, 111, 152, 152, 74, 130, 74, 130, 149, 71, 130, 149, 71, 130, 151, 5, 167, 114, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 154, 154, 74, 130, 74, 130, 113, 113, 149, 71, 130, 149, 71, 130, 154, 154, 200, 2, 0, 0, 0, 0, 0, 0, 0, 108, 74, 130, 74, 130, 149, 71, 130, 149, 71, 130, 185, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 166, 166, 200, 3, 0, 0, 0, 0, 0, 0, 0, 114, 191, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 1, 0, 0, 0, 0, 0, 0, 0, 151, 73, 130, 151, 73, 130, 149, 151, 73, 165, 150, 151, 73, 166, 114, 198, 151, 3, 167, 114, 191, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 2, 0, 0, 0, 0, 0, 0, 0, 151, 73, 130, 151, 73, 130, 149, 151, 73, 165, 150, 151, 73, 166, 114, 198, 151, 3, 167, 114, 191, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 3, 0, 0, 0, 0, 0, 0, 0, 151, 73, 130, 151, 73, 130, 149, 151, 73, 165, 150, 151, 73, 166, 114, 198, 151, 3, 167, 114, 191, 74, 130, 74, 130, 113, 113, 149, 71, 130, 149, 71, 130, 185, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 200, 1, 0, 0, 0, 0, 0, 0, 0, 153, 3, 169, 116, 191, 152, 152, 74, 130, 74, 130, 113, 113, 149, 71, 130, 149, 71, 130, 150, 150, 74, 130, 74, 130, 115, 115, 149, 71, 130, 149, 71, 130, 150, 150, 200, 2, 0, 0, 0, 0, 0, 0, 0, 153, 5, 169, 116, 191, 107, 107, 150, 150, 74, 130, 74, 130, 113, 113, 149, 71, 130, 149, 71, 130, 151, 3, 167, 114, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 149, 107, 149, 107, 152, 152, 74, 130, 74, 130, 149, 71, 130, 149, 71, 130, 150, 150, 200, 3, 0, 0, 0, 0, 0, 0, 0, 151, 5, 167, 114, 191, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 1, 0, 0, 0, 0, 0, 0, 0, 151, 73, 130, 151, 73, 130, 149, 151, 73, 165, 150, 151, 73, 166, 114, 198, 151, 3, 167, 114, 191, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 2, 0, 0, 0, 0, 0, 0, 0, 151, 73, 130, 151, 73, 130, 149, 151, 73, 165, 150, 151, 73, 166, 114, 198, 151, 3, 167, 114, 191, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 3, 0, 0, 0, 0, 0, 0, 0, 151, 73, 130, 151, 73, 130, 149, 151, 73, 165, 150, 151, 73, 166, 114, 198, 151, 3, 167, 114, 191, 107, 107, 149, 3, 165, 112, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 152, 152, 74, 130, 74, 130, 113, 113, 149, 71, 130, 149, 71, 130, 150, 150, 74, 130, 74, 130, 115, 115, 149, 71, 130, 149, 71, 130, 150, 150, 200, 1, 0, 0, 0, 0, 0, 0, 0, 153, 3, 169, 116, 191, 149, 107, 149, 107, 150, 150, 74, 130, 74, 130, 113, 113, 149, 71, 130, 149, 71, 130, 151, 5, 167, 114, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 154, 154, 74, 130, 74, 130, 113, 113, 149, 71, 130, 149, 71, 130, 154, 154, 200, 2, 0, 0, 0, 0, 0, 0, 0, 108, 74, 130, 74, 130, 149, 71, 130, 149, 71, 130, 185, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 166, 166, 200, 3, 0, 0, 0, 0, 0, 0, 0, 114, 191, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 1, 0, 0, 0, 0, 0, 0, 0, 151, 73, 130, 151, 73, 130, 149, 151, 73, 165, 150, 151, 73, 166, 114, 198, 151, 3, 167, 114, 191, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 2, 0, 0, 0, 0, 0, 0, 0, 151, 73, 130, 151, 73, 130, 149, 151, 73, 165, 150, 151, 73, 166, 114, 198, 151, 3, 167, 114, 191, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 3, 0, 0, 0, 0, 0, 0, 0, 151, 73, 130, 151, 73, 130, 149, 151, 73, 165, 150, 151, 73, 166, 114, 198, 108, 107, 4, 105, 111, 116, 97, 0, 0, 0, 0, 0, 13, 0, 110, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 191, 152, 73, 130, 152, 73, 130, 151, 198, 108, 5, 114, 111, 117, 110, 100, 0, 0, 0, 0, 0, 7, 0, 110, 211, 0, 0, 110, 211, 1, 0, 110, 211, 2, 0, 211, 3, 0, 8, 107, 101, 99, 99, 97, 107, 95, 112, 0, 0, 0, 0, 0, 120, 0, 110, 211, 5, 0, 185, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 112, 211, 4, 0, 110, 211, 5, 0, 185, 2, 137, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 112, 211, 4, 0, 110, 211, 5, 0, 185, 2, 139, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 112, 211, 4, 0, 110, 211, 5, 0, 185, 2, 128, 128, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 112, 211, 4, 0, 110, 211, 5, 0, 185, 2, 139, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 112, 211, 4, 0, 110, 211, 5, 0, 185, 2, 0, 128, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 112, 211, 4, 0, 110, 211, 5, 0, 185, 2, 136, 128, 0, 128, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 112, 211, 4, 0, 110, 211, 5, 0, 185, 2, 130, 0, 0, 128, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 112, 211, 4, 0, 110, 211, 5, 0, 185, 2, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 112, 211, 4, 0, 110, 211, 5, 0, 185, 2, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 112, 211, 4, 0, 110, 211, 5, 0, 185, 2, 130, 128, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 112, 211, 4, 0, 110, 211, 5, 0, 185, 2, 3, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 112, 211, 4, 0, 110, 211, 5, 0, 185, 2, 139, 128, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 112, 211, 4, 0, 110, 211, 5, 0, 185, 2, 11, 0, 0, 128, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 112, 211, 4, 0, 110, 211, 5, 0, 185, 2, 138, 0, 0, 128, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 112, 211, 4, 0, 110, 211, 5, 0, 185, 2, 129, 0, 0, 128, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 112, 211, 4, 0, 110, 211, 5, 0, 185, 2, 129, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 112, 211, 4, 0, 110, 211, 5, 0, 185, 2, 8, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 112, 211, 4, 0, 110, 211, 5, 0, 185, 2, 131, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 112, 211, 4, 0, 110, 211, 5, 0, 185, 2, 3, 128, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 112, 211, 4, 0, 110, 211, 5, 0, 185, 2, 136, 128, 0, 128, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 112, 211, 4, 0, 110, 211, 5, 0, 185, 2, 136, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 112, 211, 4, 0, 110, 211, 5, 0, 185, 2, 0, 128, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 112, 211, 4, 0, 110, 211, 5, 0, 185, 2, 130, 128, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 149, 211, 4, 0, 18, 116, 111, 95, 98, 105, 116, 95, 105, 110, 116, 101, 114, 108, 101, 97, 118, 101, 100, 55, 3, 71, 105, 118, 101, 110, 32, 116, 119, 111, 32, 51, 50, 32, 45, 98, 105, 116, 32, 117, 110, 115, 105, 103, 110, 101, 100, 32, 105, 110, 116, 101, 103, 101, 114, 115, 32, 40, 32, 115, 116, 97, 110, 100, 97, 114, 100, 32, 102, 111, 114, 109, 32, 41, 44, 32, 114, 101, 112, 114, 101, 115, 101, 110, 116, 105, 110, 103, 32, 117, 112, 112, 101, 114, 32, 97, 110, 100, 32, 108, 111, 119, 101, 114, 10, 98, 105, 116, 115, 32, 111, 102, 32, 97, 32, 54, 52, 32, 45, 98, 105, 116, 32, 117, 110, 115, 105, 103, 110, 101, 100, 32, 105, 110, 116, 101, 103, 101, 114, 32, 40, 32, 97, 99, 116, 117, 97, 108, 108, 121, 32, 97, 32, 107, 101, 99, 99, 97, 107, 45, 91, 49, 54, 48, 48, 44, 32, 50, 52, 93, 32, 108, 97, 110, 101, 32, 41, 44, 10, 116, 104, 105, 115, 32, 102, 117, 110, 99, 116, 105, 111, 110, 32, 99, 111, 110, 118, 101, 114, 116, 115, 32, 116, 104, 101, 109, 32, 105, 110, 116, 111, 32, 98, 105, 116, 32, 105, 110, 116, 101, 114, 108, 101, 97, 118, 101, 100, 32, 114, 101, 112, 114, 101, 115, 101, 110, 116, 97, 116, 105, 111, 110, 44, 32, 119, 104, 101, 114, 101, 32, 116, 119, 111, 32, 51, 50, 32, 45, 98, 105, 116, 10, 117, 110, 115, 105, 103, 110, 101, 100, 32, 105, 110, 116, 101, 103, 101, 114, 115, 32, 40, 32, 101, 118, 101, 110, 32, 112, 111, 114, 116, 105, 111, 110, 32, 38, 32, 116, 104, 101, 110, 32, 111, 100, 100, 32, 112, 111, 114, 116, 105, 111, 110, 32, 41, 32, 104, 111, 108, 100, 32, 98, 105, 116, 115, 32, 105, 110, 32, 101, 118, 101, 110, 32, 97, 110, 100, 32, 111, 100, 100, 10, 105, 110, 100, 105, 99, 101, 115, 32, 111, 102, 32, 54, 52, 32, 45, 98, 105, 116, 32, 117, 110, 115, 105, 103, 110, 101, 100, 32, 105, 110, 116, 101, 103, 101, 114, 32, 40, 32, 114, 101, 109, 101, 109, 98, 101, 114, 32, 105, 116, 39, 115, 32, 114, 101, 112, 114, 101, 115, 101, 110, 116, 101, 100, 32, 105, 110, 32, 116, 101, 114, 109, 115, 32, 111, 102, 10, 116, 119, 111, 32, 51, 50, 32, 45, 98, 105, 116, 32, 101, 108, 101, 109, 101, 110, 116, 115, 32, 41, 10, 73, 110, 112, 117, 116, 32, 115, 116, 97, 99, 107, 32, 115, 116, 97, 116, 101, 32, 58, 10, 91, 104, 105, 44, 32, 108, 111, 44, 32, 46, 46, 46, 93, 10, 65, 102, 116, 101, 114, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 32, 111, 102, 32, 98, 105, 116, 32, 105, 110, 116, 101, 114, 108, 101, 97, 118, 105, 110, 103, 44, 32, 115, 116, 97, 99, 107, 32, 108, 111, 111, 107, 115, 32, 108, 105, 107, 101, 10, 91, 101, 118, 101, 110, 44, 32, 111, 100, 100, 44, 32, 46, 46, 46, 93, 10, 82, 101, 97, 100, 32, 109, 111, 114, 101, 32, 97, 98, 111, 117, 116, 32, 98, 105, 116, 32, 105, 110, 116, 101, 114, 108, 101, 97, 118, 101, 100, 32, 114, 101, 112, 114, 101, 115, 101, 110, 116, 97, 116, 105, 111, 110, 32, 105, 110, 32, 115, 101, 99, 116, 105, 111, 110, 32, 50, 46, 49, 32, 111, 102, 32, 104, 116, 116, 112, 115, 58, 47, 47, 107, 101, 99, 99, 97, 107, 46, 116, 101, 97, 109, 47, 102, 105, 108, 101, 115, 47, 75, 101, 99, 99, 97, 107, 45, 105, 109, 112, 108, 101, 109, 101, 110, 116, 97, 116, 105, 111, 110, 45, 51, 46, 50, 46, 112, 100, 102, 10, 83, 101, 101, 32, 104, 116, 116, 112, 115, 58, 47, 47, 103, 105, 116, 104, 117, 98, 46, 99, 111, 109, 47, 105, 116, 122, 109, 101, 97, 110, 106, 97, 110, 47, 109, 101, 114, 107, 108, 105, 122, 101, 45, 115, 104, 97, 47, 98, 108, 111, 98, 47, 49, 100, 51, 53, 97, 97, 101, 57, 100, 97, 55, 102, 101, 100, 50, 48, 49, 50, 55, 52, 56, 57, 102, 51, 54, 50, 98, 52, 98, 99, 57, 51, 50, 52, 50, 97, 53, 49, 54, 99, 47, 105, 110, 99, 108, 117, 100, 101, 47, 117, 116, 105, 108, 115, 46, 104, 112, 112, 35, 76, 49, 50, 51, 45, 76, 49, 52, 57, 10, 102, 111, 114, 32, 114, 101, 102, 101, 114, 101, 110, 99, 101, 32, 105, 109, 112, 108, 101, 109, 101, 110, 116, 97, 116, 105, 111, 110, 32, 105, 110, 32, 104, 105, 103, 104, 101, 114, 32, 108, 101, 118, 101, 108, 32, 108, 97, 110, 103, 117, 97, 103, 101, 46, 1, 0, 0, 6, 0, 185, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254, 140, 8, 40, 0, 78, 1, 130, 78, 1, 130, 113, 113, 185, 1, 1, 0, 0, 0, 0, 0, 0, 0, 71, 130, 185, 1, 1, 0, 0, 0, 0, 0, 0, 0, 71, 130, 82, 31, 130, 82, 15, 130, 73, 73, 113, 113, 185, 1, 2, 0, 0, 0, 0, 0, 0, 0, 71, 130, 185, 1, 2, 0, 0, 0, 0, 0, 0, 0, 71, 130, 82, 30, 130, 82, 14, 130, 150, 73, 73, 130, 149, 78, 2, 165, 150, 78, 2, 166, 149, 107, 149, 107, 20, 102, 114, 111, 109, 95, 98, 105, 116, 95, 105, 110, 116, 101, 114, 108, 101, 97, 118, 101, 100, 90, 3, 71, 105, 118, 101, 110, 32, 116, 119, 111, 32, 51, 50, 32, 45, 98, 105, 116, 32, 117, 110, 115, 105, 103, 110, 101, 100, 32, 105, 110, 116, 101, 103, 101, 114, 115, 32, 40, 32, 105, 110, 32, 98, 105, 116, 32, 105, 110, 116, 101, 114, 108, 101, 97, 118, 101, 100, 32, 102, 111, 114, 109, 32, 41, 44, 32, 114, 101, 112, 114, 101, 115, 101, 110, 116, 105, 110, 103, 32, 101, 118, 101, 110, 32, 97, 110, 100, 32, 111, 100, 100, 10, 112, 111, 115, 105, 116, 105, 111, 110, 101, 100, 32, 98, 105, 116, 115, 32, 111, 102, 32, 97, 32, 54, 52, 32, 45, 98, 105, 116, 32, 117, 110, 115, 105, 103, 110, 101, 100, 32, 105, 110, 116, 101, 103, 101, 114, 32, 40, 32, 97, 99, 116, 117, 97, 108, 108, 121, 32, 97, 32, 107, 101, 99, 99, 97, 107, 45, 91, 49, 54, 48, 48, 44, 32, 50, 52, 93, 32, 108, 97, 110, 101, 32, 41, 44, 10, 116, 104, 105, 115, 32, 102, 117, 110, 99, 116, 105, 111, 110, 32, 99, 111, 110, 118, 101, 114, 116, 115, 32, 116, 104, 101, 109, 32, 105, 110, 116, 111, 32, 115, 116, 97, 110, 100, 97, 114, 100, 32, 114, 101, 112, 114, 101, 115, 101, 110, 116, 97, 116, 105, 111, 110, 44, 32, 119, 104, 101, 114, 101, 32, 116, 119, 111, 32, 51, 50, 32, 45, 98, 105, 116, 10, 117, 110, 115, 105, 103, 110, 101, 100, 32, 105, 110, 116, 101, 103, 101, 114, 115, 32, 104, 111, 108, 100, 32, 104, 105, 103, 104, 101, 114, 32, 40, 32, 51, 50, 32, 45, 98, 105, 116, 32, 41, 32, 97, 110, 100, 32, 108, 111, 119, 101, 114, 32, 40, 32, 51, 50, 32, 45, 98, 105, 116, 32, 41, 32, 98, 105, 116, 115, 32, 111, 102, 32, 115, 116, 97, 110, 100, 97, 114, 100, 10, 114, 101, 112, 114, 101, 115, 101, 110, 116, 97, 116, 105, 111, 110, 32, 111, 102, 32, 54, 52, 32, 45, 98, 105, 116, 32, 117, 110, 115, 105, 103, 110, 101, 100, 32, 105, 110, 116, 101, 103, 101, 114, 10, 73, 110, 112, 117, 116, 32, 115, 116, 97, 99, 107, 32, 115, 116, 97, 116, 101, 32, 58, 10, 91, 101, 118, 101, 110, 44, 32, 111, 100, 100, 44, 32, 46, 46, 46, 93, 10, 65, 102, 116, 101, 114, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 32, 111, 102, 32, 108, 111, 103, 105, 99, 44, 32, 115, 116, 97, 99, 107, 32, 108, 111, 111, 107, 115, 32, 108, 105, 107, 101, 10, 91, 104, 105, 44, 32, 108, 111, 44, 32, 46, 46, 46, 93, 10, 84, 104, 105, 115, 32, 102, 117, 110, 99, 116, 105, 111, 110, 32, 114, 101, 118, 101, 114, 116, 115, 32, 116, 104, 101, 32, 97, 99, 116, 105, 111, 110, 32, 100, 111, 110, 101, 32, 98, 121, 32, 96, 116, 111, 95, 98, 105, 116, 95, 105, 110, 116, 101, 114, 108, 101, 97, 118, 101, 100, 96, 32, 102, 117, 110, 99, 116, 105, 111, 110, 32, 105, 109, 112, 108, 101, 109, 101, 110, 116, 101, 100, 32, 97, 98, 111, 118, 101, 46, 10, 82, 101, 97, 100, 32, 109, 111, 114, 101, 32, 97, 98, 111, 117, 116, 32, 98, 105, 116, 32, 105, 110, 116, 101, 114, 108, 101, 97, 118, 101, 100, 32, 114, 101, 112, 114, 101, 115, 101, 110, 116, 97, 116, 105, 111, 110, 32, 105, 110, 32, 115, 101, 99, 116, 105, 111, 110, 32, 50, 46, 49, 32, 111, 102, 32, 104, 116, 116, 112, 115, 58, 47, 47, 107, 101, 99, 99, 97, 107, 46, 116, 101, 97, 109, 47, 102, 105, 108, 101, 115, 47, 75, 101, 99, 99, 97, 107, 45, 105, 109, 112, 108, 101, 109, 101, 110, 116, 97, 116, 105, 111, 110, 45, 51, 46, 50, 46, 112, 100, 102, 10, 83, 101, 101, 32, 104, 116, 116, 112, 115, 58, 47, 47, 103, 105, 116, 104, 117, 98, 46, 99, 111, 109, 47, 105, 116, 122, 109, 101, 97, 110, 106, 97, 110, 47, 109, 101, 114, 107, 108, 105, 122, 101, 45, 115, 104, 97, 47, 98, 108, 111, 98, 47, 49, 100, 51, 53, 97, 97, 101, 57, 100, 97, 55, 102, 101, 100, 50, 48, 49, 50, 55, 52, 56, 57, 102, 51, 54, 50, 98, 52, 98, 99, 57, 51, 50, 52, 50, 97, 53, 49, 54, 99, 47, 105, 110, 99, 108, 117, 100, 101, 47, 117, 116, 105, 108, 115, 46, 104, 112, 112, 35, 76, 49, 53, 49, 45, 76, 49, 55, 53, 10, 102, 111, 114, 32, 114, 101, 102, 101, 114, 101, 110, 99, 101, 32, 105, 109, 112, 108, 101, 109, 101, 110, 116, 97, 116, 105, 111, 110, 32, 105, 110, 32, 104, 105, 103, 104, 101, 114, 32, 108, 101, 118, 101, 108, 32, 108, 97, 110, 103, 117, 97, 103, 101, 46, 1, 0, 0, 6, 0, 185, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254, 189, 8, 36, 0, 78, 2, 130, 78, 2, 130, 113, 113, 185, 1, 1, 0, 0, 0, 0, 0, 0, 0, 71, 130, 185, 1, 1, 0, 0, 0, 0, 0, 0, 0, 71, 82, 31, 130, 82, 30, 73, 149, 73, 130, 113, 113, 185, 1, 0, 0, 1, 0, 0, 0, 0, 0, 71, 130, 185, 1, 0, 0, 1, 0, 0, 0, 0, 0, 71, 82, 15, 130, 82, 14, 73, 73, 149, 78, 1, 165, 150, 78, 1, 166, 149, 107, 149, 107, 14, 116, 111, 95, 115, 116, 97, 116, 101, 95, 97, 114, 114, 97, 121, 0, 0, 0, 0, 0, 45, 0, 254, 233, 8, 11, 0, 167, 211, 7, 0, 150, 150, 211, 7, 0, 150, 150, 114, 198, 108, 3, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 114, 198, 108, 3, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 114, 198, 108, 3, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 114, 198, 108, 3, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 114, 198, 108, 3, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 114, 198, 108, 3, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 114, 198, 108, 3, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 114, 198, 108, 3, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 114, 198, 108, 3, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 198, 108, 9, 116, 111, 95, 100, 105, 103, 101, 115, 116, 0, 0, 0, 0, 0, 1, 0, 254, 36, 9, 3, 0, 154, 154, 211, 8, 0, 4, 104, 97, 115, 104, 64, 3, 71, 105, 118, 101, 110, 32, 54, 52, 32, 45, 98, 121, 116, 101, 115, 32, 105, 110, 112, 117, 116, 44, 32, 105, 110, 32, 116, 101, 114, 109, 115, 32, 111, 102, 32, 115, 105, 120, 116, 101, 101, 110, 32, 51, 50, 32, 45, 98, 105, 116, 32, 117, 110, 115, 105, 103, 110, 101, 100, 32, 105, 110, 116, 101, 103, 101, 114, 115, 44, 32, 119, 104, 101, 114, 101, 32, 101, 97, 99, 104, 32, 112, 97, 105, 114, 10, 111, 102, 32, 116, 104, 101, 109, 32, 104, 111, 108, 100, 105, 110, 103, 32, 104, 105, 103, 104, 101, 114, 32, 38, 32, 108, 111, 119, 101, 114, 32, 51, 50, 32, 45, 98, 105, 116, 115, 32, 111, 102, 32, 54, 52, 32, 45, 98, 105, 116, 32, 117, 110, 115, 105, 103, 110, 101, 100, 32, 105, 110, 116, 101, 103, 101, 114, 32, 40, 32, 114, 101, 105, 110, 116, 101, 114, 112, 114, 101, 116, 101, 100, 32, 111, 110, 10, 104, 111, 115, 116, 32, 67, 80, 85, 32, 102, 114, 111, 109, 32, 108, 105, 116, 116, 108, 101, 32, 101, 110, 100, 105, 97, 110, 32, 98, 121, 116, 101, 32, 97, 114, 114, 97, 121, 32, 41, 32, 114, 101, 115, 112, 101, 99, 116, 105, 118, 101, 108, 121, 44, 32, 116, 104, 105, 115, 32, 102, 117, 110, 99, 116, 105, 111, 110, 32, 99, 111, 109, 112, 117, 116, 101, 115, 32, 51, 50, 32, 45, 98, 121, 116, 101, 115, 10, 107, 101, 99, 99, 97, 107, 50, 53, 54, 32, 100, 105, 103, 101, 115, 116, 44, 32, 104, 101, 108, 100, 32, 111, 110, 32, 115, 116, 97, 99, 107, 32, 116, 111, 112, 44, 32, 114, 101, 112, 114, 101, 115, 101, 110, 116, 101, 100, 32, 105, 110, 32, 116, 101, 114, 109, 115, 32, 111, 102, 32, 101, 105, 103, 104, 116, 32, 51, 50, 32, 45, 98, 105, 116, 32, 117, 110, 115, 105, 103, 110, 101, 100, 32, 105, 110, 116, 101, 103, 101, 114, 115, 44, 10, 119, 104, 101, 114, 101, 32, 101, 97, 99, 104, 32, 112, 97, 105, 114, 32, 111, 102, 32, 116, 104, 101, 109, 32, 107, 101, 101, 112, 115, 32, 104, 105, 103, 104, 101, 114, 32, 97, 110, 100, 32, 108, 111, 119, 101, 114, 32, 51, 50, 32, 45, 98, 105, 116, 115, 32, 111, 102, 32, 54, 52, 32, 45, 98, 105, 116, 32, 117, 110, 115, 105, 103, 110, 101, 100, 32, 105, 110, 116, 101, 103, 101, 114, 32, 114, 101, 115, 112, 101, 99, 116, 105, 118, 101, 108, 121, 10, 69, 120, 112, 101, 99, 116, 101, 100, 32, 115, 116, 97, 99, 107, 32, 115, 116, 97, 116, 101, 32, 58, 10, 91, 105, 119, 111, 114, 100, 48, 44, 32, 105, 119, 111, 114, 100, 49, 44, 32, 105, 119, 111, 114, 100, 50, 44, 32, 105, 119, 111, 114, 100, 51, 44, 32, 105, 119, 111, 114, 100, 52, 44, 32, 105, 119, 111, 114, 100, 53, 44, 32, 105, 119, 111, 114, 100, 54, 44, 32, 105, 119, 111, 114, 100, 55, 44, 10, 105, 119, 111, 114, 100, 56, 44, 32, 105, 119, 111, 114, 100, 57, 44, 32, 105, 119, 111, 114, 100, 49, 48, 44, 32, 105, 119, 111, 114, 100, 49, 49, 44, 32, 105, 119, 111, 114, 100, 49, 50, 44, 32, 105, 119, 111, 114, 100, 49, 51, 44, 32, 105, 119, 111, 114, 100, 49, 52, 44, 32, 105, 119, 111, 114, 100, 49, 53, 44, 32, 46, 46, 46, 32, 93, 10, 70, 105, 110, 97, 108, 32, 115, 116, 97, 99, 107, 32, 115, 116, 97, 116, 101, 32, 58, 10, 91, 111, 119, 111, 114, 100, 48, 44, 32, 111, 119, 111, 114, 100, 49, 44, 32, 111, 119, 111, 114, 100, 50, 44, 32, 111, 119, 111, 114, 100, 51, 44, 32, 111, 119, 111, 114, 100, 52, 44, 32, 111, 119, 111, 114, 100, 53, 44, 32, 111, 119, 111, 114, 100, 54, 44, 32, 111, 119, 111, 114, 100, 55, 44, 32, 46, 46, 46, 32, 93, 10, 83, 101, 101, 32, 104, 116, 116, 112, 115, 58, 47, 47, 103, 105, 116, 104, 117, 98, 46, 99, 111, 109, 47, 105, 116, 122, 109, 101, 97, 110, 106, 97, 110, 47, 109, 101, 114, 107, 108, 105, 122, 101, 45, 115, 104, 97, 47, 98, 108, 111, 98, 47, 49, 100, 51, 53, 97, 97, 101, 57, 100, 97, 55, 102, 101, 100, 50, 48, 49, 50, 55, 52, 56, 57, 102, 51, 54, 50, 98, 52, 98, 99, 57, 51, 50, 52, 50, 97, 53, 49, 54, 99, 47, 105, 110, 99, 108, 117, 100, 101, 47, 107, 101, 99, 99, 97, 107, 95, 50, 53, 54, 46, 104, 112, 112, 35, 76, 50, 51, 50, 45, 76, 50, 53, 55, 1, 13, 0, 9, 0, 186, 0, 0, 0, 0, 0, 0, 0, 0, 211, 9, 0, 186, 0, 0, 0, 0, 0, 0, 0, 0, 211, 6, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 1, 0, 0, 0, 0, 0, 0, 0, 185, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 0, 0, 0, 0, 0, 0, 0, 0, 211, 10, 0]),
