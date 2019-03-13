use super::*;

const D1: [u8; XPRV_SIZE] = [
    0xf8, 0xa2, 0x92, 0x31, 0xee, 0x38, 0xd6, 0xc5, 0xbf, 0x71, 0x5d, 0x5b, 0xac, 0x21, 0xc7, 0x50,
    0x57, 0x7a, 0xa3, 0x79, 0x8b, 0x22, 0xd7, 0x9d, 0x65, 0xbf, 0x97, 0xd6, 0xfa, 0xde, 0xa1, 0x5a,
    0xdc, 0xd1, 0xee, 0x1a, 0xbd, 0xf7, 0x8b, 0xd4, 0xbe, 0x64, 0x73, 0x1a, 0x12, 0xde, 0xb9, 0x4d,
    0x36, 0x71, 0x78, 0x41, 0x12, 0xeb, 0x6f, 0x36, 0x4b, 0x87, 0x18, 0x51, 0xfd, 0x1c, 0x9a, 0x24,
    0x73, 0x84, 0xdb, 0x9a, 0xd6, 0x00, 0x3b, 0xbd, 0x08, 0xb3, 0xb1, 0xdd, 0xc0, 0xd0, 0x7a, 0x59,
    0x72, 0x93, 0xff, 0x85, 0xe9, 0x61, 0xbf, 0x25, 0x2b, 0x33, 0x12, 0x62, 0xed, 0xdf, 0xad, 0x0d,
];

const D1_H0: [u8; XPRV_SIZE] = [
    0x60, 0xd3, 0x99, 0xda, 0x83, 0xef, 0x80, 0xd8, 0xd4, 0xf8, 0xd2, 0x23, 0x23, 0x9e, 0xfd, 0xc2,
    0xb8, 0xfe, 0xf3, 0x87, 0xe1, 0xb5, 0x21, 0x91, 0x37, 0xff, 0xb4, 0xe8, 0xfb, 0xde, 0xa1, 0x5a,
    0xdc, 0x93, 0x66, 0xb7, 0xd0, 0x03, 0xaf, 0x37, 0xc1, 0x13, 0x96, 0xde, 0x9a, 0x83, 0x73, 0x4e,
    0x30, 0xe0, 0x5e, 0x85, 0x1e, 0xfa, 0x32, 0x74, 0x5c, 0x9c, 0xd7, 0xb4, 0x27, 0x12, 0xc8, 0x90,
    0x60, 0x87, 0x63, 0x77, 0x0e, 0xdd, 0xf7, 0x72, 0x48, 0xab, 0x65, 0x29, 0x84, 0xb2, 0x1b, 0x84,
    0x97, 0x60, 0xd1, 0xda, 0x74, 0xa6, 0xf5, 0xbd, 0x63, 0x3c, 0xe4, 0x1a, 0xdc, 0xee, 0xf0, 0x7a,
];

const MSG: &'static [u8] = b"Hello World";

const D1_H0_SIGNATURE: [u8; 64] = [
    0x90, 0x19, 0x4d, 0x57, 0xcd, 0xe4, 0xfd, 0xad, 0xd0, 0x1e, 0xb7, 0xcf, 0x16, 0x17, 0x80, 0xc2,
    0x77, 0xe1, 0x29, 0xfc, 0x71, 0x35, 0xb9, 0x77, 0x79, 0xa3, 0x26, 0x88, 0x37, 0xe4, 0xcd, 0x2e,
    0x94, 0x44, 0xb9, 0xbb, 0x91, 0xc0, 0xe8, 0x4d, 0x23, 0xbb, 0xa8, 0x70, 0xdf, 0x3c, 0x4b, 0xda,
    0x91, 0xa1, 0x10, 0xef, 0x73, 0x56, 0x38, 0xfa, 0x7a, 0x34, 0xea, 0x20, 0x46, 0xd4, 0xbe, 0x04,
];

fn compare_xprv(xprv: &[u8], expected_xprv: &[u8]) {
    assert_eq!(
        xprv[64..].to_vec(),
        expected_xprv[64..].to_vec(),
        "chain code"
    );
    assert_eq!(
        xprv[..64].to_vec(),
        expected_xprv[..64].to_vec(),
        "extended key"
    );
}

fn derive_xprv_eq(parent_xprv: &XPrv, idx: DerivationIndex, expected_xprv: [u8; 96]) {
    let child_xprv = parent_xprv.derive(DerivationScheme::V2, idx);
    compare_xprv(child_xprv.as_ref(), &expected_xprv);
}

fn do_sign(xprv: &XPrv, expected_signature: &[u8]) {
    let signature: Signature<Vec<u8>> = xprv.sign(MSG);
    assert_eq!(signature.as_ref(), expected_signature);
}

#[test]
fn xprv_sign() {
    let prv = XPrv::from_bytes_verified(D1_H0).unwrap();
    do_sign(&prv, &D1_H0_SIGNATURE);
}

#[test]
fn verify_signature() {
    let prv = XPrv::from_bytes_verified(D1_H0).unwrap();
    let xpub = prv.public();
    let sig: Signature<u8> = Signature::from_slice(&D1_H0_SIGNATURE).unwrap();
    assert_eq!(xpub.verify(MSG, &sig), true)
}

#[test]
fn xprv_derive() {
    let prv = XPrv::from_bytes_verified(D1).unwrap();
    derive_xprv_eq(&prv, 0x80000000, D1_H0);
}