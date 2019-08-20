
extern crate cardano;
extern crate hex;
extern crate cbor_event;

use cardano::address::{ExtendedAddr, AddrType, SpendingData, Attributes, StakeDistribution};
use cardano::hdwallet;
use cardano::config::{ProtocolMagic, NetworkMagic};
use cardano::hdpayload::HDAddressPayload;
use cardano::util::base58;
use cbor_event::cbor;
use cardano::jnic::handle_inputs;

fn slice_to_pub(bytes: &[u8]) -> [u8; hdwallet::XPUB_SIZE] {
    let mut array = [0; hdwallet::XPUB_SIZE];
    let bytes = &bytes[..array.len()]; // panics if not enough data
    array.copy_from_slice(bytes);
    array
}

fn main() {
    let seed = hdwallet::Seed::from_bytes([0; hdwallet::SEED_SIZE]);
    let sk = hdwallet::XPrv::generate_from_seed(&seed);
    let pk = sk.public();

    let hdap = HDAddressPayload::from_bytes(hex::decode("9f2afb7740db15685a237bd799c1c46c0439d35ef50c4fda7fbc0775").unwrap().as_slice());
    let addr_type = AddrType::ATPubKey;
    let sd = SpendingData::PubKeyASD(pk.clone());
    let attrs = Attributes::new_bootstrap_era( Some(hdap), NetworkMagic::NoMagic);

    let ea = ExtendedAddr::new(addr_type, sd, attrs);

    let out = ea.to_address();

//    print!("{}\n", format!("{}", &out));
    let inputs  = String::from("1 08a37e190c5a99691098b615e31c91c10636ac43dab308c74f80d5f214e88f0a 1");
    handle_inputs(inputs);
}