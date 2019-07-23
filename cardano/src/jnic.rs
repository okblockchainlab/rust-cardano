// This is the interface to the JVM that we'll
// call the majority of our methods on.
use jni::JNIEnv;

// These objects are what you should use as arguments to your native function.
// They carry extra lifetime information to prevent them escaping this context
// and getting used after being GC'd.
use jni::objects::{JClass, JString};

// This is just a pointer. We'll be returning it from our function.
// We can't return one of the objects with lifetime information because the
// lifetime checker won't let us.
use jni::sys::{jstring, jbyteArray};

//use std::thread;
//use std::time::Duration;
//use std::sync::mpsc;
use hdwallet;
use address::{ExtendedAddr, AddrType, SpendingData, Attributes};
use config::{ProtocolMagic};
use util::{base58, try_from_slice::TryFromSlice};
use tx::{Tx, TxoPointer, TxId, TxOut, TxAux, TxWitness, TxInWitness};
use hex;
use coin::Coin;
use chain_core::property::{Serialize, Deserialize};
//use core::num::flt2dec::strategy::grisu::max_pow10_no_more_than;
use hdwallet::XPrv;
use std::collections::HashMap;
use hdpayload::HDAddressPayload;

fn slice_to_seed(bytes: &[u8]) -> [u8; hdwallet::SEED_SIZE] {
    let mut array = [0; hdwallet::SEED_SIZE];
    let bytes = &bytes[..array.len()]; // panics if not enough data
    array.copy_from_slice(bytes);
    array
}

fn slice_to_pri(bytes: &[u8]) -> [u8; hdwallet::XPRV_SIZE] {
    let mut array = [0; hdwallet::XPRV_SIZE];
    let bytes = &bytes[..array.len()]; // panics if not enough data
    array.copy_from_slice(bytes);
    array
}

fn slice_to_pub(bytes: &[u8]) -> [u8; hdwallet::XPUB_SIZE] {
    let mut array = [0; hdwallet::XPUB_SIZE];
    let bytes = &bytes[..array.len()]; // panics if not enough data
    array.copy_from_slice(bytes);
    array
}

// This keeps rust from "mangling" the name and making it unique for this crate.
#[no_mangle]
// This turns off linter warnings because
// the name doesn't conform to conventions.
#[allow(non_snake_case)]
pub extern "system" fn Java_AdaNative_GeneratePrivKey(env: JNIEnv,
                                                      // this is the class that owns our
                                                      // static method. Not going to be
                                                      // used, but still needs to have
                                                      // an argument slot
                                                      _class: JClass,
                                                      input: jbyteArray)
                                                      -> jstring {
    // First, we have to get the string out of java. Check out the `strings`
    // module for more info on how this works.
    let inputBytes = env.convert_byte_array(input).unwrap();
    if inputBytes.len() != hdwallet::SEED_SIZE {
        return env.new_string(format!("Error: length of seed must be {}", hdwallet::SEED_SIZE)).unwrap().into_inner();
    }

    let seed = hdwallet::Seed::from_bytes(slice_to_seed(inputBytes.as_slice()));
    let sk = hdwallet::XPrv::generate_from_seed(&seed);

    let output = env.new_string(format!("{}", sk)).unwrap();
    output.into_inner()
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_AdaNative_GeneratePubKey(env: JNIEnv,
                                                     _class: JClass,
                                                     input: jbyteArray)
                                                     -> jstring {
    let inputBytes = env.convert_byte_array(input).unwrap();
    if inputBytes.len() != hdwallet::XPRV_SIZE {
        return env.new_string(format!("Error: length of private key must be {}", hdwallet::XPRV_SIZE)).unwrap().into_inner();
    }
    let sk = hdwallet::XPrv::from_bytes(slice_to_pri(inputBytes.as_slice()));
    let pk = sk.public();
    let output = env.new_string(format!("{}", pk)).unwrap();
    output.into_inner()
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_AdaNative_GenerateAddr(env: JNIEnv,
                                                   _class: JClass,
                                                   input: jbyteArray,
                                                   payload: JString)
                                                   -> jstring {
    let inputBytes = env.convert_byte_array(input).unwrap();
    if inputBytes.len() != hdwallet::XPUB_SIZE {
        env.new_string(format!("Error: length of private key must be {}", hdwallet::XPRV_SIZE)).unwrap().into_inner();
    }
    let hdapStr: String = env.get_string(payload).expect("Error: Couldn't get payload!").into();

    let pk = hdwallet::XPub::from_bytes(slice_to_pub(inputBytes.as_slice()));
    let hdapArr = hex::decode(hdapStr);
    let hdapArr = match hdapArr {
        Ok(hdapArr) => hdapArr,
        Err(error) => {
            return env.new_string(format!("Error: hex decode payload error: {}", error.to_string())).unwrap().into_inner();
        }
    };
    let hdap = HDAddressPayload::from_bytes(hdapArr.as_slice());
    let addr_type = AddrType::ATPubKey;
    let sd = SpendingData::PubKeyASD(pk.clone());
    let attrs = Attributes::new_bootstrap_era( Some(hdap), ProtocolMagic::default().into());

    let ea = ExtendedAddr::new(addr_type, sd, attrs);

    let addr = cbor!(ea).unwrap();
    let addrStr = base58::encode(&addr);
    let output = env.new_string(format!("{}", addrStr)).unwrap();
    output.into_inner()
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_AdaNative_GenRawTx(env: JNIEnv,
                                               _class: JClass,
                                               inputs: JString,
                                               outputs: JString)
                                               -> jstring {
    let inputStr: String = env.get_string(inputs).expect("Error: Couldn't get java string!").into();
    let outStr: String = env.get_string(outputs).expect("Error: Couldn't get java string!").into();

    let txIns = handle_inputs(inputStr);
    let txIns = match txIns {
        Ok(txIns) => txIns,
        Err(error) => {
            return env.new_string(error.as_str()).unwrap().into_inner();
        }
    };

    let txOuts = handle_outputs(outStr);
    let txOuts = match txOuts {
        Ok(txOuts) => txOuts,
        Err(error) => {
            return env.new_string(error.as_str()).unwrap().into_inner();
        }
    };

    let tx = Tx::new_with(txIns, txOuts);
    let txSerial = tx.serialize_as_vec().unwrap();
    let bufStr = hex::encode(txSerial);
    let output = env.new_string(format!("{}", bufStr)).unwrap();
    // Finally, extract the raw pointer to return.
    output.into_inner()
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_AdaNative_SignRawTx(env: JNIEnv,
                                                _class: JClass,
                                                rawTx: jbyteArray,
                                                priKeys: JString)
                                                -> jstring {
    // First, we have to get the byte[] out of java.
    let input = env.convert_byte_array(rawTx).unwrap();
    // deserialize byte to raw tx
    let raw = Tx::deserialize(&input[..]);
    let raw = match raw {
        Ok(raw) => raw,
        Err(_error) => {
            return env.new_string("Error: deserialize tx failed!").unwrap().into_inner();
        }
    };
    let txIns = raw.clone().inputs;
    let txInsCntFromRwaTx = txIns.len();

    // parse private keys
    let priKeysStr: String = env.get_string(priKeys).expect("Error: Couldn't get java string!").into();
    let mut iterPriKeys = priKeysStr.split_ascii_whitespace();
    let iterPriCnt = iterPriKeys.clone().count();
    if iterPriCnt == 0 || (iterPriCnt % 2 != 0) {
        return env.new_string("Error: priKeys does not match format").unwrap().into_inner();
    }
    let mut pri_cnt = iterPriCnt / 2;
    // the value txPriTxInCnt store the count of txIns needed to be signed using key(Private key)
    let mut txPriTxInCnt: HashMap<XPrv, usize> = HashMap::new();
    let mut allTxInCnt: usize = 0;
    while pri_cnt > 0 {
        let priStr = iterPriKeys.next().unwrap();
        let priArr = hex::decode(priStr);
        let priArr = match priArr {
            Ok(priArr) => priArr,
            Err(_error) => {
                return env.new_string("Error: private key decode failed!").unwrap().into_inner();
            }
        };
        let priKey = XPrv::from_bytes(slice_to_pri(priArr.as_slice()));

        // txInCnt is the count of txins which are composed of private key's utxo.
        let txInCnt = iterPriKeys.next().unwrap().parse::<usize>();
        let txInCnt = match txInCnt {
            Ok(txInCnt) => txInCnt,
            Err(_error) => {
                return env.new_string("Error: parse count of txins failed!").unwrap().into_inner();
            }
        };
        txPriTxInCnt.insert(priKey, txInCnt);
        pri_cnt -= 1;
        allTxInCnt += txInCnt;
    }

    if allTxInCnt != txInsCntFromRwaTx {
        return env.new_string(format!("Error: private keys do not match the count of txins in raw tx! {}, {}",
                                      allTxInCnt, txInsCntFromRwaTx)).unwrap().into_inner();
    }

    let mut txWitness = TxWitness::new();
    let mut txInsIndex: usize = 0;
    for (key, value) in txPriTxInCnt {
        let mut val = value;
        while val > 0 {
            let txInWit = TxInWitness::new_extended_pk(ProtocolMagic::default(), &key, &txIns[txInsIndex].id);
            txWitness.push(txInWit);
            val -= 1;
            txInsIndex += 1;
        }
    }
    let txWithSign = TxAux::new(raw, txWitness);
    let txWithSignArr = txWithSign.serialize_as_vec().unwrap();
    let bufStr = hex::encode(txWithSignArr);
    let output = env.new_string(format!("{}", bufStr)).unwrap();
    output.into_inner()
}

#[no_mangle]
#[allow(non_snake_case)]
pub fn handle_inputs(inputs: String) -> Result<Vec<TxoPointer>, String> {
    let mut iterIn = inputs.split_ascii_whitespace();
    let iterCnt = iterIn.clone().count();
    if iterCnt == 0 {
        return Err(String::from("Error: input does not match format"));
        // return env.new_string(format!("Error: length of input can not be zero")).unwrap().into_inner();
    }

    let input_cnt = iterIn.next().unwrap().parse::<usize>();
    let mut input_cnt = match input_cnt {
        Ok(input_cnt) => input_cnt,
        Err(_error) => {
            return Err(String::from("Error: input does not match format"));
            // return env.new_string(format!("Error: input does not match format")).unwrap().into_inner();
        }
    };
    if (2 * input_cnt + 1) != iterCnt {
        return Err(String::from("Error: input does not match format"));
        // return env.new_string(format!("Error: input does not match format")).unwrap().into_inner();
    }

    let mut txIns: Vec<TxoPointer> = Vec::new();
    while input_cnt > 0 {
        let txIdStr = iterIn.next().unwrap();
        let txIdArr = hex::decode(txIdStr);
        let txIdArr = match txIdArr {
            Ok(txIdArr) => txIdArr,
            Err(_error) => {
                return Err(String::from("Error: TxId decode failed!"));
                // return env.new_string(format!("Error: TxId decode failed!")).unwrap().into_inner();
            }
        };
        let txId = TxId::new(&txIdArr);
        let index = iterIn.next().unwrap().parse::<u32>();
        let index = match index {
            Ok(index) => index,
            Err(_error) => {
                return Err(String::from("Error: input does not match format"));
                // return env.new_string(format!("Error: input does not match format")).unwrap().into_inner();
            }
        };
        let txin = TxoPointer::new(txId, index);
        txIns.push(txin);
        input_cnt -= 1;
    }
    Ok(txIns)
}

#[no_mangle]
#[allow(non_snake_case)]
pub fn handle_outputs(outputs: String) -> Result<Vec<TxOut>, String> {
    let mut iterOut = outputs.split_ascii_whitespace();
    let iterCnt = iterOut.clone().count();
    if iterCnt == 0 || (iterCnt % 2 != 0) {
        return Err(String::from("Error: outputs does not match format"));
        // return env.new_string(format!("Error: length of input can not be zero")).unwrap().into_inner();
    }

    let mut txOuts: Vec<TxOut> = Vec::new();
    let mut output_cnt = iterCnt / 2;
    while output_cnt > 0 {
        let addrStr = iterOut.next().unwrap();
        let addrArr = base58::decode(addrStr);
        let addrArr = match addrArr {
            Ok(addrArr) => addrArr,
            Err(_error) => {
                return Err(String::from("Error: address decode failed!"));
            }
        };
        let ea = ExtendedAddr::try_from_slice(&addrArr[..]);
        let ea = match ea {
            Ok(ea) => ea,
            Err(_error) => {
                return Err(String::from("Error: ExtendedAddr::try_from_slice failed!"));
            }
        };
        let coin = iterOut.next().unwrap().parse::<Coin>();
        let coin = match coin {
            Ok(coin) => coin,
            Err(_error) => {
                return Err(String::from("Error: parse coin failed!"));
                // return env.new_string(format!("Error: input does not match format")).unwrap().into_inner();
            }
        };
        let txout = TxOut::new(ea, coin);
        txOuts.push(txout);
        output_cnt -= 1;
    }
    Ok(txOuts)
}

#[cfg(test)]
mod tests {
    use jnic::*;

    #[test]
    fn test_handle_outpust() {
        let outputs = String::from("Ae2tdPwUPEZAdB5HtX7PGhaGnbdotXKV8uMme7nMjoQMH4ALhLcvpdfRE7H 100000 Ae2tdPwUPEZNHYBwkYWW4ZwpEAEiA8B7pnPYecvf6SLXpesPWguLKUJtWL8 140000");
        let res = handle_outputs(outputs);
        let res = match res {
            Ok(res) => {
                print!("succeed!!!!!!!!!!");
            }
            Err(error) => {
                print!("{}", error);
            }
        };
    }
}

