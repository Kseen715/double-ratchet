
use aes::cipher::KeySizeUser;
use aes::cipher::BlockSizeUser;
use aes::Aes256;
// use cbc::{Cbc, BlockMode, block_padding::Pkcs7};
// use block_modes::BlockMode;
// use cipher::{BlockCipher, BlockEncrypt, BlockDecrypt}
use cbc;
use cipher::BlockEncryptMut;
use cipher::BlockDecryptMut;
use block_padding::Pkcs7;
use cipher::KeyInit;
use cipher::KeyIvInit;
use clear_on_drop::clear::Clear;
use hmac::digest::OutputSizeUser;
use ksi_double_ratchet::{self as dr, KeyPair as _};

use generic_array::{typenum::U32, GenericArray};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{CryptoRng, RngCore};
use rand_os::OsRng;
use sha2::Sha256;
use std::fmt;
use std::hash::{Hash, Hasher};
// use subtle::ConstantTimeEq;
use x25519_dalek::{self, SharedSecret};

pub type SignalDR = dr::DoubleRatchet<SignalCryptoProvider>;

pub struct SignalCryptoProvider;

impl dr::CryptoProvider for SignalCryptoProvider {
    type PublicKey = PublicKey;
    type KeyPair = KeyPair;
    type SharedSecret = SharedSecret;

    type RootKey = SymmetricKey;
    type ChainKey = SymmetricKey;
    type MessageKey = SymmetricKey;

    fn diffie_hellman(us: &KeyPair, them: &PublicKey) -> SharedSecret {
        us.private.diffie_hellman(&them.0)
    }

    fn kdf_rk(rk: &SymmetricKey, s: &SharedSecret) -> (SymmetricKey, SymmetricKey) {
        let salt = Some(rk.0.as_slice());
        let ikm = s.as_bytes();
        let prk = Hkdf::<Sha256>::new(salt, ikm);
        // let prk = Hkdf::<Sha256>::extract(salt, ikm);
        let info = &b"WhisperRatchet"[..];
        let mut okm = [0; 64];
        prk.expand(&info, &mut okm).unwrap();

        let rk = GenericArray::<u8, U32>::from_slice(&okm[..32]).clone();
        
        let ck = GenericArray::<u8, U32>::from_slice(&okm[32..]).clone();

        (SymmetricKey(rk), SymmetricKey(ck))
    }

    fn kdf_ck(ck: &SymmetricKey) -> (SymmetricKey, SymmetricKey) {
        let key = ck.0.as_slice();
        
        let mut mac = <Hmac::<Sha256> as KeyInit>::new_from_slice(key).unwrap();
        mac.update(&[0x01]);
        let mk = mac.finalize().into_bytes();

        // TODO: check if this is correct, and we should not recreate the mac 
        mac = <Hmac::<Sha256> as KeyInit>::new_from_slice(key).unwrap();
        mac.update(&[0x02]);
        let ck = mac.finalize().into_bytes();

        (SymmetricKey(ck), SymmetricKey(mk))
    }

    fn encrypt(key: &SymmetricKey, pt: &[u8], ad: &[u8]) -> Vec<u8> {
        let ikm = key.0.as_slice();
        let prk = Hkdf::<Sha256>::new(None, ikm);
        // let prk = Hkdf::<Sha256>::extract(None, ikm);
        let info = b"WhisperMessageKeys";
        let mut okm = [0; 80];
        prk.expand(info, &mut okm).unwrap();

        // let ek = GenericArray::<u8, <Aes256 as BlockCipher>::KeySize>::from_slice(&okm[..32]);
        let ek = GenericArray::<u8, <Aes256 as KeySizeUser>::KeySize>::from_slice(&okm[..32]);
        let mk = GenericArray::<u8, <Hmac<Sha256> as OutputSizeUser>::OutputSize>::from_slice(&okm[32..64]);
        // let iv = GenericArray::<u8, <Aes256 as BlockCipher>::BlockSize>::from_slice(&okm[64..]);
        let iv = GenericArray::<u8, <Aes256 as BlockSizeUser>::BlockSize>::from_slice(&okm[64..]);

        
        // let cipher = Cbc::<Aes256, Pkcs7>::new_fix(ek, iv);
        type Aes256CbcEnc = cbc::Encryptor::<Aes256>;
        let ciphr = Aes256CbcEnc::new(ek, iv);

        let mut mpt = pt.to_vec();
        let pt_len = pt.len();
        println!("pt: {:?}", pt);
        println!("pt: {:?}", pt_len);
        // resize the buffer to have enough space for message and padding
        mpt.resize(pt_len + 16 - (pt_len % 16), 0);
        // let ct = Aes128CbcEnc::new(&key.into(), &iv.into())
        // .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
        // .unwrap();

        let ciphertext = match ciphr
            .encrypt_padded_mut::<Pkcs7>(&mut mpt, pt_len) {
                Ok(encrypted) => encrypted,
                Err(e) => panic!("Error: {:?}", e)
            };
        // let mut ct = cipher.encrypt_vec(pt);

        let mut mac = <Hmac::<Sha256> as Mac>::new_from_slice(mk).unwrap();
        // let mut mac = Hmac::<Sha256>::new_varkey(mk).unwrap();
        mac.update(ad);
        mac.update(&ciphertext);
        let tag = mac.finalize().into_bytes();
        let mut ct_vec = ciphertext.to_vec();

        println!("Clear ct:");
        println!("ct: {:?}", ct_vec);
        println!("tag: {:?}", &tag[..8]);
        ct_vec.extend((&tag[..8]).into_iter());

        okm.clear();

        println!("ct: {:?}", ct_vec);

        ct_vec
    }

    fn decrypt(key: &SymmetricKey, ct: &[u8], ad: &[u8]) -> Result<Vec<u8>, dr::DecryptError> {
        let ikm = key.0.as_slice();
        let prk = Hkdf::<Sha256>::new(None, ikm);
        let info = b"WhisperMessageKeys";
        let mut okm = [0; 80];
        match prk.expand(info, &mut okm) {
            Ok(_) => (),
            Err(e) => panic!("Error: {:?}", e)
        };
        let dk = GenericArray::<u8, <Aes256 as KeySizeUser>::KeySize>::from_slice(&okm[..32]);
        let mk = GenericArray::<u8, <Hmac<Sha256> as OutputSizeUser>::OutputSize>::from_slice(&okm[32..64]);
        let iv = GenericArray::<u8, <Aes256 as BlockSizeUser>::BlockSize>::from_slice(&okm[64..]);

        println!("ct: {:?}", ct);
        let ct_len_wo_tag = ct.len() - 8;
        println!("ct_len_wo_tag: {:?}", ct_len_wo_tag);
        let mut mac = match <Hmac::<Sha256> as Mac>::new_from_slice(mk) {
            Ok(mac) => mac,
            Err(e) => panic!("Error: {:?}", e)
        };
        mac.update(ad);
        mac.update(&ct[..ct_len_wo_tag]);
        let tag = mac.finalize().into_bytes();

        // if bool::from(!(&tag.as_ref()[..8]).ct_eq(&ct[ct_len..])) {
        // This seems like a better way to compare the two slices??
        // println!("tag: {:?}", &tag.as_ref()[..8]);
        println!("tag: {:?}", &tag[..8]);
        println!("ct: {:?}", &ct[(ct_len_wo_tag)..]);

        if bool::from(!((&tag[..8]) == (&ct[ct_len_wo_tag..]))) {
            okm.clear();
            println!("Error: {:?}", dr::DecryptError::DecryptFailure);
            return Err(dr::DecryptError::DecryptFailure);
        }

        type Aes256CbcDec = cbc::Decryptor::<Aes256>;
        let ciphr = Aes256CbcDec::new(dk, iv);

        let mut ct_vec = ct[..ct_len_wo_tag].to_vec();
        
        println!("ct_vec: {:?}", ct_vec);

        return match ciphr
            .decrypt_padded_mut::<Pkcs7>(&mut ct_vec) {
                Ok(pt) => {
                    okm.clear();
                    println!("pt: {:?}", pt);
                    Ok(pt.to_vec())
                },
                Err(e) => {
                    okm.clear();
                    println!("Error: {:?}", e);
                    Err(dr::DecryptError::DecryptFailure)
                }
            };
    }
}

#[derive(Clone, Debug)]
pub struct PublicKey(x25519_dalek::PublicKey);

impl Eq for PublicKey {}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.0.as_bytes() == other.0.as_bytes()
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_bytes().hash(state);
    }
}

impl<'a> From<&'a x25519_dalek::StaticSecret> for PublicKey {
    fn from(private: &'a x25519_dalek::StaticSecret) -> PublicKey {
        PublicKey(x25519_dalek::PublicKey::from(private))
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

pub struct KeyPair {
    private: x25519_dalek::StaticSecret,
    public: PublicKey,
}

impl fmt::Debug for KeyPair {
    #[cfg(debug_assertions)]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "KeyPair {{ private (bytes): {:?}, public: {:?} }}",
            self.private.to_bytes(),
            self.public
        )
    }

    #[cfg(not(debug_assertions))]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "KeyPair {{ private (bytes): <hidden bytes>, public: {:?} }}",
            self.public
        )
    }
}

impl dr::KeyPair for KeyPair {
    type PublicKey = PublicKey;

    fn new<R: CryptoRng + RngCore>(rng: &mut R) -> KeyPair {
        let private = x25519_dalek::StaticSecret::new(rng);
        let public = PublicKey::from(&private);
        KeyPair { private, public }
    }

    fn public(&self) -> &PublicKey {
        &self.public
    }
}

#[derive(Default)]
pub struct SymmetricKey(GenericArray<u8, U32>);

impl fmt::Debug for SymmetricKey {
    #[cfg(debug_assertions)]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SymmetricKey({:?})", self.0)
    }

    #[cfg(not(debug_assertions))]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SymmetricKey(<hidden bytes>)")
    }
}

impl Drop for SymmetricKey {
    fn drop(&mut self) {
        self.0.clear();
    }
}

#[test]
fn signal_session() {
    let mut rng = OsRng::new().unwrap();
    let (ad_a, ad_b) = (b"A2B:SessionID=42", b"B2A:SessionID=42");

    // Copy some values (these are usually the outcome of an X3DH key exchange)
    let bobs_prekey = KeyPair::new(&mut rng);
    let bobs_public_prekey = bobs_prekey.public().clone();
    let shared = SymmetricKey(GenericArray::<u8, U32>::clone_from_slice(
        b"Output of a X3DH key exchange...",
    ));

    // Alice fetches Bob's prekey bundle and completes her side of the X3DH handshake
    let mut alice = SignalDR::new_alice(&shared, bobs_public_prekey, None, &mut rng);
    // Alice creates her first message to Bob
    let pt_a_0 = b"Hello Bob";
    let (h_a_0, ct_a_0) = alice.ratchet_encrypt(pt_a_0, ad_a, &mut rng);
    // Alice creates an initial message containing `h_a_0`, `ct_a_0` and other X3DH information

    // Bob receives the message and finishes his side of the X3DH handshake
    let mut bob = SignalDR::new_bob(shared, bobs_prekey, None);
    // Bob can now decrypt the initial message

    assert_eq!(
        Ok(Vec::from(&b"Hello Bob"[..])),
        bob.ratchet_decrypt(&h_a_0, &ct_a_0, ad_a)
    );
    // Bob is now fully initialized: both sides can send and receive message

    let pt_a_1 = b"I will send this later";
    let (h_a_1, ct_a_1) = alice.ratchet_encrypt(pt_a_1, ad_a, &mut rng);
    let pt_b_0 = b"My first reply";
    let (h_b_0, ct_b_0) = bob.ratchet_encrypt(pt_b_0, ad_b, &mut rng);
    assert_eq!(
        Ok(Vec::from(&pt_b_0[..])),
        alice.ratchet_decrypt(&h_b_0, &ct_b_0, ad_b)
    );
    let pt_a_2 = b"What a boring conversation";
    let (h_a_2, _ct_a_2) = alice.ratchet_encrypt(pt_a_2, ad_a, &mut rng);
    let pt_a_3 = b"Don't you agree?";
    let (h_a_3, ct_a_3) = alice.ratchet_encrypt(pt_a_3, ad_a, &mut rng);
    assert_eq!(
        Ok(Vec::from(&pt_a_3[..])),
        bob.ratchet_decrypt(&h_a_3, &ct_a_3, ad_a)
    );

    let pt_b_1 = b"Agree with what?";
    let (h_b_1, ct_b_1) = bob.ratchet_encrypt(pt_b_1, ad_b, &mut rng);
    assert_eq!(
        Ok(Vec::from(&pt_b_1[..])),
        alice.ratchet_decrypt(&h_b_1, &ct_b_1, ad_b)
    );

    assert_eq!(
        Ok(Vec::from(&pt_a_1[..])),
        bob.ratchet_decrypt(&h_a_1, &ct_a_1, ad_a)
    );

    // No resending (that key is already deleted)
    assert!(bob.ratchet_decrypt(&h_a_1, &ct_a_1, ad_a).is_err());
    // No fake messages
    assert!(bob
        .ratchet_decrypt(&h_a_2, b"Incorrect ciphertext", ad_a)
        .is_err());
}
