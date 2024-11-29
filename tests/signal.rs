use aes::cipher::{BlockSizeUser, KeySizeUser};
use aes::Aes256;
use block_padding::Pkcs7;
use cbc;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit};
use clear_on_drop::clear::Clear;
use generic_array::{typenum::U32, GenericArray};
use hkdf::Hkdf;
use hmac::digest::OutputSizeUser;
use hmac::{Hmac, Mac};
use ksi_double_ratchet::{self as dr, KeyPair as _};
use rand_core::{CryptoRng, RngCore};
use rand_os::OsRng;
use sha2::Sha256;
use std::fmt;
use std::hash::{Hash, Hasher};
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
        let salt: Option<&[u8]> = Some(rk.0.as_slice());
        let input_key_material: &[u8; 32] = s.as_bytes();
        let pseudo_random_key = Hkdf::<Sha256>::new(salt, input_key_material);

        let info = &b"WhisperRatchet"[..];
        let mut output_key_material = [0; 64];
        pseudo_random_key.expand(&info, &mut output_key_material).unwrap();

        let root_key: GenericArray<u8, _> = GenericArray::<u8, U32>::from_slice(&output_key_material[..32]).clone();

        let chain_key: GenericArray<u8, _> =
            GenericArray::<u8, U32>::from_slice(&output_key_material[32..]).clone();

        return (SymmetricKey(root_key), SymmetricKey(chain_key))
    }

    fn kdf_ck(ck: &SymmetricKey) -> (SymmetricKey, SymmetricKey) {
        let key = ck.0.as_slice();

        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
        mac.update(&[0x01]);
        let message_key = mac.finalize().into_bytes();

        // TODO: [Kseen] check if this is correct, and we should not recreate the mac
        mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
        mac.update(&[0x02]);
        let chain_key = mac.finalize().into_bytes();

        return (SymmetricKey(chain_key), SymmetricKey(message_key))
    }

    fn encrypt(key: &SymmetricKey, pt: &[u8], ad: &[u8]) -> Vec<u8> {
        let input_key_material = key.0.as_slice();
        let pseudo_random_key = Hkdf::<Sha256>::new(None, input_key_material);

        let info = b"WhisperMessageKeys";
        let mut output_key_material = [0; 80];
        pseudo_random_key.expand(info, &mut output_key_material).unwrap();

        let encryption_key = GenericArray::<u8, <Aes256 as KeySizeUser>::KeySize>::from_slice(&output_key_material[..32]);
        let message_key = GenericArray::<u8, <Hmac<Sha256> as OutputSizeUser>::OutputSize>::from_slice(
            &output_key_material[32..64],
        );
        let iv = GenericArray::<u8, <Aes256 as BlockSizeUser>::BlockSize>::from_slice(&output_key_material[64..]);

        type Aes256CbcEnc = cbc::Encryptor<Aes256>;
        let ciphr = Aes256CbcEnc::new(encryption_key, iv);

        let mut mod_plaintext = pt.to_vec();
        let plaintext_len = pt.len();

        mod_plaintext.resize(plaintext_len + 16 - (plaintext_len % 16), 0);

        let ciphertext = match ciphr.encrypt_padded_mut::<Pkcs7>(&mut mod_plaintext, plaintext_len) {
            Ok(encrypted) => encrypted,
            Err(e) => panic!("Error: {:?}", e),
        };

        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(message_key).unwrap();
        
        mac.update(ad);
        mac.update(&ciphertext);

        let tag = mac.finalize().into_bytes();
        let mut ciphertext_vec = ciphertext.to_vec();

        ciphertext_vec.extend((&tag[..8]).into_iter());

        output_key_material.clear();

        println!("ct: {:?}", ciphertext_vec);

        ciphertext_vec
    }

    fn decrypt(key: &SymmetricKey, ct: &[u8], ad: &[u8]) -> Result<Vec<u8>, dr::DecryptError> {
        let input_key_material = key.0.as_slice();
        let pseudo_random_key = Hkdf::<Sha256>::new(None, input_key_material);
        let info = b"WhisperMessageKeys";
        let mut output_key_material = [0; 80];
        match pseudo_random_key.expand(info, &mut output_key_material) {
            Ok(_) => (),
            Err(e) => panic!("Error: {:?}", e),
        };
        let decryption_key = GenericArray::<u8, <Aes256 as KeySizeUser>::KeySize>::from_slice(&output_key_material[..32]);
        let message_key = GenericArray::<u8, <Hmac<Sha256> as OutputSizeUser>::OutputSize>::from_slice(
            &output_key_material[32..64],
        );
        let iv = GenericArray::<u8, <Aes256 as BlockSizeUser>::BlockSize>::from_slice(&output_key_material[64..]);

        let ciphertext_len = ct.len() - 8;

        let mut mac = match <Hmac<Sha256> as Mac>::new_from_slice(message_key) {
            Ok(mac) => mac,
            Err(e) => panic!("Error: {:?}", e),
        };

        mac.update(ad);
        mac.update(&ct[..ciphertext_len]);
        
        let tag = mac.finalize().into_bytes();

        if bool::from(!((&tag[..8]) == (&ct[ciphertext_len..]))) {
            output_key_material.clear();
            println!("Error: {:?}", dr::DecryptError::DecryptFailure);
            return Err(dr::DecryptError::DecryptFailure);
        }

        type Aes256CbcDec = cbc::Decryptor<Aes256>;
        let ciphr = Aes256CbcDec::new(decryption_key, iv);

        let mut ciphertext_vec = ct[..ciphertext_len].to_vec();

        return match ciphr.decrypt_padded_mut::<Pkcs7>(&mut ciphertext_vec) {
            Ok(pt) => {
                output_key_material.clear();
                println!("pt: {:?}", pt);
                Ok(pt.to_vec())
            }
            Err(e) => {
                output_key_material.clear();
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
    let (ad_a, ad_b) = (b"A2B:SessionID=42", b"B2A:SessionID=42"); // Authentication data

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
