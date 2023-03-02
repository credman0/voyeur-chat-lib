use num_bigint::{BigInt, ToBigInt, Sign};
use num_primes::{Generator};
use num_traits::identities::{One, Zero};
use num_integer::Integer;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let first_key = generate_key_pair();
        let second_key = generate_key_pair();
        let group = Group::new(vec![first_key.pub_key.clone(), second_key.pub_key.clone()]);
        let plaintext = "Hello, world!".as_bytes().to_vec();
        println!("Plaintext: {:?}",&plaintext);
        let msg = group.encrypt_msg(&plaintext);
        println!("Group encrypted message: {}", msg);
        let decrypted = first_key.decrypt(&msg);
        assert!(&decrypted == &plaintext);
        assert!(first_key.decrypt(&msg) == second_key.decrypt(&msg));
        let targeted = group.encrypt_targeted(&plaintext, &first_key.pub_key);
        println!("Targeted encrypted message: {}", targeted);
        assert!(&first_key.decrypt(&targeted) != &plaintext);
        println!("Second decrypt {:?}", second_key.decrypt(&targeted));
        assert!(&second_key.decrypt(&targeted) == &plaintext);
    }
}

/// A key for a particular member of the group.
/// Derives clone, debug, and display traits.
#[derive(Clone, Debug)]
pub struct PubKey {
    pub exponent: BigInt,
    pub modulus: BigInt,
}

/// Comparison trait for keys.
impl PartialEq for PubKey {
    fn eq(&self, other: &Self) -> bool {
        self.exponent == other.exponent && self.modulus == other.modulus
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct KeyPair {
    pub pub_key: PubKey,
    pub priv_key: BigInt,
}

/// Allow KeyPair to decrypt messages.
impl KeyPair {
    pub fn decrypt(&self, msg: &BigInt) -> Vec<u8> {
        let msg = msg%&self.pub_key.modulus;
        let msg = msg.modpow(&self.priv_key, &self.pub_key.modulus);
        // Convert back to a byte vector
        let mut msg_bytes = msg.to_bytes_be().1;
        // Remove any leading zeros
        while msg_bytes[0] == 0 {
            msg_bytes.remove(0);
        }
        msg_bytes
    }
}

/// Generate two large primes.
pub fn generate_primes() -> (BigInt, BigInt) {
    let p =  Generator::new_prime(512).to_bigint().unwrap();
    let q =  Generator::new_prime(512).to_bigint().unwrap();
    (p, q)
}

fn modinv(n: &BigInt, p: &BigInt) -> BigInt {
    if p.is_one() { return BigInt::one() }

    // let (mut a, mut m, mut x, mut inv) = (n.into(), p.clone(), BigInt::zero(), BigInt::one());
    // Rewrite with assignments on their own line to avoid borrow checker issues
    let mut a:BigInt = n.clone();
    let mut m = p.clone();
    let mut x = BigInt::zero();
    let mut inv = BigInt::one();

    while a > BigInt::one() {
        let (div, rem) = a.div_rem(&m);
        inv -= div * &x;
        a = rem;
        std::mem::swap(&mut a, &mut m);
        std::mem::swap(&mut x, &mut inv);
    }

    while inv < BigInt::zero() { inv += p }

    inv
}

/// Create a public and private key pair by generating two large primes and finding the decryption exponent.
pub fn generate_key_pair() -> KeyPair {
    let (p, q) = generate_primes();
    let n = &p * &q;
    let phi = (&p - 1u32) * (&q - 1u32);
    let e = BigInt::from(65537u32);
    let d = modinv(&e, &phi);
    let pub_key = PubKey {
        exponent: e,
        modulus: n,
    };
    KeyPair {
        pub_key,
        priv_key: d,
    }
}

/// A group of members.
pub struct Group {
    pub keys: Vec<PubKey>,
}

impl Group {
    /// Create a new group with the given keys.
    pub fn new(keys: Vec<PubKey>) -> Self {
        Group { keys }
    }

    /// Check if a key is in the group.
    pub fn contains_key(&self, key: &PubKey) -> bool {
        self.keys.contains(key)
    }

    /// Add a new key to the group.
    pub fn add_key(&mut self, key: PubKey) {
        self.keys.push(key);
    }

    /// Remove a key from the group.
    pub fn remove_key(&mut self, key: &PubKey) {
        self.keys.retain(|k| k != key);
    }

    fn encrypt_msg(&self, msg:&Vec<u8>) -> BigInt {
        let msg = BigInt::from_bytes_be(Sign::Plus, msg);
        let msg_vec:Vec<BigInt> = self.keys.iter().map(|key| encrypt(&msg, key)).collect();
        // Collect the moduli into a vector
        let moduli:Vec<BigInt> = self.keys.iter().map(|key| key.modulus.clone()).collect();
        let result = ring_algorithm::chinese_remainder_theorem(&msg_vec, &moduli).unwrap();

        for (u, m) in msg_vec.iter().zip(moduli.iter()) {
            assert_eq!((&result - u) % m, BigInt::from(0));
        }
        let total_modulus = moduli.iter().fold(BigInt::one(), |acc, x| acc * x);
        // Make sure the result is positive
        return (result % &total_modulus) + &total_modulus;
    }

    // Like normal encryption, but the target is not included in the encryption.
    pub fn encrypt_targeted(&self, msg:&Vec<u8>, target:&PubKey) -> BigInt {
        let msg = BigInt::from_bytes_be(Sign::Plus, msg);
        let msg_vec:Vec<BigInt> = self.keys.iter().filter(|key| key != &target).map(|key| encrypt(&msg, key)).collect();
        // Collect the moduli into a vector
        let moduli:Vec<BigInt> = self.keys.iter().filter(|key| key != &target).map(|key| key.modulus.clone()).collect();
        let result = ring_algorithm::chinese_remainder_theorem(&msg_vec, &moduli).unwrap();

        for (u, m) in msg_vec.iter().zip(moduli.iter()) {
            assert_eq!((&result - u) % m, BigInt::from(0));
        }
        let total_modulus = moduli.iter().fold(BigInt::one(), |acc, x| acc * x);
        // Make sure the result is positive
        return (result % &total_modulus) + &total_modulus;
    }
}

/// Encrypt a message with the given key.
pub fn encrypt(msg: &BigInt, key: &PubKey) -> BigInt {
    msg.modpow(&key.exponent, &key.modulus)
}

