use openssl::symm::{Cipher, Crypter, Mode};

pub fn polyfill(text: &[u8]) -> [u8; 16] {
    let mut new_text: [u8; 16] = [0; 16];
    if text.len() < 16 {
        for i in 0..text.len() {
            new_text[i] = text[i];
        }
    }
    new_text
}

pub fn encrypt(plaintext: String, key: &[u8]) -> String {
    let plaintext = polyfill(plaintext.as_bytes());

    let data_len = plaintext.len();
    let mut encrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, &key, None).unwrap();

    encrypter.pad(false);

    let block_size = Cipher::aes_128_ecb().block_size();
    let mut ciphertext = vec![0; data_len + block_size];

    let mut count = encrypter.update(&plaintext, &mut ciphertext).unwrap();
    count += encrypter.finalize(&mut ciphertext[count..]).unwrap();
    ciphertext.truncate(count);

    let base64_ciphertext = base64::encode(ciphertext);

    #[cfg(debug_assertions)]
    println!("encrypt:{:#?}", base64_ciphertext);

    base64_ciphertext
}

pub fn decrypt(ciphertext: String, key: &[u8]) -> Vec<u8> {
    let ciphertext = base64::decode(ciphertext).unwrap();

    let data_len = ciphertext.len();

    let block_size = Cipher::aes_128_ecb().block_size();
    let mut decrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, &key, None).unwrap();

    decrypter.pad(false);

    let mut plaintext = vec![0; data_len + block_size];

    let mut count = decrypter.update(&ciphertext, &mut plaintext).unwrap();

    count += decrypter.finalize(&mut plaintext[count..]).unwrap();
    plaintext.truncate(count);

    #[cfg(debug_assertions)]
    println!("decrypt:{:#?}", plaintext);

    plaintext
}

fn main() {
    let plaintext = "5VxBQ".to_string();
    let key = polyfill("jkkhfvbbedgm".as_bytes());

    let ciphertext = encrypt(plaintext, &key);

    let plaintext = decrypt(ciphertext, &key);

    let password = String::from_utf8(plaintext).unwrap();
    println!("password:{}", password);
}
