use openssl::symm::{self, Cipher, Crypter};

pub fn polyfill(text: &[u8]) -> [u8; 16] {
    let mut new_text: [u8; 16] = [0; 16];
    if text.len() < 16 {
        for i in 0..text.len() {
            new_text[i] = text[i];
        }
    }
    new_text
}

pub fn encrypt() -> String {
    let cipher = Cipher::aes_128_ecb();
    let data = polyfill("5VxBQ".as_bytes());
    let key = polyfill("jkkhfvbbedgm".as_bytes());
    let ciphertext = symm::encrypt(cipher, &key, None, &data).unwrap();

    println!("ciphertext:{:#?}", ciphertext.clone());

    let res = base64::encode(ciphertext);

    println!("encrypt:{:#?}", res);

    res
}

pub fn decrypt(data: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let key = polyfill(b"jkkhfvbbedgm");
    let res = symm::decrypt(cipher, &key, None, &data).unwrap();

    println!("decrypt:{:#?}", res);

    res
}

fn main() {
    // UJi+yZn9Jjvkt+IzsXz20A==

    // jkkhfvbbedgm

    // 5VxBQ

    let data = encrypt();

    let base64_cpsw = base64::decode(data).unwrap();

    let data = decrypt(&base64_cpsw);
    let decrypt_password = String::from_utf8(data).unwrap();
    println!("password:{}", decrypt_password);
}
