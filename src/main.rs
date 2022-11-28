use aes::Aes128;
use cipher::{block_padding::NoPadding, BlockDecrypt, BlockEncrypt, KeyInit};

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
    let plaintext_polyfill = polyfill(plaintext.as_bytes());

    let aes128 = Aes128::new_from_slice(&key).unwrap();

    let ciphertext_vec = aes128.encrypt_padded_vec::<NoPadding>(&plaintext_polyfill);

    let ciphertext = base64::encode(ciphertext_vec);

    #[cfg(debug_assertions)]
    println!("encrypt:{:#?}", &ciphertext);

    ciphertext
}

pub fn decrypt(ciphertext: String, key: &[u8]) -> String {
    let ciphertext_base64 = base64::decode(ciphertext).unwrap();

    let aes128 = Aes128::new_from_slice(&key).unwrap();

    let plaintext_vec = aes128
        .decrypt_padded_vec::<NoPadding>(&ciphertext_base64)
        .unwrap();

    let plaintext = String::from_utf8(plaintext_vec).unwrap();

    #[cfg(debug_assertions)]
    println!("plaintext:{:#?}", &plaintext);

    plaintext
}

fn main() {
    let plaintext = "5VxBQ".to_string();
    let key = polyfill("jkkhfvbbedgm".as_bytes());

    let ciphertext = encrypt(plaintext, &key);

    let plaintext = decrypt(ciphertext, &key);

    let password = plaintext.trim_matches(char::from(0));

    println!("password:{:#?}", password);
}
