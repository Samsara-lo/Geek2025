use std::io;
use base64::{Engine as _, engine::general_purpose};
use hex;

fn fun(input: &[u8]) -> String {
    const ALPHABET: &[u8] = &{
        let mut a = [0u8; 85];
        let mut i = 0usize;
        while i < 85 {
            a[i] = (33u8 + i as u8) as u8;
            i += 1;
        }
        a
    };

    let mut result = String::new();
    let mut i = 0usize;

    while i < input.len() {
        let chunk = &input[i..usize::min(i + 4, input.len())];
        let padding = 4 - chunk.len(); // 0..=3

        let mut value: u32 = 0;
        for &b in chunk {
            value = (value << 8) | (b as u32);
        }
        value <<= (padding * 8) as u32; 

        let mut parts = [0u8; 5];
        let mut v = value;
        for k in (0..5).rev() {
            parts[k] = (v % 85) as u8;
            v /= 85;
        }


        let out_count = 5 - padding;
        for idx in 0..out_count {
            result.push(ALPHABET[parts[idx] as usize] as char);
        }

        i += 4;
    }

    result
}


const TARGET_CIPHER: &[u8] = &[
    0x3c,0x41,0x41,0x3b,0x58,0x41,0x4d,0x3f,0x2c,0x5f,0x40,0x3b,0x54,0x5b,0x72,0x40,
    0x37,0x45,0x37,0x37,0x39,0x68,0x38,0x3b,0x73,0x3e,0x27,0x60,0x70,0x74,0x3d,0x3e,
    0x33,0x63,0x36,0x41,0x53,0x75,0x48,0x46,0x41,0x53,0x4f,0x74,0x50,0x3c,0x47,0x6b,
    0x66,0x5f,0x41,0x34,0x26,0x67,0x50,0x41,0x6c,0x31,0x5d,0x53
];


fn ba3eba3e(input: &str) -> String {
    let base64_encoded = general_purpose::STANDARD.encode(input.as_bytes());
    let fund = fun(base64_encoded.as_bytes());

    fund
}

fn to_hex(input: &str) -> String {
    hex::encode(input.as_bytes())
}


fn cmp(flag: &str) -> bool {
    let step1 = ba3eba3e(flag); 
    let step2 = to_hex(&step1);

    let target_hex = TARGET_CIPHER.iter()
        .map(|&b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join("");

    step2 == target_hex
}

fn main() {
    println!("███████ ███████ ██████  ██    ██ ██████  ████████      ██████ ██   ██  █████  ██      ██      ███████ ███    ██  ██████  ███████ ");
    println!("██         ███  ██   ██ ██    ██      ██    ██        ██      ██   ██ ██   ██ ██      ██      ██      ████   ██ ██       ██      ");
    println!("█████     ███   ██████  ██    ██  █████     ██        ██      ███████ ███████ ██      ██      █████   ██ ██  ██ ██   ███ █████   ");
    println!("██       ███    ██   ██ ██    ██      ██    ██        ██      ██   ██ ██   ██ ██      ██      ██      ██  ██ ██ ██    ██ ██      ");
    println!("███████ ███████ ██   ██  ██████  ██████     ██         ██████ ██   ██ ██   ██ ███████ ███████ ███████ ██   ████  ██████  ███████ ");
        
    println!("Welcome to the Rust Reverse Engineering Challenge!");
    println!("Find the correct flag to proceed...");
    println!();
    
    print!("Enter your flag: ");
    //SYC{Ohjhhh_y0u_g3t_Ezzzzz3_Ru3t!@}
    io::Write::flush(&mut io::stdout()).unwrap();
    
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");
    
    let flag = input.trim();
    

    #[cfg(debug_assertions)]
    {
        println!("Debug mode detected! Challenge disabled.");
        return;
    }
    
    if cmp(flag) {
        println!("Congratulations! You found the correct flag!");
        println!("Flag: {}", flag);
    } else {
        println!("Wrong flag! Try again.");
    }
}
