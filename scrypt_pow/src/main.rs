use blake2::{Blake2b, Digest};
use std::collections::HashMap;
use std::time::Instant;
use text_io::read;

const K : usize = 64;
const R : usize = 8;
const N : usize = 2_i32.pow(15 as u32) as usize; //2^20 takes 1GB of RAM

const D : usize = 8; // Difficulty of challenge

const C : usize = 1; // Number of iterations in the PFKDF2


fn _ROMix(b : [u8;K]) -> [u8;K] {
    //Not used, rewritten in the SMix function

    let mut x : [u8;K] = b;
    let mut v : Vec<[u8;K]> = vec![[0;K]; N];
    for i in 0..N{
        v[i] = x;
        x = hash(x);
    }
    for _ in 0..N{
        let j = modulo_bytes(x, N);
        x = hash(XOR(x, v[j]));
    }
    return x;
}

fn BlockMix(b : [[u8;K]; 2*R]) -> [[u8;K]; 2*R]{
    let mut x : [u8;K] = b[2*R-1];
    let mut y : [[u8;K]; 2*R] =[[0;K]; 2*R];
    for i in 0..2*R{
        x = hash(XOR(x, b[i]));
        y[i] = x;
    }
    let mut bp : [[u8;K]; 2*R] = [[0;K]; 2*R];
    for i in 0..R{
        bp[i] = y[2*i];
        bp[i+R] = y[2*i+1];
    }
    return bp;
}

fn SMix(b : [[u8;K]; 2*R]) -> [[u8;K]; 2*R]{
    let mut x : [[u8;K]; 2*R] = b;
    let mut v : Vec<[[u8;K]; 2*R]> = vec![[[0;K]; 2*R]; N]; //2*K*N*R bytes : 1GB for N = 2^20
    for i in 0..N{
        v[i] = x;
        x = BlockMix(x);
    }
    for _ in 0..N{
        let j = modulo_bytes2(x, N);
        x = BlockMix(XOR1(x, v[j]));
    }
    return x;
}

fn Scrypt_pow(d : &str)-> (u64, [u8; K]){
    let mut nonce : u64 = 0;
    let mut omega : [u8; K] = [255;K];
    
    let mut b : [[u8;K]; 2*R] = [[0;K]; 2*R];
    while !compare_bytes(omega, D){

        b = pbkdf2(&d, nonce);
        b = SMix(b);
        omega = F2(&d, b, 0);

        println!("{}", nonce);
        nonce +=1;

    }
    println!("final omega : {:?}", omega);
    return (nonce-1, omega); // Omega required to avoid just proposing every integer sequentially to the verifyer.
}

fn verification(d : &str, nonce : u64, omega : [u8; K]) -> bool{
    let mut b = pbkdf2(&d, nonce);
    b = SMix(b);
    let omega1 = F2(&d, b, 0);

    return (omega1 == omega && compare_bytes(omega, D));
}

fn main() {
    let d : String = read!(); //"end@date:20380119:001" for instance
    let t1 = Instant::now();

    let (n, omega) = Scrypt_pow(&d);
    println!("Nonce : {}", n);
    println!("Test of the PoW : {}", verification(&d, n, omega));
    println!("Time for execution : {:.2?}", t1.elapsed());
}


// Hash functions :

fn hash (x : [u8;K]) -> [u8;K]{

    let mut hasher = Blake2b::new();
    hasher.update(x);

    let hash = hasher.finalize();

    // there is no real better solution :
    let mut hash_ = [0;K];
    for x in 0..K{
        hash_[x] = hash[x];
    }

    return hash_;
}

fn hash1 (n : u64, d : &str, i : usize) -> [u8;K]{

    let mut hasher = Blake2b::new();
    hasher.update(n.to_be_bytes());
    hasher.update(d);
    hasher.update(i.to_be_bytes());

    let hash = hasher.finalize();

    // there is no real better solution :
    let mut hash_ : [u8;K] = [0;K];
    for x in 0..K{
        hash_[x] = hash[x];
    }

    return hash_;
}

fn hash2 (b : [[u8;K]; 2*R]) -> [u8;K]{
    let mut hasher = Blake2b::new();
    for i in 0..2*R{
    hasher.update(b[i]);
    }

    let hash = hasher.finalize();

    // there is no real better solution :
    let mut hash_ : [u8;K] = [0;K];
    for x in 0..K{
        hash_[x] = hash[x];
    }

    return hash_;
}

// PBKDF2 :

fn pbkdf2(pwd : &str, s : u64) -> [[u8;K]; 2*R] { 
    // see https://en.wikipedia.org/wiki/PBKDF2
    let mut b : [[u8;K]; 2*R] = [[0;K]; 2*R];
    for i in 0..2*R{
        b[i] = F(pwd, s, i);
    }
    return b;
}

fn F(pwd : &str, s: u64, i:usize) -> [u8;K] {
    let mut u : [[u8;K]; C] = [[0;K]; C];

    u[0] = PRF1(pwd, s, i);
    for i in 1..C{
        u[i] = PRF2(pwd, u[i-1]);
    }
    let mut b : [u8;K] = [0;K]; //neutral element for XOR
    for i in 0..C{
        b = XOR(b, u[i]);
    }
    return b;


}

fn PRF1 (d : &str, s : u64, i:usize) -> [u8;K]{
    // Pseudo-random function : blake2b.    
    let mut hasher = Blake2b::new();

    hasher.update(d);
    hasher.update(s.to_be_bytes());
    hasher.update(i.to_be_bytes());

    let hash = hasher.finalize();

    // no better solution ?
    let mut hash_ : [u8;K] = [0;K];
    for x in 0..K{
        hash_[x] = hash[x];
    }

    return hash_;
}

fn PRF2 (d : &str, s : [u8;K]) -> [u8;K]{
    let mut hasher = Blake2b::new();

    hasher.update(d);
    hasher.update(s);

    let hash = hasher.finalize();

    let mut hash_ : [u8;K] = [0;K];
    for x in 0..K{
        hash_[x] = hash[x];
    }

    return hash_;
}

// Second implem :

fn F2(pwd : &str, s: [[u8; K]; 2*R], i:usize) -> [u8;K] {
    let mut u : [[u8;K]; C] = [[0;K]; C];

    u[0] = PRF12(pwd, s, i);
    for i in 1..C{
        u[i] = PRF2(pwd, u[i-1]);
    }
    let mut b : [u8;K] = [0;K]; //neutral element for XOR
    for i in 0..C{
        b = XOR(b, u[i]);
    }
    return b;
}

fn PRF12 (d : &str, s : [[u8; K]; 2*R], i:usize) -> [u8;K]{
    // Pseudo-random function : blake2b.    
    let mut hasher = Blake2b::new();

    hasher.update(d);
    for l in 0..2*R{
        hasher.update(s[l]);
    }
    hasher.update(i.to_be_bytes());

    let hash = hasher.finalize();

    let mut hash_ : [u8;K] = [0;K];
    for x in 0..K{
        hash_[x] = hash[x];
    }

    return hash_;
}

// Aux functions :

fn XOR(x1 : [u8; K], x2 : [u8; K]) -> [u8; K]{
    let mut res : [u8;K] = [0; K];
    for i in 0..K{
        res[i] = x1[i]^x2[i];
    }
    return res;
}

fn XOR1(x1 : [[u8;K]; 2*R], x2 : [[u8;K]; 2*R]) -> [[u8;K]; 2*R]{
    let mut res : [[u8;K]; 2*R] = [[0;K]; 2*R];
    for j in 0..2*R{
        for i in 0..K{
            res[j][i] = x1[j][i]^x2[j][i];
        }
    }
    return res;
}

macro_rules! log_of {
    ($val:expr, $base:expr, $type:ty) => {
         ($val as f32).log($base) as $type
    }
}

fn modulo_bytes(y : [u8; K], n : usize) -> usize{
    let d = log_of!(n, 2., u32);
    let k  = (d % 8);
    let n1 : usize = (d as usize)/8;

    let mut sl : [u8;4] = [0; 4]; //to encode u32
    for j in 0..n1{
        sl[4-1-j] = y[K-1-j];
    }
    sl[4-n1-1] = sl[4-n1-1] % 2_u8.pow(k);

    let i = u32::from_be_bytes(sl);
    return i as usize;
}

fn modulo_bytes2(y : [[u8;K]; 2*R], n : usize) -> usize{
    let d = log_of!(n, 2., u32);
    let k  = (d % 8);
    let n1 : usize = (d as usize)/8;

    let yp = y[2*R-1];
    let mut sl : [u8;4] = [0; 4]; //to encode u32
    for j in 0..n1{
        sl[4-1-j] = yp[K-1-j];
    }
    sl[4-n1-1] = sl[4 - n1-1] % 2_u8.pow(k);

    let i = u32::from_be_bytes(sl);
    return i as usize;
}

fn compare_bytes(x: [u8; K], d : usize) -> bool {

    let k : usize = d/8;
    
    for i in 0..k {
        if x[i] > 0{
            return false;
        }
    }
    return true;
}