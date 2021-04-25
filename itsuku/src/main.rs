use blake2::{Blake2b, Digest};
use std::collections::HashMap;
use std::time::Instant;
use text_io::read;

//Constants 
const Dth : usize = 24; // Depth of tree. 2^24 -> 1.5 GB used
const T : usize = 2_i32.pow(Dth as u32) as usize; // Number of leaves.
const LS : usize = 2_i32.pow(15) as usize; //chunk size, called l in Itsuku's article.
const P : usize = T/LS; //Number of chunks, ie degree of parrallelism
const N : usize = 4; // Number of antecedents

const X : usize = 2_i32.pow(6) as usize; // in bytes, size of hash digest
const S : usize = X;

const D : usize = 24; // Number of leading zeros required

const L : usize = 9;
const M : usize = 14;

fn solution(d : &str) -> (u64, [usize; L], [Vec<[u8; X]>; L], HashMap<usize, [u8; M]>){
    
    //0. Hash service desc
    let I = hash0(d);

    //1. Challenge-dependant memory
    let mut x : Vec<[u8;X]> = vec![[0;X]; T]; //automatically put into heap by Rust. Box(array) produces stack overflow
    println!("{}.", 1);
    for p in 0..P{
        for i in 0..N{
            x[p*LS + i] = hash1(i as u32, p as u32, I);
        }
        for i in N..LS{
            let sum1 = mod_add_even(&x, i, p);
            let sum2 = mod_add_odd(&x, i, p);

            x[p*LS + i] = F(XOR1((p*LS+i) as u32, sum1), XOR(I, sum2));
        }
    }

    //2. Merkle tree
    println!("{}.", 2);
    let mut mt : Vec<[u8;M]>= vec![[0;M]; 2*T-1];  //automatically put into heap by Rust.

    //leaves
    for i in 0..T{
        mt[T-1+i] = hash2(x[i], I);
    }
    for i in (0..T-1).rev(){
        mt[i] = hash3(mt[2*i+1], mt[2*i+2], I);
    }

    //3. Iterate on Nonce
    println!("{}.", 3);
    let mut nonce : u64 = 0;
    let mut omega : [u8; S] = [63;S];

    let mut indexes : [usize; L] = [0;L];
    let mut y : [[u8;S]; L+1] = [[0;S]; L+1];

    while !compare_bytes(omega, D){
        y[0] = hash4(nonce, mt[0], I);
        for i in 1..(L+1){
            indexes[i-1] = modulo_bytes(y[i-1]); // T is a power of 2
            y[i] = hash5(y[i-1], x[indexes[i-1]], I);
        }

        omega = hash_on_rev_list(y);
        println!("{}", nonce);
        nonce+=1;
    }

    //4. Build solution for communication 
    
    //4.1 Selected leaves or n ordered antecedants

    assert!(L<=32); //required for the use of Default::default();
    let mut selected : [Vec<[u8; X]>; L] = Default::default();
    let mut selected_indexes : [Vec<usize>; L] = Default::default();

    for j in 0..L{
        let ij = indexes[j];
        let i = ij%LS;
        let l = ij - i;

        if i<N{
            selected[j] = vec![x[ij]];
        }
        else{
            let mut vec1 = Vec::new();
            let mut vec2 = Vec::new();

            let mut s : [u8;4] = [0;4];
            for l in 0..4{
                s[4-1-l] = x[i-1][X-1-l];
            }
            for k in 0..N{
                vec1.push(x[l + phis(k, i, s)]);
                vec2.push(l + phis(k, i, s));
            }
            selected[j] = vec1;
            selected_indexes[j] = vec2;
        }

    }

    //4.2 Merged opening

    let mut all_selected : Vec<u32> = Vec::new();
    for x in selected_indexes.iter(){
        for y in x{
            all_selected.push(*y as u32);
        }
    }

    for i in indexes.iter(){
        all_selected.push(*i as u32);    
    }

    let op = openings(all_selected);
    let mut op1 = HashMap::new();
    for x in op.iter(){
        op1.insert(*x, mt[*x]);
    }


    println!("Omega final : {:?}", omega);
    //println!("Selected : {:?}", selected);
    //println!("Merged opening : {:?}", op1);
    println!("Real root : {:?}", mt[0]);
    for y in &indexes{
        println!("index {} : {:?}", y, x[*y]);
    }
    return (nonce-1, indexes, selected, op1);
}

fn verification(d : &str, nonce : u64, indexes : [usize; L], selected : [Vec<[u8; X]>; L], op : HashMap<usize, [u8;M]>) -> bool {

    //1.
    let I : [u8; X] = hash0(d);

    let mut x : [[u8;X]; L] = [[0;X]; L];
    for k in 0..L{
        let ik = indexes[k];
        let i = ik % LS;
        if i < N{
            x[k] = selected[k][0];
        }
        else{
            x[k] = F(XOR1(ik as u32, mod_add_even1(&selected[k])), XOR(I, mod_add_odd1(&selected[k])));
        }
    }

    //2. 
    let phi0 = compute_root(&op, I);

    println!("Computed root is {:?}", phi0);

    //3. 
    let mut y : [[u8;S];L+1] = [[0; S];L+1];
    let mut indexes_2 : [usize; L] = [0;L];

    y[0] = hash4(nonce, phi0, I);

    for i in 1..(L+1){
        indexes_2[i-1] = modulo_bytes(y[i-1]); // T is a power of 2
        if indexes_2[i-1] != indexes[i-1]{
            println!("PB for {} : {} - {}", i-1, indexes_2[i-1], indexes[i-1]);
            return false;
        }
        y[i] = hash5(y[i-1], x[i-1], I);
    }

    let omega = hash_on_rev_list(y); 
    
    return compare_bytes(omega, D);

}


fn main() {
    let d : String = read!(); //"end@date:20380119:001" for instance
    let t1 = Instant::now();
    
    let (n, indexes, selected, op) = solution(&d);
    println!("Nonce : {}", n);
    
    println!("Test of the PoW : {}", verification(&d, n, indexes, selected, op));
    println!("Time for execution : {:.2?}", t1.elapsed());
}

// Intermediary functions


// I. Solution 

// 1. Challenge dependant memory
fn hash0 (d : &str) -> [u8;X]{

    let mut hasher = Blake2b::new();
    hasher.update(d);

    let hash = hasher.finalize();

    // no better solution ?
    let mut hash_ = [0;X];
    for x in 0..X{
        hash_[x] = hash[x];
    }

    return hash_;
}

fn hash1 (i : u32, p: u32, I : [u8; X]) -> [u8;X]{
    let mut hasher = Blake2b::new();
    hasher.update(i.to_be_bytes());
    hasher.update(p.to_be_bytes());
    hasher.update(I);

    let hash = hasher.finalize();
    let mut hash_ = [0;X];
    for x in 0..X{
        hash_[x] = hash[x];
    }
    return hash_;
}

fn F(a1 : [u8;X], a2 : [u8;X]) -> [u8; X]{
    let mut hasher = Blake2b::new();
    hasher.update(a1);
    hasher.update(a2);
    
    let hash = hasher.finalize();
    let mut hash_ = [0;X];
    for x in 0..X{
        hash_[x] = hash[x];
    }
    return hash_;

}

// Indexing functions :

fn phi(i : usize, j : [u8;4]) -> usize{

    let j1 : u32 = u32::from_be_bytes(j);
    let x = (j1 as u64).pow(3)/2_u64.pow(32);
    let y = (((i as u64-1)*x)/2_u64.pow(32)) as usize; // (i-1) for an integer between 0 and i-1.
    let z = ((y as u64)/2_u64.pow(32)) as usize;
    (i-1)-1-z
}


fn phis(k:usize, i:usize, j : [u8;4]) -> usize{
    assert!(k<=N);
    match k { 
        0 => i - 1,
        1 => phi(i, j),
        2 => (phi(i, j) + i)/2,
        3 => 7*i/8,
        4 => (phi(i, j) + 3*i)/4,
        5 => (3*phi(i, j) + i)/4,
        _ => 0,
    }
}

fn mod_add_even(x : &Vec<[u8;X]>, i : usize, p : usize) -> [u8;X]{
    let mut res : [u8;X] = [0;X];

    let mut s : [u8;4] = [0;4];
    for l in 0..4{
        s[4-1-l] = x[i-1][X-1-l];
    }


    for k in 0..(N+1)/2{
        for j in (0..X).rev(){
            let y = x[p*LS + phis(2*k, i, s)][j];
            if (res[j] as u16 + y as u16) >=64 && j>0{
                res[j-1] +=1;
            }
            res[j] = ((res[j] as u16 + y as u16) %64) as u8 ;
        }
    }
    return res;
}

fn mod_add_odd(x : &Vec<[u8;X]>, i : usize, p : usize) -> [u8;X]{
    let mut res : [u8;X] = [0;X];

    let mut s : [u8;4] = [0;4];
    for l in 0..4{
        s[4-1-l] = x[i-1][X-1-l];
    }


    for k in 0..(N/2){
        for j in (0..X).rev(){
            let y = x[p*LS + phis(2*k+1, i, s)][j];
            if (res[j] as u16 + y as u16) >=64 && j>0{
                res[j-1] +=1;
            }
            res[j] = ((res[j] as u16 + y as u16) %64) as u8 ;
        }
    }
    return res;
}

fn XOR(x1 : [u8; X], x2 : [u8; X]) -> [u8; X]{
    let mut res : [u8;X] = [0; X];
    for i in 0..X{
        res[i] = x1[i]^x2[i];
    }
    return res;
}

fn XOR1(i : u32, x : [u8; X]) -> [u8; X]{
    let mut res : [u8;X] = x;
    let i1 = i.to_be_bytes();

    for j in 0..4{
        res[X-1-j] = res[X-1-j]^i1[3 - j];
    }
    return res;
}

//2. Merkle tree 
fn hash2(x1 : [u8; X], I : [u8; X]) -> [u8; M]{
    let mut hasher = Blake2b::new();
    hasher.update(x1);
    hasher.update(I);

    let hash = hasher.finalize();
    let mut hash_ = [0;M];
    for x in 0..M{
        hash_[x] = hash[x];
    }
    return hash_;
}

fn hash3(x1 : [u8; M], x2 : [u8; M], I:[u8; X]) -> [u8; M]{
    let mut hasher = Blake2b::new();
    hasher.update(x1);
    hasher.update(x2);
    hasher.update(I);

    let hash = hasher.finalize();
    let mut hash_ = [0;M];
    for x in 0..M{
        hash_[x] = hash[x];
    }
    return hash_;
}

//3. Iterate on nonce
fn hash4(n : u64, x : [u8; M], I : [u8; X]) -> [u8; S]{
    let mut hasher = Blake2b::new();
    hasher.update(n.to_be_bytes());
    hasher.update(x);
    hasher.update(I);

    let hash = hasher.finalize();
    let mut hash_ = [0;S];
    for x in 0..S{
        hash_[x] = hash[x];
    }
    return hash_;
}

fn hash5(y : [u8; S], x : [u8; X], I : [u8; X]) -> [u8; S]{
    let mut hasher = Blake2b::new();
    hasher.update(y);
    hasher.update(XOR(x, I));

    let hash = hasher.finalize();
    let mut hash_ = [0;S];
    for x in 0..S{
        hash_[x] = hash[x];
    }
    return hash_;
}

fn hash_on_rev_list(l : [[u8; S]; L+1]) -> [u8; S]{

    let mut hasher = Blake2b::new();
    for x in l.iter().rev(){
        hasher.update(x);
    }
    let hash = hasher.finalize();
    let mut hash_ = [0;S];
    for x in 0..S{
        hash_[x] = hash[x];
    }
    return hash_;
}

fn compare_bytes(x: [u8; X], d : usize) -> bool {

    let k : usize = d/8;
    //To improve
    for i in 0..k {
        if x[i] > 0{
            return false;
        }
    }
    return true;
}

fn modulo_bytes(y : [u8; X]) -> usize{
    assert!(Dth>=24);
    let k  = (Dth % 8) as u32;

    let mut sl : [u8;4] = [0; 4]; //to encode u32
    for j in 0..4{
        sl[4-1-j] = y[X-1-j];
    }
    sl[0] = sl[0] % 2_u8.pow(k);

    let i = u32::from_be_bytes(sl);
    return i as usize
}

//4. Solution building 

//4.2 :

fn parent(n : u32) -> u32 {
    if n==0 {0} else {(n-1)/2}
    // Only the root is its own parent
}

fn childrens(n : &u32) -> (u32, u32) {
    (2*n +1, 2*n + 2)
}

fn sibling(a: u32) -> u32 {
    assert!(a>0);
    let n = parent(a);
    if a == 2*n+1 {2*n+2} else {2*n+1}
}

fn opening(n: u32)-> Vec<u32> {
    // Opening for one leaf of index n.
    let mut a = n;
    let mut v : Vec<u32> = vec![n];
    while parent(a)!=a {
        v.push(sibling(a));
        a = parent(a);
    }

    return v;
}

fn path(n: u32) -> Vec<u32> {
    // path from leaf of index n (excluded) to root index
    let mut a = n;
    let mut v = Vec::new();
    while parent(a)!=a {
        a = parent(a);
        v.push(a);
    }
    return v;
}

fn add_path(v : &mut Vec<u32>, n: u32) {
    // add the path from a new index
    // v : list of already know merged paths, n : new index, paths to be added

    let w = path(n);
    for x in w {
        if !v.contains(&x) {
            v.push(x);
        }
    }
}

fn openings(lj : Vec<u32>) -> Vec<usize> {
    let mut v0 : Vec<u32> = Vec::new();
    let mut paths : Vec<u32> = Vec::new();

    for x in lj.iter() {
        add_path(&mut paths, *x);
        let op = opening(*x);
        for y in &op {
            if !paths.contains(y) && !v0.contains(y){
                v0.push(*y);
            } 
        }
    }
        
    // to avoid having one mutable ref and one unmutable one.
    let mut v1 = Vec::new();
    for z in &v0 { 
        if !paths.contains(z){
            v1.push(*z as usize);
        }
    }
    return v1;
}

// II. Verification 

fn mod_add_even1(x : &Vec<[u8;X]>) -> [u8;X]{
    let mut res : [u8;X] = [0;X];

    for k in 0..(N+1)/2{
        for j in (0..X).rev(){
            let y = x[2*k][j];
            if (res[j] as u16 + y as u16) >=64 && j>0{
                res[j-1] +=1;
            }
            res[j] = ((res[j] as u16 + y as u16) %64) as u8 ;
        }
    }
    return res;
}

fn mod_add_odd1(x : &Vec<[u8;X]>) -> [u8;X]{
    let mut res : [u8;X] = [0;X];

    for k in 0..N/2{
        for j in (0..X).rev(){
            let y = x[2*k + 1][j];
            if (res[j] as u16 + y as u16) >=64 && j>0{
                res[j-1] +=1;
            }
            res[j] = ((res[j] as u16 + y as u16) %64) as u8 ;
        }
    }
    return res;
}

fn compute_root(op0 : &HashMap<usize, [u8; M]>, I : [u8; X]) -> [u8;M] {
    let mut values = op0.clone();
    let mut to_compute : Vec<usize> = vec![0];
    while !to_compute.is_empty(){
        
        let n0 = to_compute.pop().unwrap();

        let (x,y) = childrens(&(n0 as u32));
        let x = x as usize;
        let y = y as usize; // shadowing

        if values.contains_key(&x) && values.contains_key(&y) {
            values.insert(n0, hash3(values[&x], values[&y], I));
        }
        else{
            to_compute.push(n0);
            if !values.contains_key(&x){
                to_compute.push(x);
            }
            if !values.contains_key(&y){
                to_compute.push(y);
            }
        }
    }
    values[&0]
}