#![feature(seek_convenience)]
use std::io;
use std::io::prelude::*;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek};
use std::io::SeekFrom;
use std::path::Path;
use std::error::Error;



#[allow(dead_code)]
const SBOX: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
];

#[allow(dead_code)]
const RCON: [u8; 11] = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

const NUM_OF_COLUMS : usize = 4;

// Function to print bytes
fn println_bytes(name_str: &str, bytes: &Vec<u8>) {
    print!("{}", name_str); 
    for b in bytes {
      print!("{:02x}", b);
    }
    print!("\n");
}
#[allow(dead_code)]
// Function to handle encryption/decryption command with given parameters
pub fn handle_aes_ctr_command(command: String,
                              key_size: u16,
                              key_bytes: Vec<u8>,
                              iv_bytes: Vec<u8>,
                              input_file_path: std::path::PathBuf,
                              output_file_path: std::path::PathBuf) {

    println!("\n### Dummy printing ...");
    println!(" - command           = {}", command);
    println!(" - key_size          = {}", key_size);
    println_bytes(" - key_bytes         = ", &key_bytes); //vec[0] = 00, vec[len-1] = ff <-eingabe war 001122...ff im speicher steht aber ff..221100
    println_bytes(" - iv_bytes          = ", &iv_bytes);
    println!(" - input_file_path   = {}", input_file_path.as_path().display());
    println!(" - output_file_path  = {}", output_file_path.as_path().display());
    aes_encript_block_128_works();
 
    

    let round_keys = expand_key(&key_bytes);

  //let mut test_block: [u8; 4*NUM_OF_COLUMS] = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
  encript_file_ctr(&iv_bytes, &key_bytes, &input_file_path, &output_file_path).expect("error");

}

struct CtrState
{
  num: u8,
  ivec: [u8; 8],
  ctr: u64
}

impl CtrState
 {
  fn inc_ctr(&mut self)
  {
    self.num += 1;
    self.ctr += 1;
  }

  fn get_block(&self) -> [u8; 16]
  { 
    let mut tmp: [u8; 16] = [0; 16];
    tmp[..8].clone_from_slice(&self.ivec[..8]);
    tmp[8..16].clone_from_slice(&self.ctr.to_be_bytes());

    return tmp;
  }

  fn init(iv: &Vec<u8>) -> CtrState
  
  {
    let mut ctr_struct : CtrState
     = CtrState
     {num: 0, ivec: [0;8], ctr: 0};

    ctr_struct.ivec[..8].clone_from_slice(&iv[..8]);

    //todo: richtige richtung herausfinden. Ich glaub man muss es noch umdrehen. dh iv[8] muss ganz rechts stehen und iv[15] ganz links
    ctr_struct.ctr = 
    ((iv[8] as u64) << 56) +
    ((iv[9] as u64) << 48) +
    ((iv[10] as u64) << 40) +
    ((iv[11] as u64) << 32) +
    ((iv[12] as u64) << 24) +
    ((iv[13] as u64) << 16) +
    ((iv[14] as u64) << 8) +
    ((iv[15] as u64) << 0);

    //ctr_struct.ctr = 
    //((iv[8] as u64) << 0) +
    //((iv[9] as u64) << 8) +
    //((iv[10] as u64) << 16) +
    //((iv[11] as u64) << 24) +
    //((iv[12] as u64) << 32) +
    //((iv[13] as u64) << 40) +
    //((iv[14] as u64) << 48) +
    //((iv[15] as u64) << 56);

    return ctr_struct;
  }
}

fn encript_file_ctr(iv: &Vec<u8>, key: &Vec<u8>, in_path: &std::path::PathBuf, out_path: &std::path::PathBuf) -> io::Result<Vec<u8>>
{
  //Check if file exists
  let mut file = File::open(in_path.as_path())?;
  let meta = file.metadata()?;
  let size = meta.len() as usize;
  let mut data = Vec::with_capacity(size);
  data.resize(size, 0);
  file.read_exact(&mut data)?;
  //let posafterread = file.seek(SeekFrom::Current(0))?;

  //Check file size-> if less then the cap. load whole file into ram ->else: ?



  let number_of_rounds = if key.len() > 16 {14} else {10};
  let r_keys = expand_key(&key);
  let mut ctr_struct = CtrState
  ::init(iv);

  
  let mut len: usize;
  let mut left: usize = size;
  let mut pos: usize = 0;

  let mut clear_block : [u8; 16] = [0; 16];
  let mut enc_block: [u8; 16] = [0; 16];

  while left > 0
  {
    clear_block.copy_from_slice(&ctr_struct.get_block());
    encript_block(&clear_block, &mut enc_block, &r_keys, &number_of_rounds);

    len = if(left < 16) {left} else {16}; 
    for j in 0..len {
      data[pos + j] ^= enc_block[j]; 
    }
    pos += len;
    left -= len;

    ctr_struct.inc_ctr();
  }

  let mut o_file = File::create(&out_path.as_path())?;
  let x = o_file.write_all(&data);
  println!("{:?}", x);


  return Ok(data);

  



  
  

}

fn init_ctr(iv: &Vec<u8>) -> CtrState

{
  let mut CtrState
   : CtrState
   = CtrState
   {num: 0, ivec: [0; 8], ctr: 0,};
  //todo: init 

  CtrState
  .num = 0;
  CtrState
  .ivec[..8].clone_from_slice(&iv[..8]);
  //to big endian 
  CtrState
  .ctr = 
  ((iv[8] as u64) << 56) +
  ((iv[9] as u64) << 48) +
  ((iv[10] as u64) << 40) +
  ((iv[11] as u64) << 32) +
  ((iv[12] as u64) << 24) +
  ((iv[13] as u64) << 16) +
  ((iv[14] as u64) << 8) +
  ((iv[15] as u64) << 0);


  return CtrState
  ;
}

fn encript_block(in_block: &[u8; 4* NUM_OF_COLUMS], out_block: &mut[u8; 4* NUM_OF_COLUMS], r_key: &Vec<u32>, num_rounds: &u8)
{
  //always [4][4] per clear_block for AES
  let mut state: [[u8;4];NUM_OF_COLUMS] = [[0;4]; NUM_OF_COLUMS];

  state = as_2D(in_block);

  add_round_key(&mut state, r_key, &0);

  for round in 1..*num_rounds {
    sub_bytes(&mut state);
    shift_rows(&mut state);
    mix_colums(&mut state);
    add_round_key(&mut state, r_key, &round);
  }

  sub_bytes(&mut state);
  shift_rows(&mut state);
  add_round_key(&mut state, r_key, num_rounds);

  let tmp = as_1D(&state);
  out_block[..16].clone_from_slice(&tmp[..16]);
}

#[allow(dead_code)]
fn expand_key(provided_key: &Vec<u8>) -> Vec<u32>
{
  let num_words_in_key : u8 = provided_key.len() as u8 / 4 ; //Nk
  let num_of_rounds : usize = if num_words_in_key > 4 {14} else {10}; //Nr
  //NUM_OF_COLUMS: Nb

  //create enc_block vector:
  let mut res : Vec<u32> = vec![0; NUM_OF_COLUMS * (num_of_rounds+1)];


  let mut temp: u32 = 0;

  for i in 0..num_words_in_key as usize {
    let tmpArr: [u8; 4] = [provided_key[(4*i)], provided_key[(4*i+1)], provided_key[(4*i+2)], provided_key[(4*i+3)]];
    res[i] = as_u32_be(&tmpArr);
  }

  for i in num_words_in_key as usize..NUM_OF_COLUMS*(num_of_rounds+1) {
    temp = res[i-1];

    if (i as u8 % num_words_in_key) == 0
    {

      let mut tmp_rcon: u32 = 0;
      tmp_rcon |= (RCON[(i as u8/num_words_in_key)  as usize] as u32) << 24;
      
      temp = sub_word(&rot_word(&temp)) ^ tmp_rcon;
    }
    else if (num_words_in_key > 6) && ((i as u8 % num_words_in_key) == 4)
    {
      temp = sub_word(&temp);
    }
    res[i] = res[i-num_words_in_key as usize] ^ temp;
  }

  return res;

  //notes:
  //Nk: Number of 32-bit words im key (4 oder 8 in diesem fall)
  //Nb: Number of columns (32-bit words) aus dem der state besteht (immer 4 in diesem Fall)
  //Nr: Number of rounds (10 & 14 in diesem fall)
  //Rcon[]: Round constant array
  //word: entweder single u32 oder byte array[4]: kein union wg unsafe
}

fn sub_word(word : &u32) -> u32
{
  //Apply S-box to 4byte input
  let mut bytes = word.to_be_bytes();
  for byte in bytes.iter_mut() {
    *byte = SBOX[*byte as usize];
  }

  return as_u32_be(&bytes);
}

fn rot_word(word : &u32) -> u32
{
  //Perform cyclic permutation
  //(word >> 8) | (word <<24); other direction. dont know wich is right. ich gaub bei intel wird in die andere richtung geschoben
  return (word << 8) | (word >>24);
}

fn add_round_key(out_state: &mut[[u8;4];4], r_keys: &Vec<u32>, round: &u8)
{

  let mut key = r_keys[*round as usize * 4].to_be_bytes();
  out_state[0][0] ^= key[0];
  out_state[1][0] ^= key[1];
  out_state[2][0] ^= key[2];
  out_state[3][0] ^= key[3];
  key = r_keys[(*round as usize * 4) + 1 ].to_be_bytes();
  out_state[0][1] ^= key[0];
  out_state[1][1] ^= key[1];
  out_state[2][1] ^= key[2];
  out_state[3][1] ^= key[3];
  key = r_keys[(*round as usize * 4) + 2 ].to_be_bytes();
  out_state[0][2] ^= key[0];
  out_state[1][2] ^= key[1];
  out_state[2][2] ^= key[2];
  out_state[3][2] ^= key[3];
  key = r_keys[(*round as usize * 4) + 3 ].to_be_bytes();
  out_state[0][3] ^= key[0];
  out_state[1][3] ^= key[1];
  out_state[2][3] ^= key[2];
  out_state[3][3] ^= key[3];

  //let mut key = r_keys[*round as usize * 4].to_be_bytes(); //endian nich sicher
  //out_state[0][0] ^= key[0];
  //out_state[0][1] ^= key[1];
  //out_state[0][2] ^= key[2];
  //out_state[0][3] ^= key[3];
  //
  //key = r_keys[(*round as usize * 4) + 1 ].to_be_bytes();
  //out_state[1][0] ^= key[0];
  //out_state[1][1] ^= key[1];
  //out_state[1][2] ^= key[2];
  //out_state[1][3] ^= key[3];
  //
  //key = r_keys[(*round as usize * 4) + 2 ].to_be_bytes();
  //out_state[2][0] ^= key[0];
  //out_state[2][1] ^= key[1];
  //out_state[2][2] ^= key[2];
  //out_state[2][3] ^= key[3];
  //
  //key = r_keys[(*round as usize * 4) + 3 ].to_be_bytes();
  //out_state[3][0] ^= key[0];
  //out_state[3][1] ^= key[1];
  //out_state[3][2] ^= key[2];
  //out_state[3][3] ^= key[3];
}

fn sub_bytes(out_state: &mut[[u8;4];4])
{
  for r in 0..4_usize {
    for c in 0..4_usize {
      out_state[r][c] = SBOX[out_state[r][c] as usize];
    }
  }
}

#[allow(dead_code)]
fn shift_rows(out_state: &mut[[u8;4];4])
{
  let mut tmp;

  //1. row: 1 left shift
  tmp = out_state[1][0];
  out_state[1][0] = out_state[1][1];
  out_state[1][1] = out_state[1][2];
  out_state[1][2] = out_state[1][3];
  out_state[1][3] = tmp;

  //2. row: 2 left shifts
  tmp = out_state[2][0];
  out_state[2][0] = out_state[2][2];
  out_state[2][2] = tmp;
  tmp = out_state[2][1];
  out_state[2][1] = out_state[2][3];
  out_state[2][3] = tmp;

  //3. row 3 left shifts
  tmp = out_state[3][0];
  out_state[3][0] = out_state[3][3];
  out_state[3][3] = out_state[3][2];
  out_state[3][2] = out_state[3][1];
  out_state[3][1] = tmp;
}

fn mix_colums(out_state: &mut[[u8;4];4])
{
  let xtime = |x: &u8| -> u8 {return (x<<1)^(((x>>7)& 1_u8) * 0x1b_u8)}; 

  let mut tmp1: u8;
  let mut tmp2: u8;
  let mut tmp3: u8;

  for i in 0..4 {
    tmp3 = out_state[0][i];
    tmp1 = out_state[0][i] ^ out_state[1][i] ^ out_state[2][i] ^ out_state[3][i];
    tmp2 = out_state[0][i] ^ out_state[1][i]; tmp2 = xtime(&tmp2); out_state[0][i] ^= tmp2 ^ tmp1;
    tmp2 = out_state[1][i] ^ out_state[2][i]; tmp2 = xtime(&tmp2); out_state[1][i] ^= tmp2 ^ tmp1;
    tmp2 = out_state[2][i] ^ out_state[3][i]; tmp2 = xtime(&tmp2); out_state[2][i] ^= tmp2 ^ tmp1;
    tmp2 = out_state[3][i] ^ tmp3;            tmp2 = xtime(&tmp2); out_state[3][i] ^= tmp2 ^ tmp1;

  }
}

fn as_u32_be(array: &[u8; 4]) -> u32 {
  ((array[0] as u32) << 24) +
  ((array[1] as u32) << 16) +
  ((array[2] as u32) <<  8) +
  ((array[3] as u32) <<  0)
} 

#[allow(unused_macros)]
macro_rules! four_u8_to_u32 {
  ($b0:expr, $b1:expr, $b2:expr, $b3:expr) => {{
      (($b0 as u32) << 24) ^ (($b1 as u32) << 16) ^ (($b2 as u32) << 8) ^ ($b3 as u32)
  }};
  }

fn as_u32_le(array: &[u8; 4]) -> u32 {
  ((array[0] as u32) <<  0) +
  ((array[1] as u32) <<  8) +
  ((array[2] as u32) << 16) +
  ((array[3] as u32) << 24)
}

fn as_2D(in_array: &[u8; 4*4]) -> [[u8;4];4]
{
  let mut enc_block: [[u8;4]; 4] = [[0; 4]; 4];

  for r in 0..4 {
    for c in 0..4{
      enc_block[r][c] = in_array[r + 4 * c];
    }
  }

  return enc_block;
}

fn as_1D(in_array: &[[u8;4];4]) -> [u8; 4*4]
{
  let mut enc_block: [u8; 16] = [0; 16];

  for r in 0..4 {
    for c in 0..4 {
      enc_block[r + 4 * c] = in_array[r][c];
      
    } 
  }

  return enc_block;
}




///////////////////TEST//////////////////////
#[test]
fn key_expansion_128_works()
{
  //let key = vec![0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff]
  let key = vec![0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c]; //key from paper
  let correct_expanded_keys: Vec<u32> = vec![0x2b7e1516,0x28aed2a6,0xabf71588,0x09cf4f3c,
  0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605, 0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f, 0x3d80477d, 0x4716fe3e,
  0x1e237e44, 0x6d7a883b, 0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00, 0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc,
  0x11f915bc, 0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd, 0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f,
  0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f, 0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e, 0xd014f9a8,
  0xc9ee2589, 0xe13f0cc8, 0xb6630ca6];

  //Another thest
  //let key = vec![0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
  //    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C];
  //let correct_expanded_keys: Vec<u32> = vec![0x2B7E1516, 0x28AED2A6, 0xABF71588, 0x09CF4F3C,
  //     0xA0FAFE17, 0x88542CB1, 0x23A33939, 0x2A6C7605,
  //     0xF2C295F2, 0x7A96B943, 0x5935807A, 0x7359F67F,
  //     0x3D80477D, 0x4716FE3E, 0x1E237E44, 0x6D7A883B,
  //     0xEF44A541, 0xA8525B7F, 0xB671253B, 0xDB0BAD00,
  //     0xD4D1C6F8, 0x7C839D87, 0xCAF2B8BC, 0x11F915BC,
  //     0x6D88A37A, 0x110B3EFD, 0xDBF98641, 0xCA0093FD,
  //     0x4E54F70E, 0x5F5FC9F3, 0x84A64FB2, 0x4EA6DC4F,
  //     0xEAD27321, 0xB58DBAD2, 0x312BF560, 0x7F8D292F,
  //     0xAC7766F3, 0x19FADC21, 0x28D12941, 0x575C006E,
  //     0xD014F9A8, 0xC9EE2589, 0xE13F0CC8, 0xB6630CA6];
  
  let round_keys = expand_key(&key);
  //println!("Correct Keys: {:x?}", correct_expanded_keys);
  //println!("Calculated Keys: {:x?}",res);
  assert_eq!(correct_expanded_keys, round_keys);
}

#[test]
fn key_expansion_256_works()
{
  //let key = vec![0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff];
  let key: Vec<u8> = vec![
      0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
      0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
      0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
      0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
  ];
  let correct_expanded_keys: Vec<u32> = vec![
    0x603DEB10, 0x15CA71BE, 0x2B73AEF0, 0x857D7781,
     0x1F352C07, 0x3B6108D7, 0x2D9810A3, 0x0914DFF4,
     0x9BA35411, 0x8E6925AF, 0xA51A8B5F, 0x2067FCDE,
     0xA8B09C1A, 0x93D194CD, 0xBE49846E, 0xB75D5B9A,
     0xD59AECB8, 0x5BF3C917, 0xFEE94248, 0xDE8EBE96,
     0xB5A9328A, 0x2678A647, 0x98312229, 0x2F6C79B3,
     0x812C81AD, 0xDADF48BA, 0x24360AF2, 0xFAB8B464,
     0x98C5BFC9, 0xBEBD198E, 0x268C3BA7, 0x09E04214,
     0x68007BAC, 0xB2DF3316, 0x96E939E4, 0x6C518D80,
     0xC814E204, 0x76A9FB8A, 0x5025C02D, 0x59C58239,
     0xDE136967, 0x6CCC5A71, 0xFA256395, 0x9674EE15,
     0x5886CA5D, 0x2E2F31D7, 0x7E0AF1FA, 0x27CF73C3,
     0x749C47AB, 0x18501DDA, 0xE2757E4F, 0x7401905A,
     0xCAFAAAE3, 0xE4D59B34, 0x9ADF6ACE, 0xBD10190D,
     0xFE4890D1, 0xE6188D0B, 0x046DF344, 0x706C631E];


  let round_keys = expand_key(&key);

  assert_eq!(correct_expanded_keys, round_keys);
}

#[test]
fn add_round_key_works()
{ 
  let input: [u8; 16] = [0x58, 0x4d,0xca, 0xf1, 0x1b, 0x4b, 0x5a, 0xac, 0xdb, 0xe7, 0xca, 0xa8, 0x1b, 0x6b, 0xb0, 0xe5];
  let key: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];

  let r_keys = expand_key(&key.to_vec());

  let correct_output = [0xaa, 0x8f, 0x5f, 0x03, 0x61, 0xdd, 0xe3, 0xef, 0x82, 0xd2, 0x4a, 0xd2, 0x68, 0x32, 0x46, 0x9a];


  let round = 2_u8;

  let mut state = as_2D(&input);
  add_round_key(&mut state, &r_keys, &round);
  assert_eq!(as_1D(&state), correct_output);

}

#[test]
fn sub_bytes_works()
{
  let input: [u8; 16] = [0xaa, 0x8f, 0x5f, 0x03, 0x61, 0xdd, 0xe3, 0xef, 0x82, 0xd2, 0x4a, 0xd2, 0x68, 0x32, 0x46, 0x9a];
  let correct_output: [u8; 16] = [0xac, 0x73, 0xcf, 0x7b, 0xef, 0xc1, 0x11, 0xdf, 0x13, 0xb5, 0xd6, 0xb5, 0x45, 0x23, 0x5a, 0xb8];

  let mut tmp_status = as_2D(&input);
  sub_bytes(&mut tmp_status);

  assert_eq!(correct_output, as_1D(&tmp_status));
}

#[test]
fn shift_rows_works()
{
  let input: [u8; 16] = [0x49, 0xde ,0xd2, 0x89, 0x45, 0xdb, 0x96, 0xf1, 0x7f, 0x39, 0x87, 0x1a, 0x77, 0x02, 0x53, 0x3b];
  let correct_output: [u8; 16] = [0x49, 0xdb, 0x87, 0x3b, 0x45, 0x39, 0x53, 0x89, 0x7f, 0x02, 0xd2, 0xf1, 0x77, 0xde, 0x96, 0x1a];

  let mut status = as_2D(&input);
  shift_rows(&mut status);

  assert_eq!(correct_output, as_1D(&status));
}

#[test]
fn mix_colums_works()
{
  let input: [u8; 16] = [0x49, 0xdb, 0x87, 0x3b, 0x45, 0x39, 0x53, 0x89, 0x7f, 0x02, 0xd2, 0xf1, 0x77, 0xde, 0x96, 0x1a];
  let correct_output: [u8; 16] = [ 0x58, 0x4d, 0xca, 0xf1, 0x1b, 0x4b, 0x5a, 0xac, 0xdb, 0xe7, 0xca, 0xa8, 0x1b, 0x6b, 0xb0, 0xe5];

  let mut status = as_2D(&input);
  mix_colums(&mut status);

  assert_eq!(correct_output, as_1D(&status));
}


fn aes_encript_block_128_works()
{
  let rounds = 10_u8;
  let input_block: [u8; 16] = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
  let input_key: Vec<u8> = vec![0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c];

  let correct_output: [u8; 16] = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32];

  let mut output: [u8; 16] = [0; 16];

  let r_keys: Vec<u32> = expand_key(&input_key);
  encript_block(&input_block, &mut output, &r_keys, &rounds);

  assert_eq!(correct_output, output);
  
}


