
use std::io;
use std::io::prelude::*;
use std::fs::File;
use std::fs::OpenOptions;

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


const RCON: [u8; 11] = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

const NUM_OF_COLUMS : usize = 4;
const MAX_HEAP_USAGE : usize = 96_000_000; //has to be a multible of 16

// Function to handle encryption/decryption command with given parameters
pub fn handle_aes_ctr_command(_command: String,
                              _key_size: u16,
                              key_bytes: Vec<u8>,
                              iv_bytes: Vec<u8>,
                              input_file_path: std::path::PathBuf,
                              output_file_path: std::path::PathBuf) {

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

    tmp
  }

  fn init(iv: &Vec<u8>) -> CtrState
  {
    let mut ctr_struct : CtrState
     = CtrState
     {num: 0, ivec: [0;8], ctr: 0};

    ctr_struct.ivec[..8].clone_from_slice(&iv[..8]);

    ctr_struct.ctr = 
    ((iv[8] as u64) << 56) +
    ((iv[9] as u64) << 48) +
    ((iv[10] as u64) << 40) +
    ((iv[11] as u64) << 32) +
    ((iv[12] as u64) << 24) +
    ((iv[13] as u64) << 16) +
    ((iv[14] as u64) << 8) +
    ((iv[15] as u64) << 0);

    ctr_struct
  }
}

fn encript_file_ctr(iv: &Vec<u8>, key: &Vec<u8>, in_path: &std::path::PathBuf, out_path: &std::path::PathBuf) -> io::Result<bool>
{
  //Get input file meta data
  let mut file = File::open(in_path.as_path())?;
  let meta = file.metadata()?;
  let size = meta.len() as usize;

  //Create new output file and open it as appendable
  File::create(&out_path.as_path())?;
  let mut o_file = OpenOptions::new().append(true).open(&out_path.as_path())?;

  let mut bytes_left_in_input_file = size;

  let mut data: Vec<u8>;
  let mut was_over_heap_max : bool = false;

  if size <= MAX_HEAP_USAGE
  {
    data = vec![0; size];
  }
  else{
    data = vec![0; MAX_HEAP_USAGE];
    was_over_heap_max = true;
  }

  let number_of_rounds = if key.len() > 16 {14} else {10};
  let r_keys = expand_key(&key);
  let mut ctr_struct = CtrState::init(iv);

  
  while bytes_left_in_input_file > 0
  {
    if was_over_heap_max && (bytes_left_in_input_file < MAX_HEAP_USAGE)
    {
      data.resize(bytes_left_in_input_file, 0);
    }
    file.read_exact(&mut data)?;

    let mut len: usize;
    let mut left: usize = data.len();
    let mut pos: usize = 0;

    let mut clear_block : [u8; 16] = [0; 16];
    let mut enc_block: [u8; 16] = [0; 16];

    while left > 0
    {
      clear_block.copy_from_slice(&ctr_struct.get_block());
      encript_block(&clear_block, &mut enc_block, &r_keys, &number_of_rounds);

      len = if left < 16 {left} else {16}; 
      if len != 16
      {
        for j in 0..len {
          data[pos + j] ^= enc_block[j]; 
        }
      }else
      {
        //if data 16 we can easily unroll the loop
        data[pos + 0] ^= enc_block[0]; 
        data[pos + 1] ^= enc_block[1]; 
        data[pos + 2] ^= enc_block[2]; 
        data[pos + 3] ^= enc_block[3]; 
        data[pos + 4] ^= enc_block[4]; 
        data[pos + 5] ^= enc_block[5]; 
        data[pos + 6] ^= enc_block[6]; 
        data[pos + 7] ^= enc_block[7]; 
        data[pos + 8] ^= enc_block[8]; 
        data[pos + 9] ^= enc_block[9]; 
        data[pos + 10] ^= enc_block[10]; 
        data[pos + 11] ^= enc_block[11]; 
        data[pos + 12] ^= enc_block[12]; 
        data[pos + 13] ^= enc_block[13]; 
        data[pos + 14] ^= enc_block[14]; 
        data[pos + 15] ^= enc_block[15];
      }

      pos += len;
      left -= len;

      ctr_struct.inc_ctr();
    }

    o_file.write_all(&data)?;
    bytes_left_in_input_file -= data.len();
  }

  Ok(true)
}

#[inline(always)]
fn encript_block(in_block: &[u8; 4* NUM_OF_COLUMS], out_block: &mut[u8; 4* NUM_OF_COLUMS], r_key: &Vec<u32>, num_rounds: &u8)
{
  let mut state: [[u8;4];NUM_OF_COLUMS];

  state = as_2d(in_block);

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

  let tmp = as_1d(&state);
  out_block[..16].clone_from_slice(&tmp[..16]);
}

fn expand_key(provided_key: &Vec<u8>) -> Vec<u32>
{
  let num_words_in_key : u8 = provided_key.len() as u8 / 4 ; //Nk
  let num_of_rounds : usize = if num_words_in_key > 4 {14} else {10}; //Nr
  //NUM_OF_COLUMS: Nb

  //create enc_block vector:
  let mut res : Vec<u32> = vec![0; NUM_OF_COLUMS * (num_of_rounds+1)];

  let mut temp: u32;

  for i in 0..num_words_in_key as usize {
    let tmp_arr: [u8; 4] = [provided_key[(4*i)], provided_key[(4*i+1)], provided_key[(4*i+2)], provided_key[(4*i+3)]];
    res[i] = as_u32_be(&tmp_arr);
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

  res
}

#[inline(always)]
fn sub_word(word : &u32) -> u32
{
  //unrolled 
  let mut bytes = word.to_be_bytes();
  bytes[0] = SBOX[bytes[0] as usize];
  bytes[1] = SBOX[bytes[1] as usize];
  bytes[2] = SBOX[bytes[2] as usize];
  bytes[3] = SBOX[bytes[3] as usize];

  as_u32_be(&bytes)
}

fn rot_word(word : &u32) -> u32
{
  (word << 8) | (word >>24)
}

#[inline(always)]
fn add_round_key(out_state: &mut[[u8;4];4], r_keys: &Vec<u32>, round: &u8)
{
  //unrolled 
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


}

#[inline(always)]
fn sub_bytes(out_state: &mut[[u8;4];4])
{
  out_state[0][0] = SBOX[out_state[0][0] as usize];
  out_state[0][1] = SBOX[out_state[0][1] as usize];
  out_state[0][2] = SBOX[out_state[0][2] as usize];
  out_state[0][3] = SBOX[out_state[0][3] as usize];

  out_state[1][0] = SBOX[out_state[1][0] as usize];
  out_state[1][1] = SBOX[out_state[1][1] as usize];
  out_state[1][2] = SBOX[out_state[1][2] as usize];
  out_state[1][3] = SBOX[out_state[1][3] as usize];
  
  out_state[2][0] = SBOX[out_state[2][0] as usize];
  out_state[2][1] = SBOX[out_state[2][1] as usize];
  out_state[2][2] = SBOX[out_state[2][2] as usize];
  out_state[2][3] = SBOX[out_state[2][3] as usize];

  out_state[3][0] = SBOX[out_state[3][0] as usize];
  out_state[3][1] = SBOX[out_state[3][1] as usize];
  out_state[3][2] = SBOX[out_state[3][2] as usize];
  out_state[3][3] = SBOX[out_state[3][3] as usize];
}

#[inline(always)]
fn shift_rows(out_state: &mut[[u8;4];4])
{
  let mut tmp;

  //unrolled
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

#[inline(always)]
fn mix_colums(out_state: &mut[[u8;4];4])
{
  let xtime = |x: &u8| -> u8 {(x<<1)^(((x>>7)& 1_u8) * 0x1b_u8)}; 

  let mut tmp1: u8;
  let mut tmp2: u8;
  let mut tmp3: u8;

  
  tmp3 = out_state[0][0];
  tmp1 = out_state[0][0] ^ out_state[1][0] ^ out_state[2][0] ^ out_state[3][0];
  tmp2 = out_state[0][0] ^ out_state[1][0]; tmp2 = xtime(&tmp2); out_state[0][0] ^= tmp2 ^ tmp1;
  tmp2 = out_state[1][0] ^ out_state[2][0]; tmp2 = xtime(&tmp2); out_state[1][0] ^= tmp2 ^ tmp1;
  tmp2 = out_state[2][0] ^ out_state[3][0]; tmp2 = xtime(&tmp2); out_state[2][0] ^= tmp2 ^ tmp1;
  tmp2 = out_state[3][0] ^ tmp3;            tmp2 = xtime(&tmp2); out_state[3][0] ^= tmp2 ^ tmp1;

  tmp3 = out_state[0][1];
  tmp1 = out_state[0][1] ^ out_state[1][1] ^ out_state[2][1] ^ out_state[3][1];
  tmp2 = out_state[0][1] ^ out_state[1][1]; tmp2 = xtime(&tmp2); out_state[0][1] ^= tmp2 ^ tmp1;
  tmp2 = out_state[1][1] ^ out_state[2][1]; tmp2 = xtime(&tmp2); out_state[1][1] ^= tmp2 ^ tmp1;
  tmp2 = out_state[2][1] ^ out_state[3][1]; tmp2 = xtime(&tmp2); out_state[2][1] ^= tmp2 ^ tmp1;
  tmp2 = out_state[3][1] ^ tmp3;            tmp2 = xtime(&tmp2); out_state[3][1] ^= tmp2 ^ tmp1;

  tmp3 = out_state[0][2];
  tmp1 = out_state[0][2] ^ out_state[1][2] ^ out_state[2][2] ^ out_state[3][2];
  tmp2 = out_state[0][2] ^ out_state[1][2]; tmp2 = xtime(&tmp2); out_state[0][2] ^= tmp2 ^ tmp1;
  tmp2 = out_state[1][2] ^ out_state[2][2]; tmp2 = xtime(&tmp2); out_state[1][2] ^= tmp2 ^ tmp1;
  tmp2 = out_state[2][2] ^ out_state[3][2]; tmp2 = xtime(&tmp2); out_state[2][2] ^= tmp2 ^ tmp1;
  tmp2 = out_state[3][2] ^ tmp3;            tmp2 = xtime(&tmp2); out_state[3][2] ^= tmp2 ^ tmp1;

  tmp3 = out_state[0][3];
  tmp1 = out_state[0][3] ^ out_state[1][3] ^ out_state[2][3] ^ out_state[3][3];
  tmp2 = out_state[0][3] ^ out_state[1][3]; tmp2 = xtime(&tmp2); out_state[0][3] ^= tmp2 ^ tmp1;
  tmp2 = out_state[1][3] ^ out_state[2][3]; tmp2 = xtime(&tmp2); out_state[1][3] ^= tmp2 ^ tmp1;
  tmp2 = out_state[2][3] ^ out_state[3][3]; tmp2 = xtime(&tmp2); out_state[2][3] ^= tmp2 ^ tmp1;
  tmp2 = out_state[3][3] ^ tmp3;            tmp2 = xtime(&tmp2); out_state[3][3] ^= tmp2 ^ tmp1;

  
}

#[inline(always)]
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

#[allow(dead_code)]
#[inline(always)]
fn as_u32_le(array: &[u8; 4]) -> u32 {
  ((array[0] as u32) <<  0) +
  ((array[1] as u32) <<  8) +
  ((array[2] as u32) << 16) +
  ((array[3] as u32) << 24)
}

#[inline(always)]
fn as_2d(in_array: &[u8; 4*4]) -> [[u8;4];4]
{
  let mut enc_block: [[u8;4]; 4] = [[0; 4]; 4];

  enc_block[0][0] = in_array[0];
  enc_block[0][1] = in_array[0 + 4];
  enc_block[0][2] = in_array[0 + 4 * 2];
  enc_block[0][3] = in_array[0 + 4 * 3];

  enc_block[1][0] = in_array[1];
  enc_block[1][1] = in_array[1 + 4];
  enc_block[1][2] = in_array[1 + 4 * 2];
  enc_block[1][3] = in_array[1 + 4 * 3];

  enc_block[2][0] = in_array[2 ];
  enc_block[2][1] = in_array[2 + 4];
  enc_block[2][2] = in_array[2 + 4 * 2];
  enc_block[2][3] = in_array[2 + 4 * 3];

  enc_block[3][0] = in_array[3];
  enc_block[3][1] = in_array[3 + 4];
  enc_block[3][2] = in_array[3 + 4 * 2];
  enc_block[3][3] = in_array[3 + 4 * 3];

  enc_block
}

#[inline(always)]
fn as_1d(in_array: &[[u8;4];4]) -> [u8; 4*4]
{
  let mut enc_block: [u8; 16] = [0; 16];
  
  enc_block[0] = in_array[0][0];
  enc_block[0 + 4] = in_array[0][1];
  enc_block[0 + 4 * 2] = in_array[0][2];
  enc_block[0 + 4 * 3] = in_array[0][3];

  enc_block[1] = in_array[1][0];
  enc_block[1 + 4] = in_array[1][1];
  enc_block[1 + 4 * 2] = in_array[1][2];
  enc_block[1 + 4 * 3] = in_array[1][3];

  enc_block[2] = in_array[2][0];
  enc_block[2 + 4] = in_array[2][1];
  enc_block[2 + 4 * 2] = in_array[2][2];
  enc_block[2 + 4 * 3] = in_array[2][3];

  enc_block[3] = in_array[3][0];
  enc_block[3 + 4] = in_array[3][1];
  enc_block[3 + 4 * 2] = in_array[3][2];
  enc_block[3 + 4 * 3] = in_array[3][3];

  enc_block
}
