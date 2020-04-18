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
    println!(" - input_file_path   = {}", input_file_path.display());
    println!(" - output_file_path  = {}", output_file_path.display());

    //top layer: 
    //1. Extend keys 
    //Array that will be filled with key: 
    let number_of_rounds = if key_size > 128 {14} else {10}; println!("Number of rounds: {}", number_of_rounds);
    //let mut key_array = vec![0_u32; NUM_OF_COLUMS * (number_of_rounds+1)]; println!("Words in key_array: {}", key_array.len());
    let round_keys = expand_key(&key_bytes);

    println!("Expanded key:  {:x?}", round_keys);

    //2. Encript all or a specific amount of nounce+counter blocks (maybe not all so the dont need to be in memory)
    //3. XOR that the right block with the clear text data

    //test encript 1 block
    let mut block: [[u8;4];4] = [[0;4]; 4]; //will be filled with nounce and counter

    print!("{:?}", round_keys);

}

fn encript_block()
{
  //1. Get 

}

#[allow(dead_code)]
fn expand_key(provided_key: &Vec<u8>) -> Vec<u32>
{
  let num_words_in_key : u8 = provided_key.len() as u8 / 4 ; //Nk
  let num_of_rounds : usize = if num_words_in_key > 4 {14} else {10}; //Nr
  //NUM_OF_COLUMS: Nb

  //create result vector:
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

#[allow(dead_code)]
fn add_round_key()
{

}

#[allow(dead_code)]
fn sub_bytes()
{
  
}

#[allow(dead_code)]
fn shift_rows()
{

}

#[allow(dead_code)]
fn mix_colums()
{

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



///////////////////TEST//////////////////////
#[test]
fn key_expansion_128_works()
{
  //let key = vec![0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff];

  let key = vec![0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c]; //key from paper
  let correct_expanded_keys: Vec<u32> = vec![0x2b7e1516,0x28aed2a6,0xabf71588,0x09cf4f3c,
  0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605, 0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f, 0x3d80477d, 0x4716fe3e,
  0x1e237e44, 0x6d7a883b, 0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00, 0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc,
  0x11f915bc, 0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd, 0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f,
  0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f, 0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e, 0xd014f9a8,
  0xc9ee2589, 0xe13f0cc8, 0xb6630ca6];
  let res = expand_key(&key);
  //println!("Correct Keys: {:x?}", correct_expanded_keys);
  //println!("Calculated Keys: {:x?}",res);
  assert_eq!(correct_expanded_keys, res);
}

#[test]
fn key_expansion_256_works()
{
  //todo create random key
  let key = vec![0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff];
  let round_keys = expand_key(&key);
}


