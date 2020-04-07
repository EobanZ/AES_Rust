// Function to print bytes
fn println_bytes(name_str: &str, bytes: &Vec<u8>) {
    print!("{}", name_str); 
    for b in bytes {
      print!("{:02x}", b);
    }
    print!("\n");
}

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
    println_bytes(" - key_bytes         = ", &key_bytes);
    println_bytes(" - iv_bytes          = ", &iv_bytes);
    println!(" - input_file_path   = {}", input_file_path.display());
    println!(" - output_file_path  = {}", output_file_path.display());

}

