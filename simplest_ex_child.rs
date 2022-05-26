use std::{fs, path::PathBuf};

fn main() {
    let input_file_path = PathBuf::from("simple_input.txt");
    let file_str = fs::read_to_string(input_file_path).unwrap();
    if file_str.contains("Hi") {
        println!("Milo");
    } else if file_str.contains("Hello") {
        println!("Alex");
    }
}
