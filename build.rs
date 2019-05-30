fn main() {
    cc::Build::new()
        .file("src/getPid.c")
        .compile("getPid");
}
