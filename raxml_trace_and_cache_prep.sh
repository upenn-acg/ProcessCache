#! usr/bin/bash

# Assume you are starting in /IOTracker and
# bioinfo is one level up.
cargo clean && cargo build --release
rm -rf cache/
mkdir cache
cd ../bioinfo/
cargo clean && cargo build --release --bin single_raxml_job
cd raxml/
make clean && make