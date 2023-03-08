## Compiling the library and header file
First, one needs to compile the library running:
```shell
cargo build --release
```

Then, we need to build the header files using `cbindgen`. For this, first install
cbindgen:
```shell
cargo install cbindgen
```

and then build the header file by running the following command from the parent directory (nightly is required):
```shell
rustup run nightly cbindgen ./ --config cbindgen.toml --crate atms-halo2 --output target/include/atms_halo2.h
```

## Running C tests

We first build the test executable:

``` sh
gcc -Wl,-dead_strip c-tests/atms_halo2.c -g -o test -L ./target/release -latms_halo2 -lstdc++
```

then simply run the tests:

```shell
./test
```
