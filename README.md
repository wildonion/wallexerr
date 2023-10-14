

> Crypto Contract Wallets.

## 🖲 Algorithms

- ed25519   -> EdDSA
- secp256k1 -> EC (compatible with all EVM based chains)
- secp256r1 -> ECDSA

## 🛠️ Setup on local

> refer to https://docs.cossacklabs.com/themis/installation/installation-from-packages/ if you don't want to build themis from source.

> wallet infos are inside `wallexerr-keys` folder in the root of the project.

> refer to `themis-wasm` to see how to use themis inside js.

first clone the repo then install the followings:

```bash
wget http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2_amd64.deb
sudo dpkg -i libssl1.1_1.1.1f-1ubuntu2_amd64.deb
sudo apt update -y && sudo apt upgrade && sudo apt install -y libpq-dev pkg-config build-essential libudev-dev libssl-dev librust-openssl-dev
git clone https://github.com/cossacklabs/themis.git
cd themis
make
sudo make install
# install themis on MacOS M1
brew install libthemis
```

### 🎯 Run

```bash
cargo run --bin wallexerr
```

### 🧪 Tests

```bash
cargo test # test all wallets
cargo test ed25519_test # test ed25519 wallet
cargo test secp256r1_test # test secp256r1 wallet
cargo test secp256k1_test # test secp256k1 wallet
```