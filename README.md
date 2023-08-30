

## 🖲 Algorithms

- ed25519   -> EdDSA
- secp256k1 -> EC (compatible with all EVM based chains)
- secp256r1 -> ECDSA

> refer to `themis-wasm` to see how to use themis inside js.

## 🛠️ Setup 

> refer to https://docs.cossacklabs.com/themis/installation/installation-from-packages/ if you don't want to build themis from source.

```bash
wget http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2_amd64.deb
sudo dpkg -i libssl1.1_1.1.1f-1ubuntu2_amd64.deb
sudo apt update -y && sudo apt upgrade && sudo apt install -y libpq-dev pkg-config build-essential libudev-dev libssl-dev librust-openssl-dev
git clone https://github.com/cossacklabs/themis.git
cd themis
make
sudo make install
```

> install on MacOS M1:

```bash
brew install libthemis
```

> also deploy with docker:

```bash 
sudo docker network create -d bridge wallexerr || true
sudo docker build -t wallexerr -f $(pwd)/Dockerfile . --no-cache
sudo docker run -d --restart unless-stopped --link postgres --network wallexerr --name wallexerr -p 7443:7442 -v $(pwd)/infra/assets/:/usr/src/app/assets -v $(pwd)/infra/logs/:/usr/src/app/logs wallexerr
```