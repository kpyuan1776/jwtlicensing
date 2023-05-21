# jwtlicensing

The program shows an example of how to create and use a JWT-based license file, signed with asymmetric cryptography to protect a program from unwanted use.
The code contains functionality for creating a JWT-based license as well. However this part should never be used in a program that checks a license since it contains the private key which should leave the developers system. Only the code snippet starting from loading the license file and public key can be used as a precursor to running the actual application that will be protected from unwanted use (like checking expiration time, some other license transfered information etc...).

## Quickstart

### download external dependencies

```
#only required first time adding new external repo as submodule
#git submodule add https://github.com/Thalhammer/jwt-cpp.git external/jwt-cpp
git submodule init
git submodule update
```

### build example program

The external JWT-library jwt-cpp requires openssl on the system
on mac:
```
brew install openssl
```
linux:
```
sudo apt-get install libssl-dev
```

I have openssl version: LibreSSL 3.3.6

```
mkdir build
cd build
cmake ..
# on mac: cmake -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl -DOPENSSL_LIBRARIES=/opt/homebrew/opt/openssl/lib ..
make
app/./JwtLicensing_Executable
```

### example run

generate a key pair, for example using openssl:
```
ssh-keygen -t rsa -b 2048 -m PEM -f jwtR256.key
openssl rsa -in jwtR256.key -pubout -outform PEM -out jwtR256.key.pub
```

in app/main.cpp fill in the following string declarations with actual file paths:
```
std::string privateKeyfilepath = "PATH_TO_YOUR_PRIVATE_KEY";
std::string licensefilename = "PATH_TO_LICENSEFILE_license.txt";
std::string publicKeyfilepath = "PATH_TO_YOUR_PUBLIC_KEY";
```


### How to use
following 2 thigs should be at least checked:
* JWT signature, is for example the exp expiration time tampered
* the expiration time can be checked against local system time, however it is recommended to compare it to some time server (however then itnernet is required for executing the program)

## Roadmap

[ ] decouple the lciense cration and verification from openssl (e.g. botan library for crypto: https://botan.randombit.net)
[ ] check windows support (haven't tried to build and run it there...) 