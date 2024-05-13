SoftHSM is an implementation of a cryptographic store accessible through a PKCS #11 interface. You can use it to explore PKCS #11 without having a Hardware Security Module. It is being developed as a part of the OpenDNSSEC project.

https://www.opendnssec.org/softhsm/


# Installation

## Windows

OpenSC; OpenSC provides a set of libraries and utilities to work with smart cards. Its main focus is on cards that support cryptographic operations, and facilitate their use in security applications such as authentication, mail encryption and digital signatures.

Contains utilities for crypto functions
https://github.com/OpenSC/OpenSC


SoftHSM

https://github.com/disig/SoftHSM2-for-Windows
https://dist.opendnssec.org/source/

## Ubuntu 22.04.4 LTS

Dependencies

```
g++
libssl-dev
```

run the following the command in a terminal
```
sudo apt install g++ libssl-dev
```

It is assumed that SoftHSM sources is download and/or untar as required
Next run the following commands
./configure --prefix=/where/to/install/SoftHSM

```
make or make -j

sudo make install
```

After SoftHSM successful installation, then

```
sudo apt install opensc
```

Next include the SoftHSM library location to PATH environment variable as follows
open .profile file (user home directory) in any text editor of your choice then added the following line at the end of file

```
export PATH=$PATH:/where/SoftHSM/is/installed/bin
```

To confirm the installation was success, run the following commands in a terminal
softhsm2-util
The output shows the softHSM utility manual

Run the following command to see the list of slots. Note that for the first time, there will be an un-initialized slot only e.g., slot 0
```
softhsm2-util --show-slots
```

To initialize a token slot, one can run the following command
```
softhsm2-util --init-token --slot <slot_number> --label <text>
```

After running the command above correctly, you'll be asked to enter Security Officer (SO) and user PIN, respectively

To confirm slot initialization, run the following command and check its output
```
softhsm2-util --show-slots
```

If the OpenSC installation was successful, then you should be able to see the pkcs11-tool utility.
Simply run the following command to check pkcs11-tool manuel
```
man pkcs11-tool
```
