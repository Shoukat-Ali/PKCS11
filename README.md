This is an attempt to show some of the PKCS #11 interfaces using the SoftHSM library. All the programs are written in C++ programming language. For more details on SoftHSM, please visit the following link.

https://www.opendnssec.org/softhsm/

# Installation

## OpenSC 
It provides a set of libraries and utilities to work with smart cards. Its main focus is on cards that support cryptographic operations, and facilitate their use in security applications such as authentication, mail encryption and digital signatures.

Contains utilities for crypto functions
https://github.com/OpenSC/OpenSC


## SoftHSM

SoftHSM is an implementation of a cryptographic store accessible through a PKCS #11 interface. You can use it to explore PKCS #11 without having a Hardware Security Module. It is being developed as a part of the OpenDNSSEC project. The SoftHSM source can be found using the following link.

https://dist.opendnssec.org/source/

## Ubuntu 22.04.4 LTS

The programs in this repository required the following tools

```
g++
libssl-dev
```

To install the above dependencies, run the following the command in a terminal
```
sudo apt install g++ libssl-dev
```

It is assumed that SoftHSM sources is downloaded and/or untarred as required. Next run the following commands one-by-one
```
./configure --prefix=/where/to/install/SoftHSM
make or make -j
sudo make install
```

After the SoftHSM successful installation, then install OpenSC by running the following command
```
sudo apt install opensc
```

Next include the SoftHSM library location to PATH environment variable as follows. Open .profile file (user home directory) in any text editor of your choice then added the following line at the end of file
```
export PATH=$PATH:/where/SoftHSM/is/installed/bin
```

To confirm the installation was success, run the following commands in a terminal
```
softhsm2-util
```

The output shows the softHSM utility manual.

Run the following command to see the list of slots. Note that for the first time, there will be an un-initialized slot only e.g., slot 0
```
softhsm2-util --show-slots
```

To initialize a token slot, one can run the following command
```
softhsm2-util --init-token --slot <slot_number> --label <text>
```

After running the command above correctly, you'll be asked to enter Security Officer (SO) and user PIN, respectively.

To confirm slot initialization, run the following command and check its output
```
softhsm2-util --show-slots
```

If the OpenSC installation was successful, then you should be able to see the pkcs11-tool utility. Simply run the following command to check pkcs11-tool manuel
```
man pkcs11-tool
```

## MS Windows
The programs were compiled and executed on Window 10 Pro, therefore, please perform the following steps in order. First, download SoftHSM2 for Windows and install it on your machine using the following github link

https://github.com/disig/SoftHSM2-for-Windows?tab=readme-ov-file

Next, for OpenSC on Windows, using the following link

https://github.com/OpenSC/OpenSC

Note that, in order to use softHSM2 and OpenSC in cmd.exe (Command Prompt), please add the followings to path environment variable 
```
C:\path\to\OpenSC\tools
C:\path\to\SoftHSM2\bin
```

One can also add the SoftHSM library path to cmd.exe by adding the following to path environment variable
```
C:\path\to\SoftHSM2\lib
```

Finally, to confirm softHSM2 has been added to path environment variable, please use one of the following commands in cmd.exe
```
path
softhsm2-util --version 
```

Don't forget to download code editor or IDE of your choice. For Windows, we are using TDM-GCC 10.3.0 compiler suite. Moreover, don't forget to set SOFTHSM2_LIB environment variable for the programs.