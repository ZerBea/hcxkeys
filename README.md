hcxkeys
==============

Small set of tools to generate hashes and keys for the use with
latest hashcat. The tools are 100% compatible to hashcat
and recommended by hashcat (that means hcxtools 3.6.0 working with
hashcat 3.6.0).


Brief description
--------------

Multiple stand-alone binaries.

All of these utils are designed to execute only one specific function.


Detailed description
--------------

| Tool           | Description                                                                                          |
| -------------- | ---------------------------------------------------------------------------------------------------- |
| wlangenpmk     | Generates plainmasterkey from essid and password (CPU)                                               |
| wlangenpmkocl  | Generates plainmasterkey from essid and password (GPU)                                               |
| pwhash         | Generate hash of a word by using a given charset                                                     |


Compile
--------------

Simply run:

```
make
make install (as super user)
```


Requirements
--------------

* Linux (recommended Arch, but other distros should work, too)

* OpenCL and OpenCL Headers installed

* libopenssl and openssl-dev installed

* librt and librt-dev installed (should be installed by default)


Notice
--------------

Most output files will be appended to existing files.


