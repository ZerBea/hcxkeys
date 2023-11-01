Important notice
==============
Calulating of PlainMaster Key rainbowtables is no longer up-to-date.
Future plan is to replace teh old by a Plain Master Key Data Base (PMKDB)
- create PMKs by CPU and GPU and import them to the data base
- import hashcat pot file to data base
- import hashcat out file to data base
- creat hashcat pot file from data base
- add PMKDB support to all hcxtools


hcxkeys
==============

Small set of tools to generate plainmasterkeys (rainbowtables) for the use with latest hashcat and latest John the Ripper.


Brief description
--------------

Multiple stand-alone binaries.

All of these utils are designed to execute only one specific function.

Read this post: hcxtools - solution for capturing wlan traffic and conversion to hashcat formats (https://hashcat.net/forum/thread-6661.html)


Detailed description
--------------

| Tool           | Description                                                                                          |
| -------------- | ---------------------------------------------------------------------------------------------------- |
| wlangenpmk     | Generates plainmasterkeys (CPU) from essid and password for use with hashcat hash-mode 22001         |
| wlangenpmkocl  | Generates plainmasterkeys (GPU) from essid and password for use with hashcat hash-mode 22001         |


Compile
--------------

Simply run:

```
make
make install (as super user)
```


Requirements
--------------

* knowledge of radio technology

* knowledge of electromagnetic-wave engineering

* detailed knowledge of 802.11 protocol

* detailed knowledge of key derivation functions

* detailed knowledge of Linux

* Linux (recommended Arch, but other distros should work, too)

* gcc >= 11 recommended (deprecated versions are not supported: https://gcc.gnu.org/)

* OpenCL and OpenCL Headers installed

* libopenssl and openssl-dev installed

* librt and librt-dev installed (should be installed by default)


Notice
--------------

Most output files will be appended to existing files.


