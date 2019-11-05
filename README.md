### AES Differential Power Analysis POC
This repository is forked from [tiny-AES-C](https://github.com/kokke/tiny-AES-c) and add POC to demonstrate AES Differential Power Analysis(=DPA).

Since last round of AES encryption doesn't have MixColumn, there are direct relationship between output cipher text and AES key.

To be more specific, if we can have a hamming-distance between output cipher text and last block of expand key for a larget number of pattern, we can guess actual AES key. AES key can be calculated back from the last block of expand key.

#### DPA Requirement
To guess the actual AES key by DPA, the following conditions are required:

- a number of AES operation can be issued to generate for each different output. 
- output cipher text can be observed.
- hamming-distance can be observed.

Detecting actual hamming-distance might be difficult but if there is relationship between power consumption and hamming-distance and if we can observe power consumption, we can use it instead of hamming-distance.

This POC is running on the ideal condition which can detect actual hamming-distance directly by modifying AES function, but if we can observe power consumption, same strategy can be adopted.
