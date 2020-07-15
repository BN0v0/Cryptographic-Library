# Cryptographic Library

## Library Analisys 
|Algorithm | 	Key Size         | Block Size |	RAM    |	Flash |
|-----     |:----:             |:----:      |:----:  |:----:  |
|AES	     |128/192/256 bits	 |128 bits    |	0,6 KB |	9,6 KB|
|DES       |	56 bits          | 64 bits    |	0,3 KB |	8,4 KB|
|3DES      | 3 keys of 64 bits | 64 bits    | 0,3 KB |	8,5 KB|
| Blowfish |	32 - 448 bits    | 64 bits    | 0,2 KB | 12,8 KB|


**Note** - It is worth notice that the most RAM consuming algorith (AES) only uses 2,27% of Arduino RAM resources and the most FLASH consuming algorithm (Blowfish) only uses 5% of Arduino available Flash resources.

## Desciption
User-friendly C++ library built to embedded sytems and IoT devices. Built to ensure a level of security to IoT communications, specially to constrained IoT devices. This library includes the encryption algorithms as AES, DES, 3DES or TDES, Blowfish,RSA and includes HMAC with MD5 or SHA256, to sign the messages. 
All encryption algorithms include ECB (Electronic CodeBook) mode and CBC (Cipher-block chaining) in the encryption and decryption process, except RSA.

## Examples 
You have some examples in the examples folders, that can help you using the algorithms.

## Tested
This library has been tested with some test vectores. The Unit Tests are in the Tests folder. 

## Contribution
Everyone who is interested in contribuiting to this project are welcome!! 
You can do it by clonning this repository.

## Issues 
Any detected issue, please report it!

## Support this Work and others
If you like and want to support this kind of work, please support it, and buy me a beer.
Click the following  image:

 <a href="https://www.buymeacoffee.com/techontheline" target="_blank" style="text-decoration: none;">
        <img src="https://i.imgur.com/xkeS95o.png" alt="Buy Me A Beer" style="display: block;margin-left: auto; margin-right: auto; margin-top: 5px;" >
 </a>

