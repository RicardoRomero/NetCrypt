# Encrypt files in chunks with PHP openssl_encrypt

This is heavily borrowed from [http://php.net/manual/en/function.openssl-encrypt.php#120141](http://php.net/manual/en/function.openssl-encrypt.php#120141)

 The difference is that the decryption no longer depends on the chunk size, allowing the resulting cyphertext to be decrypted in one shot by opensss_decrypt. See the tests.

 This code is provided only as reference. This code as-is is NOT suitable for use in production environments.
 
 ### The encrypted file:
 
 - The first 16 bytes contain the initialization vector
 - The next byte contains the decrypted file size modulo 16 in least significant bit positions
 - The rest of the bytes contain the ciphertext
 

 ### Tests

```bash
$ phpunit NetCryptTest.php --testdox
```

 
### References:

* [http://php.net/manual/en/function.openssl-encrypt.php#120141](http://php.net/manual/en/function.openssl-encrypt.php#120141)
* [https://en.wikipedia.org/wiki/Block_size](https://en.wikipedia.org/wiki/Block_size) (cryptography)
* [https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) (CBC)
* [https://www.aescrypt.com/aes_file_format.html](https://www.aescrypt.com/aes_file_format.html) (This class does NOT implement AES format)


### License

[Creative Commons Attribution 3.0 License](https://creativecommons.org/licenses/by/3.0/) (Same as php.net comments)
