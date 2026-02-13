Well, I made some alterations to my old C version of my HMAC cipher. It uses some non-portable API's in order to try to get a TRNG. It prints out its usage, just run the program with no arguments, look in ct_help.

Well, can anybody else get it to compile _and_ run on their end? Thanks everybody!

The secret key is hardcoded to Password and SHA2-512:

____________________________________
/*
    Chris M. Thomasson 6/4/2018
    Experimental HMAC Cipher
    C version with hardcoded secret key

    FIXED VERSION: Now uses proper TRNG (/dev/urandom on Unix, CryptGenRandom on Windows)

    Using the following HMAC lib:
    https://github.com/ogay/hmac

    Here is some info on my cipher:
    http://funwithfractals.atspace.cc/ct_cipher
________________________________________________________*/
