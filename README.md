RSAKeyGenerator
==============

A simple utility class that generates a RSA PGPPublicKey/PGPSecretKey pair.

When you have the requirement to generate a RSA PGPPublicKey/PGPSecretKey pair programatically, there are the libraries from [The Legion of Bouncy Castle](https://www.bouncycastle.org/), that can be used for that purpose.

Although it is straight forward to generate a key pair, the generated keys do not have set a key expiration time.

To set a key expiration time, there is a little more work to do.

This utility class contains the necessary PGPSignatureSubpacketVector to achieve this.

##Configuration

The most important parameters for key generation can be configured directly in the source code.

**key length**

    // Length of generated key in bits
    kpg.initialize(2048);

**expiration date of the keys**

    // ExpirationTime of generated key in seconds
    svg.setKeyExpirationTime(true, 86400L * 366 * 2);

Please note that this is provided in seconds from the key generation date. The above value would be two years in future.

##Dependencies

This class needs two Bouncy Castle [libraries](http://www.bouncycastle.org/latest_releases.html) in order to compile and run:

* bcprov-jdk15on-150.jar and
* bcpg-jdk15on-150.jar

##JCE Unlimited Strength Jurisdiction Policy Files

Bouncy Castle itself requires the *Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files 7* to be installed with the JDK. These can be obtained directly from [Oracle](http://www.oracle.com/technetwork/java/javase/downloads/index.html)

##License

Copyright (c) 2014 Ralph Plawetzki, http://purejava.org. This program is licensed under the GNU General Public License (GPL) version 3.
