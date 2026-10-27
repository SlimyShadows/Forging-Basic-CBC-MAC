# Assignment 4: Forging Basic CBC-MAC

Name:
* Dante Ruzic

Language Used:
* Java (OpenJDK 17 / Java SE 17+)

AES Library:
* Java Cryptography Architecture (`javax.crypto`)

Build/Test:
* Makefile is used by running:
```
C:\Users\[user]\Documents\GitHub\Forging Basic CBC-MAC> make tests(test, demo, all, tests)
```
For automated testing.
```
C:\Users\[user]\Documents\GitHub\Forging Basic CBC-MAC> javac CBCMAC.java CBCMACTest.java 
C:\Users\[user]\Documents\GitHub\Forging Basic CBC-MAC> java CBCMACTest
```
To run the files without makefile
```
C:\Users\[user]\Documents\GitHub\Forging Basic CBC-MAC> javac CBCMAC.java
C:\Users\[user]\Documents\GitHub\Forging Basic CBC-MAC> java CBCMAC mac (xxx) (xxx)
C:\Users\[user]\Documents\GitHub\Forging Basic CBC-MAC> java CBCMAC verify (xxx) (xxx) (xxx)
C:\Users\[user]\Documents\GitHub\Forging Basic CBC-MAC> java CBCMAC forge (xxx)
```
To manually run each command in the commandline. Computing tag, verifying, and forge tag.


 Limitations: 
* System used for this was Windows, therefore any examples or ways to run the code have only been tested on Powershell and Command Line.

 Disclosure:
* I used A.I. to help with mathematical proof understanding if anything did not make sense, such as using Mark Down for mathematics (as finding XOR symbols, etc).
* I verified the Mark Down using the following site "https://markdownviewer.org/".