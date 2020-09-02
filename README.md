# Cryptography_projects
Implementation of Simple substitution cipher, Double Transposition cipher, A5, Tea, Cmea, Knapsack, Pkzip, RSA, Rabin cipher.

# Instructions:

1.) Gitclone this repository.

2.) Install Java 8 or above, jdk13 or above and lombok. For more installation info visit: https://projectlombok.org/download.

3.) Add CryptoUtil-1.9 jar as the external library. 

4.) Create a Maven Project and place this folder.

5.) Create a Junit Test Case to run and check the results as follow:
   * JUnit Test Program
      package edu.sjsu.crypto.ciphersys.publicKey;

      import org.junit.jupiter.api.Test;
      import edu.sjsu.crypto.ciphersys.publicKey.RabinSys;
      import lombok.extern.slf4j.Slf4j;

      @Slf4j
      public class Prog_name_Test {

    	@Test
	   void key_gen_function() {
         Call respective classes and pass parameters to generate key and print as below;
       log.info("Private Key = [\n" + sys.getPrivateKey() + "\n]\n");
		   log.info("Public Key = [\n" + sys.getPublicKey() + "\n]\n");
    	}

      @Test
        void encrypt_function() {
        String plaintext = "Hi!!!!Hello";
          Call Object and pass parmeters to call cipher function and print ciphered text below;
        log.info("ciphertext = [" + sys.encrypt(plaintext, sys.getPublicKey()) + "]");
      }
      
      @Test
      void decrypt_text() {
        String ciphertext = "3d8701e2088ed38443ef98939bbbe26842c2ad27c0d096c01af3a1c5e60f0da0";
          #Call object, pass parameters and call decipher function and print deciphered text as in below;
        log.info("PlaintextR = [" + sys.decrypt(ciphertext, sys.getPrivateKey()) + "]");
      }
     }
     
  Replace the function name and follow comments as above for respective cipher programs. For Eg refer RabinSysTest.java file in the repo.

6.) For any additional queries contact me at rakesh.nagaraju@sjsu.edu or rakenju@gamil.com .
