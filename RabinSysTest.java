/**
 * CS265 Project: Rabin Cipher Implementation
 * 
 * JUnit Test Program RabinSysTest.java
 * 
 * Name: Rakesh Nagaraju; Student ID: 014279304
 * 
 * @author Rakesh Nagaraju
 * 
 */
package edu.sjsu.crypto.ciphersys.publicKey;

import org.junit.jupiter.api.Test;
import edu.sjsu.crypto.ciphersys.publicKey.RabinSys;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class RabinSysTest {

	@Test
	/**
	 * Generate key method where we provide pass, Account holder name, specify path
	 * for the public/private keys. Create an object of Rabin Sys, call
	 * sys.generateKeys(), save the files, print the generated keys on the console.
	 */
	void generateKeys() {
		String pass = "Rabin2020";
		String keyHolderName = "Rakesh";
		/**
		 * Provide File_Path below. Example: C:\\Desktop.
		 */
		String publicKeyFile = "File_Path\\RabinPublicKey.txt";
		String privateKeyFile = "File_Path\\RabinPrivateKey.txt";
		RabinSys sys = new RabinSys();
		sys.generateKeys(pass, keyHolderName);
		sys.getPrivateKey().save(privateKeyFile);
		sys.getPublicKey().save(publicKeyFile);
		log.info("Private Key = [\n" + sys.getPrivateKey() + "\n]\n");
		log.info("Public Key = [\n" + sys.getPublicKey() + "\n]\n");
	}

	@Test
	/**
	 * Encrypt method, we provide plaintext and specify file path and restore public
	 * key, create an object of RabinSys(), call sys.encrypt() method and print the
	 * ciphered text on the console.
	 */
	void encrypt_text() {
		String plaintext = "Hi!!!!Hello";
		/**
		 * Provide File_Path below. Example: C:\\Desktop.
		 */
		String publicKeyFile = "File_Path\\RabinPublicKey.txt";
		RabinSys sys = new RabinSys();
		sys.getPublicKey().restore(publicKeyFile);
		log.info("ciphertext = [" + sys.encrypt(plaintext, sys.getPublicKey()) + "]");
	}

	@Test
	/**
	 * Decrypt method, we provide cipheredtext and specify file path and restore
	 * private key, create an object of RabinSys(), call sys.decrypt() method and
	 * print the plaintext on the console.
	 */
	void decrypt_text() {
		String ciphertext = "3d8701e2088ed38443ef98939bbbe26842c2ad27c0d096c01af3a1c5e60f0da0";
		/**
		 * Provide File_Path below. Example: C:\\Desktop.
		 */
		String privateKeyFile = "File_Path\\RabinPrivateKey.txt";
		RabinSys sys = new RabinSys();
		sys.getPrivateKey().restore(privateKeyFile);
		log.info("PlaintextR = [" + sys.decrypt(ciphertext, sys.getPrivateKey()) + "]");
	}

}
/**
 * END.
 **/
