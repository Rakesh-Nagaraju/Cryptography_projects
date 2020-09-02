/**
 * Assignment 9: RSA Public-Key Cipher//
 */
package edu.sjsu.crypto.ciphersys.publicKey;

import java.math.BigInteger;
import java.util.Random;

import edu.sjsu.yazdankhah.crypto.util.abstracts.RsaAbs;
import edu.sjsu.yazdankhah.crypto.util.ciphersysdatatypes.RsaPrivateKey;
import edu.sjsu.yazdankhah.crypto.util.ciphersysdatatypes.RsaPublicKey;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.ConversionUtil;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.Function;
import lombok.Data;
import lombok.EqualsAndHashCode;

/**
 * Name : Rakesh Nagaraju; Customer Name: Inhee Park, Tracy Ho//
 * 
 * @author Rakesh Nagaraju
 *
 */

@Data
@EqualsAndHashCode(callSuper = false)
public class RsaSys extends RsaAbs {
	private RsaPublicKey publicKey;
	private RsaPrivateKey privateKey;

	/**
	 * Constructor initializing RSA Public and Private Key.
	 */
	public RsaSys() {
		publicKey = new RsaPublicKey(null, null, null);
		privateKey = new RsaPrivateKey(null, null);
	}

	/**
	 * Decrypt method, takes in Ciphertext and returns plaintext.
	 */
	@Override
	public String decrypt(String ciphertext, RsaPrivateKey PrivateKey) {
		BigInteger[] CBlock = ConversionUtil.hexStrToBigIntegerArr(ciphertext, CIPHER_BLOCK_SIZE_BITS);
		BigInteger[] PBlock = new BigInteger[CBlock.length];
		for (int i = 0; i <= CBlock.length - 1; i++) {
			PBlock[i] = DecryptOneBlock(CBlock[i], PrivateKey);
		}
		String Plaintext = ConversionUtil.bigIntegerArrToText(PBlock, PLAIN_BLOCK_SIZE_BITS);
		return Plaintext.trim();
	}

	/**
	 * Decrypt One block method where we get d, n from the private_key, M is
	 * calculated by using modpow(d, N)
	 * 
	 * @param decrypt_block
	 * @param private_key
	 * @return
	 */
	private BigInteger DecryptOneBlock(BigInteger decrypt_block, RsaPrivateKey private_Key) {
		BigInteger d = private_Key.getD();
		BigInteger N = private_Key.getN();
		BigInteger M = decrypt_block.modPow(d, N);
		return M;
	}

	@Override
	public String encrypt(String plaintext, RsaPublicKey PublicKey) {
		BigInteger[] PBlock = ConversionUtil.textToBigIntegerArr(plaintext, PLAIN_BLOCK_SIZE_BITS);
		BigInteger[] CBlock = new BigInteger[PBlock.length];
		for (int i = 0; i <= PBlock.length - 1; i++) {
			CBlock[i] = EncryptOneBlock(PBlock[i], PublicKey);
		}
		String ciphertext = ConversionUtil.bigIntegerArrToHexStr(CBlock, CIPHER_BLOCK_SIZE_BITS);
		return ciphertext;
	}

	/**
	 * Encrypt method, takes plaintext as input along with public key to return
	 * ciphertext.
	 */
	private BigInteger EncryptOneBlock(BigInteger encrypt_block, RsaPublicKey public_Key) {
		BigInteger e = public_Key.getE();
		BigInteger N = public_Key.getN();
		BigInteger C = encrypt_block.modPow(e, N);
		return C;
	}

	/**
	 * Generate Keys, generates public and private key using pass and Key holder
	 * name of 64 Knapsack size bits.
	 */
	@Override
	public void generateKeys(String pass, String KeyHolderName) {
		Random rnd = Function.getRandomGenerator64(pass);
		BigInteger p = Function.generateRandomPrimeBigInteger(P_SIZE_BITS, rnd);
		BigInteger q = Function.generateRandomPrimeBigInteger(Q_SIZE_BITS, rnd);
		BigInteger N = p.multiply(q);
		BigInteger e = Function.generateRandomPrimeBigInteger(E_SIZE_BITS, rnd);
		BigInteger mult_bits = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		BigInteger d = e.modInverse(mult_bits);
		publicKey.setN(N);
		publicKey.setHolderName(KeyHolderName);
		publicKey.setE(e);
		privateKey.setN(N);
		privateKey.setD(d);

	}

}
/** END **/
