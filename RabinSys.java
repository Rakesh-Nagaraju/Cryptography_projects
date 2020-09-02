/**
 * CS265 Project: Rabin Cipher Implementation
 * 
 * Main Implementation Program RabinSys.java
 * 
 * Name: Rakesh Nagaraju; Student ID: 014279304
 * 
 * @author Rakesh Nagaraju
 * 
 */
package edu.sjsu.crypto.ciphersys.publicKey;

import java.math.BigInteger;
import java.util.Random;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.ConversionUtil;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.Function;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = false)
public class RabinSys {

	private RabinPublicKey publicKey;
	private RabinPrivateKey privateKey;
	private Random rnd;
	private String plaintext_R = null;

	private static final int Rabin_Key_Bits = 128;
	private static final int Pass_Size_Bits = 8;
	private static final int Cipher_Size_Bits = 256;
	private static BigInteger TWO = BigInteger.valueOf(2);
	private static BigInteger THREE = BigInteger.valueOf(3);
	private static BigInteger FOUR = BigInteger.valueOf(4);

	/**
	 * Constructor initializing Rabin Public and Private Key.
	 */
	public RabinSys() {
		publicKey = new RabinPublicKey(null, null);
		privateKey = new RabinPrivateKey(null, null);
	}

	/**
	 * Generate Keys of variable bits. Generates Random Number using pass. makes the
	 * length pass 8 if it is less. Generate P, Q, calculate N Set (P,Q) to private
	 * key and (Account_Holder_Name, N) to the public key.
	 */
	public void generateKeys(String pass, String KeyHolderName) {
		while (pass.length() < Pass_Size_Bits) {
			pass += pass.charAt(0);
		}
		rnd = Function.getRandomGenerator64(pass);
		BigInteger p = null;
		BigInteger q = null;
		do {
			p = Function.generateRandomPrimeBigInteger(Rabin_Key_Bits, rnd);
			q = Function.generateRandomPrimeBigInteger(Rabin_Key_Bits, rnd);
		} while (!p.mod(FOUR).equals(THREE) && !q.mod(FOUR).equals(THREE));

		BigInteger N = p.multiply(q);

		publicKey.setN(N);
		publicKey.setHolderName(KeyHolderName);
		privateKey.setP(p);
		privateKey.setQ(q);
	}

	/**
	 * encrypt method, replicates the plaintext, get N value from public key,
	 * convert text to BigInteger, calculate c using modPow(2,N), return ciphertext
	 * by converting C to hex string.
	 * 
	 * @param plaintext
	 * @param PublicKey
	 * @return
	 */
	public String encrypt(String plaintext, RabinPublicKey PublicKey) {

		// Repeating the text.
		plaintext += plaintext;

		BigInteger PBlock = ConversionUtil.textToBigInteger(plaintext);
		BigInteger N = PublicKey.getN();
		BigInteger C = PBlock.modPow(TWO, N);

		String ciphertext = ConversionUtil.bigIntegerToHexStr(C, Cipher_Size_Bits);
		return ciphertext;
	}

	/**
	 * decrypt method, converts hex ciphertext to biginteger, get P, Q from private
	 * key, calculate N, call Extended_Euclid and Chinese_Rem_Theorem to get 4
	 * possible roots. Choose the correct root and return it as a text.
	 * 
	 * @param ciphertext
	 * @param PrivateKey
	 * @return
	 */
	public String decrypt(String ciphertext, RabinPrivateKey PrivateKey) {

		BigInteger CBlock = ConversionUtil.hexStrToBigInteger(ciphertext);

		BigInteger p = PrivateKey.getP();
		BigInteger q = PrivateKey.getQ();
		BigInteger N = p.multiply(q);

		BigInteger p1 = CBlock.modPow(p.add(BigInteger.ONE).divide(FOUR), p);
		BigInteger p2 = p.subtract(p1);
		BigInteger q1 = CBlock.modPow(q.add(BigInteger.ONE).divide(FOUR), q);
		BigInteger q2 = q.subtract(q1);

		BigInteger[] extended_array = Extended_Euclid(p, q);
		BigInteger[] PBlocks = Chinese_Rem_Theorem(extended_array, CBlock, p, q, p1, p2, q1, q2, N);

		for (BigInteger c : PBlocks) {
			String result = ConversionUtil.bigIntegerToText(c, Cipher_Size_Bits).trim();
			final int mid = result.length() / 2;
			String[] parts = { result.substring(0, mid), result.substring(mid) };
			if (parts[0].equals(parts[1])) {
				plaintext_R = parts[0];
			}
		}
		if (plaintext_R == null) {
			plaintext_R = "Ciphertext is Invalid!!!";
		}
		return plaintext_R.trim();
	}

	/**
	 * Implementation of Chinese remainder theorem, calculate and returns 4 possible
	 * roots of the the cipheredtext.
	 * 
	 * @param ext
	 * @param decrypt_block
	 * @param p
	 * @param q
	 * @param p1
	 * @param p2
	 * @param q1
	 * @param q2
	 * @param N
	 * @return
	 */
	private BigInteger[] Chinese_Rem_Theorem(BigInteger[] extended_array, BigInteger decrypt_block, BigInteger p,
			BigInteger q, BigInteger p1, BigInteger p2, BigInteger q1, BigInteger q2, BigInteger N) {

		BigInteger y_p = extended_array[1];
		BigInteger y_q = extended_array[2];

		BigInteger Root_1 = y_p.multiply(p).multiply(q1).add(y_q.multiply(q).multiply(p1)).mod(N);
		BigInteger Root_2 = y_p.multiply(p).multiply(q2).add(y_q.multiply(q).multiply(p1)).mod(N);
		BigInteger Root_3 = y_p.multiply(p).multiply(q1).add(y_q.multiply(q).multiply(p2)).mod(N);
		BigInteger Root_4 = y_p.multiply(p).multiply(q2).add(y_q.multiply(q).multiply(p2)).mod(N);

		return new BigInteger[] { Root_1, Root_2, Root_3, Root_4 };
	}

	/**
	 * Extended_Euclid() method, calculates and returns previous values of S,R,T.
	 * 
	 * @param a
	 * @param b
	 * @return
	 */
	private BigInteger[] Extended_Euclid(BigInteger a, BigInteger b) {

		BigInteger S = BigInteger.ZERO;
		BigInteger Old_S = BigInteger.ONE;
		BigInteger T = BigInteger.ONE;
		BigInteger Old_T = BigInteger.ZERO;

		BigInteger R = b;
		BigInteger Old_R = a;

		while (!R.equals(BigInteger.ZERO)) {
			BigInteger Q = Old_R.divide(R);
			BigInteger Tr = R;
			R = Old_R.subtract(Q.multiply(R));
			Old_R = Tr;

			BigInteger Ts = S;
			S = Old_S.subtract(Q.multiply(S));
			Old_S = Ts;

			BigInteger Tt = T;
			T = Old_T.subtract(Q.multiply(T));
			Old_T = Tt;
		}
		return new BigInteger[] { Old_R, Old_S, Old_T };

	}

}
/**
 * END
 */
