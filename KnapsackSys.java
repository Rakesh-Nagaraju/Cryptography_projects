/**
 * Assignment 8: Knapsack Public-Key Cipher//
 */
package edu.sjsu.crypto.ciphersys.publicKey;

import java.math.BigInteger;
import java.util.Random;

import edu.sjsu.yazdankhah.crypto.util.abstracts.KnapsackAbs;
import edu.sjsu.yazdankhah.crypto.util.ciphersysdatatypes.Knapsack;
import edu.sjsu.yazdankhah.crypto.util.ciphersysdatatypes.KnapsackPrivateKey;
import edu.sjsu.yazdankhah.crypto.util.ciphersysdatatypes.KnapsackPublicKey;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.ConversionUtil;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.Function;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.Bit;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.Word;
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
public class KnapsackSys extends KnapsackAbs {

	private KnapsackPublicKey publicKey;
	private KnapsackPrivateKey privateKey;

	/**
	 * Constructor initializing Knapsack Public and Private Key.
	 */
	public KnapsackSys() {
		publicKey = new KnapsackPublicKey(null, null);
		privateKey = new KnapsackPrivateKey(null, null, null);
	}

	/**
	 * Decrypt method, takes in Ciphertext and returns plaintext.
	 */
	@Override
	public String decrypt(String ciphertext, KnapsackPrivateKey PrivateKey) {
		BigInteger[] bin_cipher = ConversionUtil.hexStrToBigIntegerArr(ciphertext, CIPHER_BLOCK_SIZE_BITS);
		Word[] bin_cipher_p = new Word[bin_cipher.length];
		for (int i = 0; i <= bin_cipher.length - 1; i++) {
			BigInteger P = PrivateKey.getP();
			BigInteger M_inverse = PrivateKey.getM().modInverse(P);
			bin_cipher_p[i] = DecryptOneBlock(bin_cipher[i], M_inverse, P, PrivateKey.getW());
		}
		return ConversionUtil.wordArrToText(bin_cipher_p).trim();
	}

	/**
	 * Decrypt One block method where c prime is calculated and then call
	 * solvesuperincreasing array method to obtain bit array and return as a
	 * word.
	 * 
	 * @param Target
	 * @param val
	 * @param p
	 * @param W
	 * @return
	 */
	private Word DecryptOneBlock(BigInteger Target, BigInteger M_inverse, BigInteger p, Knapsack W) {
		BigInteger C_p = Target.multiply(M_inverse).mod(p);
		Bit[] X = solveSuperIncreasingKnapsack(W, C_p);
		return Word.constructFromBitArr(X);
	}

	/**
	 * Encrypt method, takes plaintext as input along with public key to return
	 * ciphertext
	 */
	@Override
	public String encrypt(String plaintext, KnapsackPublicKey PublicKey) {

		Word[] PtextBlock = ConversionUtil.textToWordArr(plaintext);
		BigInteger[] CtextBlock = new BigInteger[PtextBlock.length];

		for (int i = 0; i <= PtextBlock.length - 1; i++) {
			CtextBlock[i] = EncryptOneBlock(PtextBlock[i], PublicKey.getWp());
		}
		String ciphertext = ConversionUtil.bigIntegerArrToHexStr(CtextBlock, CIPHER_BLOCK_SIZE_BITS);
		return ciphertext;
	}

	/**
	 * Encrypt One Block method which encrypts one block, by converting each word to
	 * bit array and does sum selective on W prime.
	 * 
	 * @param ptextBlock
	 * @param wp
	 * @return
	 */
	private BigInteger EncryptOneBlock(Word ptextBlock, Knapsack wp) {
		Bit[] M = ptextBlock.toBitArr();
		BigInteger CSum = wp.sumSelective(M);
		return CSum;
	}

	/**
	 * Generate Keys, generates public and private key using pass and Key holder
	 * name of 32 Knapsack size bits.
	 */
	@Override
	public void generateKeys(String pass, String KeyHolderName) {
		Random rnd = Function.getRandomGenerator64(pass);
		BigInteger[] w = new BigInteger[KNAPSACK_SIZE];
		w[0] = Function.generateRandomPositiveInteger(rnd);
		for (int i = 1; i <= w.length - 1; i++) {
			BigInteger k = BigInteger.ZERO;
			for (int j = 0; j <= i - 1; j++) {
				k = k.add(w[j]);
			}
			w[i] = k.add(Function.generateRandomPositiveInteger(rnd));
		}
		Knapsack W = Knapsack.constructFromSuperIncreasingArr(w);
		BigInteger m = Function.generateRandomPositiveInteger(rnd);
		BigInteger p = Function.generateRandomPrimeBigIntegerBiggerThan(W.sum(), rnd);
		Knapsack w_p = W.toRegularKnapsack(m, p);
		W.setRnd(rnd);
		W.setSize(KNAPSACK_SIZE);
		w_p.setRnd(rnd);
		w_p.setSize(KNAPSACK_SIZE);
		publicKey.setWp(w_p);
		publicKey.setHolderName(KeyHolderName);
		privateKey.setW(W);
		privateKey.setM(m);
		privateKey.setP(p);

	}

	/**
	 * Solve SuperIncreasing Array, solves super increasing array(W) to generate Bit
	 * array using Target as sum .
	 */
	@Override
	public Bit[] solveSuperIncreasingKnapsack(Knapsack W, BigInteger Target) {
		Bit[] X = new Bit[W.getSize()];
		for (int i = W.getSize() - 1; i >= 0; i--) {
			if (W.memberAt(i).compareTo(Target) <= 0) {
				X[i] = Bit.one();
				Target = Target.subtract(W.memberAt(i));
			} else {
				X[i] = Bit.zero();
			}
		}
		return X;
	}

}
/**
 * END
 */
