//Assignment 5: Cmea Cipher//
package edu.sjsu.crypto.ciphersys.block;

import edu.sjsu.yazdankhah.crypto.util.abstracts.CmeaAbs;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.ConversionUtil;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.StringUtil;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.UByte;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.Word;

//Name : Rakesh Nagaraju;     Customer Name: Inhee Park//

public class CmeaSys extends CmeaAbs {
	UByte[] k = new UByte[8];

	// Constructor to take pass and generate Key.
	public CmeaSys(String pass) {
		String reg1 = StringUtil.toDividableByNRightPadZero(
				StringUtil.rightTruncRightPadWithZeros(ConversionUtil.textToBinStr(pass), KEY_SIZE_BITS), 32);
		k = ConversionUtil.binStrToUByteArr(reg1);
	}

	// Decrypt method; converts encrypted text and display recovered plaintext.
	@Override
	public String decrypt(String arg0) {

		Word[] CtextBlock = ConversionUtil.hexStrToWordArr(arg0);
		Word[] PtextBlock = new Word[CtextBlock.length];
		for (int i = 0; i < CtextBlock.length; i++) {
			PtextBlock[i] = EncryptOneBlock(CtextBlock[i]);
		}
		String plaintext = ConversionUtil.wordArrToText(PtextBlock);
		return plaintext.trim();

	}

	// Encrypt method; encrypts the plaintext to generate encrypted text.
	@Override
	public String encrypt(String arg0) {

		Word[] PtextBlock = ConversionUtil.textToWordArr(arg0);
		Word[] CtextBlock = new Word[PtextBlock.length];
		for (int i = 0; i < PtextBlock.length; i++) {
			CtextBlock[i] = EncryptOneBlock(PtextBlock[i]);
		}
		String ciphertext = ConversionUtil.wordArrToHexStr(CtextBlock);
		return ciphertext;
	}

	// Encrypt one block method; flow same as mentioned in the algorithm.
	private Word EncryptOneBlock(Word word) {
		UByte[] pM = word.toUByteArr();
		Round_1(pM);
		Round_2(pM);
		UByte[] c = Round_3(pM);
		return Word.constructFromUByteArr(c);
	}

	// Round 2 method; flow same as mentioned in the algorithm.
	// input is one block of plaintext.floor function ; n = size of pM[]
	private void Round_2(UByte[] pM) {

		int h = pM.length / 2;
		for (int i = 0; i < h; i++) {
			UByte t = pM[pM.length - 1 - i].or(UByte.ONE());
			pM[i] = pM[i].xor(t);
		}
	}

	// Round 3 method; flow same as mentioned in the algorithm.
	// input is one block of plaintext. Output is one block of ciphertext;
	private UByte[] Round_3(UByte[] pM) {
		UByte z = UByte.ZERO();
		UByte[] c = new UByte[pM.length];
		for (int i = 0; i < pM.length; i++) {
			UByte k1 = T(z.xor(UByte.constructFromInteger(i)));
			z = z.addMod256M(pM[i]);
			c[i] = pM[i].subtractMod256M(k1);
		}
		return c;
	}

	// Round 1 method; flow same as mentioned in the algorithm.
	// input is one block of plaintext.
	private void Round_1(UByte[] pM) {
		UByte z = UByte.ZERO();
		for (int i = 0; i < pM.length; i++) {
			pM[i] = pM[i].addMod256M(T(z.xor(UByte.constructFromInteger(i))));
			z = z.addMod256M(pM[i]);
		}
	}

	// T method that performs Cave Lookup Operations; flow same as mentioned in the
	// algorithm.
	private UByte T(UByte arg0) {
		UByte Qx = CAVE_LOOKUP.lookUp(arg0.xor(k[0]).addMod256M(k[1])).addMod256M(arg0);
		UByte Rx = CAVE_LOOKUP.lookUp(Qx.xor(k[2]).addMod256M(k[3])).addMod256M(arg0);
		UByte Sx = CAVE_LOOKUP.lookUp(Rx.xor(k[4]).addMod256M(k[5])).addMod256M(arg0);
		return CAVE_LOOKUP.lookUp(Sx.xor(k[6]).addMod256M(k[7])).addMod256M(arg0);

	}

}
//END//