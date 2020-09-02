//Assignment 4: Pkzip Cipher//
package edu.sjsu.crypto.ciphersys.stream;

import edu.sjsu.yazdankhah.crypto.util.abstracts.PkzipAbs;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.ConversionUtil;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.StringUtil;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.UByte;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.Word;

//Name : Rakesh Nagaraju;     Customer Name: Inhee Park//

public class PkzipSys extends PkzipAbs {
	private Word X;
	private Word Y;
	private Word Z;

	// Constructor to initialize X,Y,Z by parsing Pass(Key).
	public PkzipSys(String pass) {
		String reg1 = StringUtil.rightTruncRightPadWithZeros(ConversionUtil.textToBinStr(pass), KEY_SIZE_BITS);
		X = Word.constructFromBinStr(reg1.substring(0, 32));
		Y = Word.constructFromBinStr(reg1.substring(32, 64));
		Z = Word.constructFromBinStr(reg1.substring(64));
	}

	// CRC function, structured defined exactly as in the algorithm.
	@Override
	public void CRC(Word arg0, UByte arg1) {

		arg0.xorM(Word.constructFromUByte(arg1));
		for (int i = 0; i < CRC_ITERATION; i++) {
			arg0.shiftRightM(1);
			if (arg0.toLong() % 2 != 0) {
				arg0.xorM(CRC_CONST_WORD);
			}
		}
	}

	// Decrypt function, converts ciphertext to UByteArray and for every byte,
	// generates key,
	// Xor's textbyte with key byte to get decrypted text.
	@Override
	public String decrypt(String arg0) {
		UByte[] bin = ConversionUtil.hexStrToUByteArr(arg0);
		UByte[] deciphers = new UByte[bin.length];
		for (int i = 0; i < bin.length; i++) {
			UByte keystream = generateKey(Z);
			deciphers[i] = bin[i].xorM(keystream);
			update(X, Y, Z, bin[i]);
		}
		return (ConversionUtil.binStrToText(ConversionUtil.ubyteArrToBinStr(deciphers)));
	}

	// Encrypt function, converts plaintext to UByteArray and for every byte,
	// generates key,
	// Xor's textbyte with key byte to get hex-converted encrypted text.
	@Override
	public String encrypt(String arg0) {

		UByte[] bin = ConversionUtil.textToUByteArr(arg0);
		UByte[] ciphers = new UByte[bin.length];
		for (int i = 0; i < bin.length; i++) {
			UByte keystream = generateKey(Z);
			ciphers[i] = bin[i].xor(keystream);
			update(X, Y, Z, bin[i]);
		}
		return ConversionUtil.ubyteArrToHexStr(ciphers);
	}

	// Generate key function, structure defined exactly as in the algorithm.
	@Override
	public UByte generateKey(Word arg0) {
		Word t = null;
		Word k = null;
		t = arg0.or(THREE_WORD).rightHalfAsWord();
		k = t.multiplyMod2p32(t.xor(Word.ONE_WORD)).shiftRightM(KEY_GENERATION_SHIFTS);
		return k.byteAt(3);
	}

	// Update function, structure defined exactly as in the algorithm.
	@Override
	public void update(Word arg0, Word arg1, Word arg2, UByte arg3) {
		CRC(arg0, arg3);
		arg1.addMod2p32M(Word.constructFromUByte(arg0.byteAt(3))).multiplyMod2p32M(UPDATE_CONST_WORD)
				.addMod2p32M(Word.ONE_WORD);
		CRC(arg2, arg1.byteAt(0));
	}
}
//END//
