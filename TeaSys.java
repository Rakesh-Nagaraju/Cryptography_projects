//Assignment 6: TEA Cipher//
package edu.sjsu.crypto.ciphersys.block;

import edu.sjsu.yazdankhah.crypto.util.abstracts.TeaAbs;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.ConversionUtil;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.StringUtil;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.DWord;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.Word;

//Name : Rakesh Nagaraju;     Customer Name: Inhee Park//
public class TeaSys extends TeaAbs {
	private Word[] SK = new Word[4];

	// Constructor that take pass and generates Key of 128 bits.
	public TeaSys(String pass) {
		String reg1 = StringUtil.rightTruncRightPadWithZeros(ConversionUtil.textToBinStr(pass), KEY_SIZE_BITS);
		SK = ConversionUtil.binStrToWordArr(reg1);
	}

	// Decrypt method; converts encrypted text and display recovered plaintext.
	// Contains DecryptOneBlock method call.
	@Override
	public String decrypt(String ciphertext) {

		DWord[] CtextBlock = ConversionUtil.hexStrToDWordArr(ciphertext);
		DWord[] PtextBlock = new DWord[CtextBlock.length];
		for (int i = 0; i < CtextBlock.length; i++) {
			PtextBlock[i] = DecryptOneBlock(CtextBlock[i], SK);
		}
		String plaintext = ConversionUtil.dwordArrToText(PtextBlock);
		return plaintext.trim();
	}

	// DecryptOneBlock: implemented as specified in the algorithm
	// Returns one word.
	private DWord DecryptOneBlock(DWord C, Word[] SK) {

		Word L = C.leftWord();// CLis left word of C.
		Word R = C.rightWord();// CRis right word of C.

		Word sum = DELTA_WORD.shiftLeft(5);
		for (int r = 1; r <= ROUNDS; r++) {
			R = R.subtractMod2p32(
					L.shiftLeft(4).addMod2p32(SK[2]).xorM(L.addMod2p32(sum).xorM(L.shiftRight(5).addMod2p32(SK[3]))));
			L = L.subtractMod2p32(
					R.shiftLeft(4).addMod2p32(SK[0]).xorM(R.addMod2p32(sum).xorM(R.shiftRight(5).addMod2p32(SK[1]))));
			sum = sum.subtractMod2p32(DELTA_WORD);
		}
		Word[] dummy = new Word[2];
		dummy[0] = L;
		dummy[1] = R;
		return DWord.constructFromWordArr(dummy);
	}

	// Encrypt method; converts decrypted text and display ciphered text.
	// Contains EncryptOneBlock method call.
	@Override
	public String encrypt(String plaintext) {
		DWord[] PtextBlock = ConversionUtil.textToDWordArr(plaintext);
		DWord[] CtextBlock = new DWord[PtextBlock.length];
		for (int i = 0; i < PtextBlock.length; i++) {
			CtextBlock[i] = EncryptOneBlock(PtextBlock[i], SK);
		}
		String ciphertext = ConversionUtil.dwordArrToHexStr(CtextBlock);
		return ciphertext;
	}

	// EncryptOneBlock: implemented as specified in the algorithm
	// Returns one word.
	private DWord EncryptOneBlock(DWord P, Word[] SK) {
		Word L = P.leftWord();
		Word R = P.rightWord();
		Word sum = Word.ZERO_WORD;
		for (int r = 1; r <= ROUNDS; r++) {
			sum = (sum.addMod2p32(DELTA_WORD));
			L = L.addMod2p32(
					R.shiftLeft(4).addMod2p32(SK[0]).xorM(R.addMod2p32(sum).xorM(R.shiftRight(5).addMod2p32(SK[1]))));
			R = R.addMod2p32(
					L.shiftLeft(4).addMod2p32(SK[2]).xorM(L.addMod2p32(sum).xorM(L.shiftRight(5).addMod2p32(SK[3]))));
		}
		Word[] dummy = new Word[2];
		dummy[0] = L;
		dummy[1] = R;
		return DWord.constructFromWordArr(dummy);
	}

}
//END//