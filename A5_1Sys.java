//Assignment 3: A5/1 Cipher//
package edu.sjsu.crypto.ciphersys.classic;

import edu.sjsu.yazdankhah.crypto.util.abstracts.A5_1Abs;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.ConversionUtil;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.Function;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.StringUtil;
import edu.sjsu.yazdankhah.crypto.util.primitivedatatypes.Bit;
import edu.sjsu.yazdankhah.crypto.util.shiftregisters.LFSR;

//Name : Rakesh Nagaraju;     Customer Name: Inhee Park//

public class A5_1Sys extends A5_1Abs {
	// 3 LFSR's X,Y,Z Initialization.
	private LFSR X;
	private LFSR Y;
	private LFSR Z;

	// Constructor takes pass as key, makes it 64 bit and allocate it three LFSR's
	// X(19), Y(22), Z(23).
	public A5_1Sys(String pass) {
		String reg1 = StringUtil.rightTruncRightPadWithZeros(ConversionUtil.textToBinStr(pass), 64);
		int[] X_taps = { 13, 16, 17, 18 };
		int[] Y_taps = { 20, 21 };
		int[] Z_taps = { 7, 20, 21, 22 };
		String X_val = reg1.substring(0, 19);
		String Y_val = reg1.substring(19, 41);
		String Z_val = reg1.substring(41);
		X = LFSR.constructFromBinStr(X_val, X_taps);
		Y = LFSR.constructFromBinStr(Y_val, Y_taps);
		Z = LFSR.constructFromBinStr(Z_val, Z_taps);
	}

	// Decrypt method: Converts ciphertext to binary string ,
	// then converts it to Bit array and then calls a call_meth()
	// then returns the string text of bit-array as Plaintext .
	@Override
	public String decrypt(String arg0) {
		String binary = ConversionUtil.hexStrToBinStr(arg0);
		Bit[] bin = ConversionUtil.binStrToBitArr(binary);
		Bit[] deciphers = new Bit[bin.length];
		deciphers = call_meth(bin, deciphers);
		return (ConversionUtil.binStrToText(ConversionUtil.bitArrToBinStr(deciphers)));
	}

	// Encrypt method: Converts text to binary string ,
	// then converts it to Bit array and then calls a call_meth()
	// then returns the hex of bit-array as Ciphertext .
	@Override
	public String encrypt(String arg0) {
		String binary = ConversionUtil.textToBinStr(arg0);
		Bit[] bin = ConversionUtil.binStrToBitArr(binary);
		Bit[] ciphers = new Bit[bin.length];
		ciphers = call_meth(bin, ciphers);
		return ConversionUtil.bitArrToHexStr(ciphers);
	}

	// Method to generate Key for every stream.Foolows the algorithm of
	// key-generation in A5/1.
	@Override
	public Bit generateKey() {
		Bit[] maj_val = { X.bitAt(8), Y.bitAt(10), Z.bitAt(10) };
		Bit Gx = Bit.zero();
		Bit Gy = Bit.zero();
		Bit Gz = Bit.zero();
		Bit m = Function.maj(maj_val);
		if (m.equal(X.bitAt(8))) {
			Gx = X.stepM();
		}
		if (m.equal(Y.bitAt(10))) {
			Gy = Y.stepM();
		}
		if (m.equal(Z.bitAt(10))) {
			Gz = Z.stepM();
		}
		Bit K = (Gx.xorM(Gy)).xorM(Gz);
		return K;
	}

	// Method called by encrypt and decrypt methods,
	// Generate keystream and XOR it with every bit.
	public Bit[] call_meth(Bit[] bin, Bit[] dummy) {
		for (int i = 0; i < bin.length; i++) {
			Bit keystream = generateKey();
			dummy[i] = (bin[i].xor(keystream));
		}
		return dummy;
	}
}
//END
