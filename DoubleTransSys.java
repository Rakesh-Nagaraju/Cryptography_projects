//Assignment 2: Double Transposition Cipher//
package edu.sjsu.crypto.ciphersys.classic;
import edu.sjsu.yazdankhah.crypto.util.abstracts.DoubleTransAbs;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.ConversionUtil;
import edu.sjsu.yazdankhah.crypto.util.matrixdatatypes.CharMatrix;

//Name : Rakesh Nagaraju;     Customer Name: Inhee Park//

public class DoubleTransSys extends DoubleTransAbs {
	
	//Variables to store rows permutation and column permutation//
	private static int [] rowsPerms;
	private static int [] colsPerms;

	//Constructor//
	public DoubleTransSys(int[] rowsPerm, int[] colsPerm) {
		rowsPerms = rowsPerm;
		colsPerms = colsPerm;
			}
	
	//Decrypting method, inverse permuting columns first and rows next,
	//Trimming the leading and trailing spaces of the plaintext before returning//
	@Override
	public String decrypt(String arg0) {
		CharMatrix[] input = ConversionUtil.textToCharMatrixArr(rowsPerms.length,colsPerms.length,arg0);
		for (int i = 0; i < input.length; i++) {
			input[i].inversePermuteColsM(colsPerms);
		}
		for (int i = 0; i < input.length ; i++) {
			input[i].inversePermuteRowsM(rowsPerms);
		}	
		return ConversionUtil.charMatrixArrToText(input).toLowerCase().trim();
	}
	
	//Encrypting method, permuting rows first and columns next,
	//Trimming the leading and trailing spaces of the plaintext before encrypting//
	@Override
	public String encrypt(String arg0) {
		CharMatrix[] input = ConversionUtil.textToCharMatrixArr(rowsPerms.length,colsPerms.length,arg0.trim());
		for (int i = 0; i < input.length ; i++) {
			input[i].permuteRowsM(rowsPerms);
		}
		for (int i = 0; i < input.length; i++) {
			input[i].permuteColsM(colsPerms);
		}
		return ConversionUtil.charMatrixArrToText(input).toUpperCase();
	}

}
//END//

