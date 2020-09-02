//Simple Substitution Cipher.
package edu.sjsu.crypto.ciphersys.classic;

import java.util.Map;
import edu.sjsu.yazdankhah.crypto.util.abstracts.SimpleSubAbs;
import edu.sjsu.yazdankhah.crypto.util.shiftregisters.CSR;

//Name:Rakesh Nagaraju ; Customer's Name: Inhee Park.

public class SimpleSubSys extends SimpleSubAbs {
    //Attributes Initialization of Encryption and Decryption hash map.
	private static Map<Character, Character> encryptionTable;
	private static Map<Character, Character> decryptionTable;

	//Constructor contains all Initialized variables.
	public SimpleSubSys(int key) {
		//CSR Regular Alphabet text, Decrypting Alphabet text, Encrypting Alphabet text Initialization.
		CSR text = null;
		CSR decrypt_text = null;
		CSR encrypt_text = null;
		//Populating Alphabets to the Initialized CSR's.
		text = CSR.constructFromText(ENGLISH_ALPHABET_STR);
		decrypt_text = CSR.constructFromText(ENGLISH_ALPHABET_STR.toUpperCase());
		encrypt_text = decrypt_text.clone();
		//Rotate left by key for Encryption.
		encrypt_text.rotateLeftM(key);
		//Mapping to make up Encryption Table.
	    encryptionTable = makeLookupTable(text, encrypt_text);
	    //Rotate right by key for Decryption.
	    text.rotateRightM(key);
		//Mapping to make up Decryption Table.
	    decryptionTable = makeLookupTable(decrypt_text, text);    
	}
	
	@Override
	//Decryption Method.
	public String decrypt(String arg0) {
		//Final Result string.
		char[] result = new char[arg0.length()];
		//Checking for Empty String.
		if (arg0.length() > 0){	
	     for (int i = 0; i< arg0.length(); i++) {
	    	 if (Character.isAlphabetic(arg0.charAt(i))) {
	    		 //Decrypting the message.
	    		 result[i] = decryptionTable.get(arg0.charAt(i));
	    	 }
	    	 else {
	    		 //If character is other than a alphabet, add the character as it is.
	    		 result[i] = arg0.charAt(i);
	    	 }	
		 }
	     //return the decrypted text.
	     return String.valueOf(result);
		}
		else {
		 //If Input is empty return null.
     	 return null;
	    }	
	}

	@Override
	//Encryption Method.
	public String encrypt(String arg0) {
		//Final Result String.
		char[] result = new char[arg0.length()];
		//Checking for Empty String.
		if (arg0.length() > 0){	
	     for (int i = 0; i< arg0.length(); i++) {
	    	 if (Character.isAlphabetic(arg0.charAt(i))) {
	    		 //Encrypting the message.
	    		 result[i] = encryptionTable.get(arg0.charAt(i));
	    	 }
	    	 else {
	    		 //If character is other than a alphabet, add the character as it is.
	    		 result[i] = arg0.charAt(i);
	    	 }	
		 }
	     //return the encrypted text.
	     return String.valueOf(result);
		}
		else {
		 //If Input is empty return null.
       	 return null;
	    }	
	}	
}
//End.