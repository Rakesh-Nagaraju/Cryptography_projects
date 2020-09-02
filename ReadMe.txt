**********************************************************************************************************************************
*****Rabin Cipher Implementation ReadMe File**************************************************************************************
**********************************************************************************************************************************

Pre-Requisites:
	1.) Add cryptoUtil-1.9.jar in your package by:
	     
             Right-clicking on your package folder ==> select Build Path 
	     ==> select Configure Build Path ==> select from the right tabs "Add External JARs" 
	     ==> select path of cryptoUtil-1.9.jar ==> select Apply and close.

	2.) Key datastructure files:  
             "RabinPrivateKey.java"     "RabinPublicKey.java"
	    
             Place them along with the "RabinSys.java" file path. (For FilePath of "RabinSys.java", check "Main Code" section below.)
             
             Note: If you place these files in different path make sure to import 
                   that path using "import" command in both "RabinSys.java" and "RabinSysTest.java".

  
1.) Main Code: "RabinSys.java"
    
    Place the above mentioned java code in package edu.sjsu.crypto.ciphersys.publicKey; 
    (Optional: You can also place "RabinPrivateKey.java" and "RabinPublicKey.java" files in the same path).
    Make sure your code is in : src/main/java.
    Make sure cryptoUtil is added in your package.
    

To be Run:

2.) JUnit Test Case: "RabinSysTest.java"
     
     Place the above mentioned java code in package edu.sjsu.crypto.ciphersys.publicKey;
     Make sure your code is in :src/test/java
     Make sure cryptoUtil is added in your package.
     
     Change File_Path appropriately as mentioned in the code comments (along with examples) in "RabinSysTest.java",
     This is for creating and reading public and private key files.

     Note: You can provide any desired path here. 
    
  Run RabinSysTest.java ==> it contains testcase for generating keys, encryption and decryption.



*****For additional queries, check screenshots in the Report or contact Rakesh Nagaraju at rakesh.nagaraju@sjsu.edu***************