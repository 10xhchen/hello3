import java.io.*;
import java.security.*;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

import sun.misc.BASE64Encoder;


public class mima {
	private static String Digest;
	private static boolean flag=true;
	public static void DigestFile(String FileName) throws Exception{  //文件摘要

        MessageDigest md = MessageDigest.getInstance("MD5");

    	BufferedInputStream in = new BufferedInputStream(new FileInputStream(FileName));

    	int theByte = 0;
    	while ((theByte = in.read()) != -1)
    	{
      		md.update((byte)theByte);

    	}
    	in.close();

       // byte[] theDigest = md.digest();
        byte[] theDigest = md.digest();
    	//digest = new BASE64Encoder().encode(theDigest);
        System.out.print("消息摘要:");
        Digest=new BASE64Encoder().encode(theDigest);
    	System.out.println(new BASE64Encoder().encode(theDigest));
}
	private static void createPassword(String password)
	  throws Exception {

	    // Create a new salt
	    SecureRandom random = new SecureRandom();
	    byte[] salt = new byte[12];
	    random.nextBytes(salt);

	    // Get a MessageDigest object
	    MessageDigest md = MessageDigest.getInstance("MD5");
	    md.update(salt);
	    md.update(password.getBytes("UTF8"));
	    byte[] digest = md.digest();

	    // Open up the password file and write the salt and the digest to it.
	    FileOutputStream fos = new FileOutputStream("password");
	    fos.write(salt);
	    fos.write(digest);
	    fos.close();
	  }
	private static boolean authenticatePassword(String password)
	  throws Exception {

	    // Read in the byte array from the file "password"
	    ByteArrayOutputStream baos = new ByteArrayOutputStream();
	    FileInputStream fis = new FileInputStream("password");
	    int theByte = 0;
	    while ((theByte = fis.read()) != -1)
	    {
	      baos.write(theByte);
	    }
	    fis.close();
	    byte[] hashedPasswordWithSalt = baos.toByteArray();
	    baos.reset();

	    byte[] salt = new byte[12];
	    System.arraycopy(hashedPasswordWithSalt,0,salt,0,12);

	    // Get a message digest and digest the salt and
	    // the password that was entered.
	    MessageDigest md = MessageDigest.getInstance("MD5");
	    md.update(salt);
	    md.update(password.getBytes("UTF8"));
	    byte[] digest = md.digest();

		// Get the byte array of the hashed password in the file
	    byte[] digestInFile = new byte[hashedPasswordWithSalt.length-12];
	    System.arraycopy(hashedPasswordWithSalt,12,
	    digestInFile,0,hashedPasswordWithSalt.length-12);

	    // Now we have both arrays, we need to compare them.

	    if (Arrays.equals(digest, digestInFile)) {
	      System.out.println("Password matches.");
	      return true;
	    } else {
	      System.out.println("Password does not match");
	      return false;
	    }
	}
	public static void main (String[] args)
	  throws Exception
	  {
	    if (args.length != 1) {
	      System.err.println("Usage: java SimpleExample FileName");
	      System.exit(1);
	    }
	    String text = args[0];
	    
	    DigestFile(text);  //生成消息摘要
	    
	    System.out.println("请输入加密口令:");
	    Scanner sc = new Scanner(System.in);
	    String password = sc.next();
	    createPassword(password);
	    
		byte[] iv = new byte[16];
	    SecureRandom random = new SecureRandom();
	    random.nextBytes(iv);
		     
	    System.out.println("Generating a AES key...");  

	    // Create a AES key 
	    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
	    keyGenerator.init(128);	// need to initialize with the keysize
	    Key key = keyGenerator.generateKey();

	    System.out.println("Done generating the key.");

	    // Create a cipher using that key to initialize it
	    //Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
	    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	    //cipher.init(Cipher.ENCRYPT_MODE, key);
	    cipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(iv)); //加密器

/*	    byte[] plaintext = text.getBytes("UTF8");

	    // Print out the bytes of the plaintext
	    System.out.println("\nPlaintext: ");
	    for (int i=0;i<plaintext.length;i++) {
			System.out.print(plaintext[i]+" ");
		}
*/
	    // Perform the actual encryption
	    byte[] cipherdigest = cipher.doFinal(Digest.getBytes());  //加密摘要信息

	    System.out.println("\n加密的消息摘要: ");
	    for (int i=0;i<cipherdigest.length;i++) {
			System.out.print(cipherdigest[i]+" ");
		}
	    
	    System.out.println("\n请输入解密口令:");
	    Scanner sc2 = new Scanner(System.in);
	    String password2 = sc2.next();
	    flag = authenticatePassword(password2);
	    if(flag == false) return;
		/* Print out the ciphertext
	   /* System.out.println("\n\nCiphertext: ");
	    for (int i=0;i<ciphertext.length;i++) {
			System.out.print(ciphertext[i]+" ");
		}*/

	    // Re-initialize the cipher to decrypt mode
	    //cipher.init(Cipher.DECRYPT_MODE, key);
	    cipher.init(Cipher.DECRYPT_MODE, key,new IvParameterSpec(iv));//解密摘要信息
	    // Perform the decryption
	    byte[] decrypteddigest = cipher.doFinal(cipherdigest);
	    System.out.println("\n解密的消息摘要: ");
	    String t = new String(decrypteddigest);
	    System.out.println(t);
/*	    for (int i=0;i<decrypteddigest.length;i++) {
			System.out.print(decrypteddigest[i]+" ");
		}*/
	  //  String output = new String(decrypteddigest,"UTF8");

	  //  System.out.println("\n\nDecrypted text: "+output);

	    byte[] Digestbyte=Digest.getBytes();
	    System.out.println("\ndigestbyte: ");
	 /*   for (int i=0;i<Digestbyte.length;i++) {
			System.out.print(Digestbyte[i]+" ");
		}*/
	    
	    for (int i=0;i<Digestbyte.length;i++) {
			//System.out.print(Digestbyte[i]+" ");
			if(Digestbyte[i]!=decrypteddigest[i]) 
			{
				System.out.println("文件被篡改过");
				return ;
			}
		}
	    System.out.println("\n文件没被篡改过");
	  }

}
