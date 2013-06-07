//package netsec;

import static java.lang.System.out;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import java.security.SecureRandom;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class ThreeDES {

	public static byte[] myencrypt(byte[] bytedata1, byte[] bytedata2,
			byte[] bytePlaintext) throws Throwable

	{

		SecretKey myDesKey1 = new SecretKeySpec(bytedata1, "DES");
		SecretKey myDesKey2 = new SecretKeySpec(bytedata2, "DES");
		byte[] encrypted_text;
		Cipher desCipher1;
		Cipher desCipher2;

		// Create the cipher

		desCipher1 = Cipher.getInstance("DES/ECB/NoPadding");
		desCipher2 = Cipher.getInstance("DES/ECB/NoPadding");

		// Initialize the cipher for encryption
		desCipher1.init(Cipher.ENCRYPT_MODE, myDesKey1);

		desCipher2.init(Cipher.DECRYPT_MODE, myDesKey2);

		// Encrypt the text
		encrypted_text = desCipher1.doFinal(bytePlaintext);
		bytePlaintext = desCipher2.doFinal(encrypted_text);
		encrypted_text = desCipher1.doFinal(bytePlaintext);
		return encrypted_text;

	}

	public static byte[] mydecrypt(byte[] bytedata1, byte[] bytedata2,
			byte[] encrypted_text) throws Throwable

	{
		SecretKey myDesKey1 = new SecretKeySpec(bytedata1, "DES");
		SecretKey myDesKey2 = new SecretKeySpec(bytedata2, "DES");
		byte[] decrypted_text;
		Cipher desCipher1;
		Cipher desCipher2;
		// Create the cipher
		desCipher1 = Cipher.getInstance("DES/ECB/NoPadding");
		desCipher2 = Cipher.getInstance("DES/ECB/NoPadding");
		// Initialize the cipher for encryption
		desCipher1.init(Cipher.DECRYPT_MODE, myDesKey1);
		desCipher2.init(Cipher.ENCRYPT_MODE, myDesKey2);
		// Decrypt the text
		decrypted_text = desCipher1.doFinal(encrypted_text);
		encrypted_text = desCipher2.doFinal(decrypted_text);
		decrypted_text = desCipher1.doFinal(encrypted_text);
		// System.out.println(decrypted_text.toString());
		return decrypted_text;

	}

}
