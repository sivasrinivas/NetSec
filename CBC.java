//package netsec;

import static java.lang.System.out;
import java.util.Arrays;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import java.security.SecureRandom;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class CBC {

    public static byte[] b1 = new byte[8];
    public static byte[] b2 = new byte[8];

    public CBC(byte[] b1, byte b2[]) {
        this.b1 = Arrays.copyOf(b1, 8);
        this.b2 = Arrays.copyOf(b2, 8);
        
    }
    public static int blocks = 0;
    public static int pad = 0;
    public static byte[] IV = new byte[8];

    public static void IVGen() {
        IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        IV = iv.getIV();
    }

    public static byte[] XOR(byte[] b1, byte[] b2) {
        byte[] b3 = new byte[8];
        for (int i = 0; i < 8; i++) {
            b3[i] = (byte) (b1[i] ^ b2[i]);
        }
        //b3=Arrays.copyOf(b3,8);
//        out.println("b3= " + b3.length);
        return b3;
    }

    public byte[] encrypt(String Plaintext) {
        Plaintext = Plaintext.toLowerCase();
        ThreeDES DES3 = new ThreeDES();
        byte[] Residue_block = new byte[8];
        IVGen();
        byte[] e_text = new byte[8];

        /*	String text = new String();
         text = Plaintext; */



        int len = Plaintext.length();
        if (len % 8 != 0) {
            pad = 8 - len % 8;
            for (int i = 1; i <= pad; i++) {
                Plaintext = Plaintext + "#";
            }
        }
//        out.println("pad length= " + pad);
//        out.println("Message after padding " + Plaintext);
        blocks = (Plaintext.length()) / 8;

        byte[][] CipherText = new byte[blocks][8];

        for (int i = 0, j = 0; i < blocks; i++, j = j + 8) {

            if (i == 0) {
                try {
                    e_text = XOR(IV, Plaintext.substring(j, j + 8).getBytes("ISO-8859-1"));
                    e_text = DES3.myencrypt(b1, b2, e_text);
                    CipherText[i] = e_text;
                    if ((i + 1) == blocks) {
                        Residue_block = e_text;
                    }

                } catch (Throwable e) {
                    e.printStackTrace();
                    System.exit(0);
                }

            } else {
                try {
                    e_text = XOR(CipherText[i - 1], Plaintext.substring(j, j + 8).getBytes("ISO-8859-1"));
                    e_text = DES3.myencrypt(b1, b2, e_text);
                    CipherText[i] = e_text;
                    if (i == (blocks - 1)) {
                        Residue_block = e_text;
                    }
                } catch (Throwable e) {
                    e.printStackTrace();
                    System.exit(0);
                }

            }
        }
//        out.println("Blocks= " + blocks);
        //String []s=new String[blocks];
        byte[] Final_enc = new byte[blocks * 8];
//        out.println("Final_enc length= " + Final_enc.length);
        String enc = new String();
        enc = "";
        try {
            for (int i = 0, j = 0; i < blocks; i++, j = j + 8) {
                //CipherText[i]=Arrays.copyOf(CipherText[i],8);
			/*enc=enc + new String(CipherText[i],"ISO-8859-1");
                 out.println("enc length in for "+enc.length());
                 out.println("Byte length "+CipherText[i].length);*/

                System.arraycopy(CipherText[i], 0, Final_enc, j, 8);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        // out.println("Residue block------>"+new String(Residue_block));
        //out.println("enc length in encrypt= " + enc.length());
        //return enc;
        return Final_enc;
//        return CipherText[blocks];
        //return CipherText;	
    }
    //CipherText

    public String decrypt(byte[] Message) {
        blocks = Message.length / 8;
//        out.println("Message length= " + Message.length);
//        out.println("Blocks= " + blocks);
        byte[][] CipherText = new byte[blocks][8];
//        out.println("B1= " + b1.length);
//        out.println("B2= " + b2.length);
//        out.println("Message Decrypt length= " + Message.length);
        for (int i = 0, j = 0; i < blocks; i++, j = j + 8) {
            System.arraycopy(Message, j, CipherText[i], 0, 8);
        }
        String[] d_message = new String[blocks];
        byte[] d_text = new byte[8];
        ThreeDES DES3 = new ThreeDES();

        for (int n = (blocks - 1); n >= 0; n--) {
            
            if (n == 0) {
                try {
                    d_text = DES3.mydecrypt(b1, b2, CipherText[n]);
                    d_text = XOR(IV, d_text);
                    // out.println("DEcrypted Text---->"+new String(d_text));
                    d_message[n] = new String(d_text, "ISO-8859-1");
                } catch (Throwable e) {
                    e.printStackTrace();
                    System.exit(0);
                }
            } else {
                try {
                    d_text = DES3.mydecrypt(b1, b2, CipherText[n]);
                    d_text = XOR(CipherText[n - 1], d_text);
                    // out.println("Decrypted Text---->"+new String(d_text));
                    d_message[n] = new String(d_text, "ISO-8859-1");
                } catch (Throwable e) {
                    e.printStackTrace();
                    System.exit(0);
                }

            }
        }
        String output = "";
        for (int i = 0; i < blocks; i++) {
            output = output + d_message[i];
        }
//        out.println("Output with pad= " + output);
        pad = (output.length() - output.indexOf("#"));


        // out.println("Decrypted message---->"+output.substring(0,(output.length()-pad)));
//        return output.substring(0, (output.length() - pad));
        int first = output.indexOf("#");
        //int last = output.lastIndexOf("#");
        if (first != -1) {
            String temp = output.substring(0, first);
            //String temp1 = output.substring(last + 1, output.length());
            output = temp;
        }
        
        return output;
    }
}