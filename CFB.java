//package netsec;


import java.io.BufferedReader;
import java.io.InputStreamReader;
import static java.lang.System.out;
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
import java.util.Arrays;

public class CFB {

    public static byte[] IV = new byte[8];
    public static int pad = 0;
    public static int blocks = 0;
    public static byte[] b1 = new byte[8];
    public static byte[] b2 = new byte[8];

    public CFB(byte[] b1, byte[] b2) {
        this.b1 = Arrays.copyOf(b1, 8);
        this.b2 = Arrays.copyOf(b2, 8);
    }

    // Generatng the Initialization Vector
    public static void IVGen() {
        IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        IV = iv.getIV();
    }

    // XOR function accepts two byte array inputs and returns a xored byte array
    public static byte[] XOR(byte[] b1, byte[] b2) {
        byte[] b3 = new byte[8];
        for (int i = 0; i < 8; i++) {
            b3[i] = (byte) (b1[i] ^ b2[i]);
        }
        return b3;
    }

    // Main method
    public byte[] encrypt(String Plaintext) {
        ThreeDES DES3 = new ThreeDES();
        String text = new String();
        text = Plaintext;

        // Padding the Original input message if not multiple of 8

        int len = text.length();
        if (len % 8 != 0) {
            pad = 8 - len % 8;
            for (int i = 1; i <= pad; i++) {
                text = text + "#";
            }
        }
//        out.println("Pad= " + pad);
        blocks = (text.length()) / 8;
        // System.out.println("No of blocks---->"+blocks);

        byte[][] CipherText = new byte[blocks][8];
        //byte[][] Intermediate_enc = new byte[blocks][8];

        // Generate the Keys using the TripleDES_cfb class methods

        // Generate the IV
        IVGen();

        /* ENCRYPTION Using CFB */
        byte[] e_text = new byte[8];
        byte[] FinalCFB = new byte[8];

        for (int i = 0, j = 0; i < blocks; i++, j = j + 8) {


            if (i == 0) {
                try {
                    // call the TripleDES myencrypt method --first block - IV is
                    // used
                    e_text = DES3.myencrypt(b1, b2, IV);
                    //Intermediate_enc[i] = e_text;

                    // call the XOR function using 2 byte arrays as input
                    e_text = XOR(e_text, text.substring(j, j + 8).getBytes("ISO-8859-1"));
                    CipherText[i] = e_text;
                } catch (Throwable e) {
                    e.printStackTrace();
                    System.exit(0);
                }

            } else {
                try {

                    // call the TripleDES myencrypt method --subsequent blocks -
                    // Previous Cipher text block used
                    e_text = DES3.myencrypt(b1, b2, CipherText[i - 1]);
                    //Intermediate_enc[i] = e_text;
                    // call the XOR function using 2 byte arrays as input
                    e_text = XOR(e_text, text.substring(j, j + 8).getBytes("ISO-8859-1"));
                    CipherText[i] = e_text;

                    if (i == (blocks - 1)) {
                        FinalCFB = e_text;
                    }
                } catch (Throwable e) {
                    e.printStackTrace();
                    System.exit(0);
                }

            }
        }


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
//        out.println("enc length in encrypt= " + enc.length());
        //return enc;
        return Final_enc;
    }

    public String decrypt(byte[] Message) {
        //out.println("Message Length= "+Message.length());
        blocks = Message.length / 8;
        byte[][] CipherText = new byte[blocks][8];
        for (int i = 0, j = 0; i < blocks; i++, j = j + 8) {
            System.arraycopy(Message, j, CipherText[i], 0, 8);
        }
        ThreeDES DES3 = new ThreeDES();
        String[] d_message = new String[blocks];
        byte[] d_text = new byte[8];
        byte[] r_text = new byte[8];

        // System.out.println("No. of. Blocks---->"+blocks);
        for (int n = (blocks - 1); n >= 0; n--) {

            if (n == 0) {
                try {
                    // call the TripleDES myencrypt method --first block - IV is
                    // used
                    r_text = DES3.myencrypt(b1, b2, IV);
                    // call the XOR function using 2 byte arrays as input
                    d_text = XOR(r_text, CipherText[n]);
                    d_message[n] = new String(d_text, "ISO-8859-1");
                } catch (Throwable e) {
                    e.printStackTrace();
                    System.exit(0);
                }
            } else {
                try {
                    // call the TripleDES myencrypt method --subsequent blocks -
                    // Previous Cipher text block used
                    r_text = DES3.myencrypt(b1, b2, CipherText[n - 1]);
                    // call the XOR function using 2 byte arrays as input
                    d_text = XOR(r_text, CipherText[n]);

                    // System.out.println("Decrypted Text---->"+new
                    // String(d_text));
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
//            out.println("d_message= " + d_message[i]);
        }
        pad = (output.length() - output.indexOf("#"));
        // System.out.println("\nFull Decrypted message :"+output.substring(0,(output.length()-pad)));
//        out.println("Pad= " + pad);
        //		return output.substring(0, (output.length() - pad));
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