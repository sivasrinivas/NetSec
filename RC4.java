//package netsec;



/**
 *
 * @author Siva
 */
public class RC4 {

    /**
     * @param args
     */
    static short[] S;
    static short[] T;

    public RC4(String keyString) {

        if (keyString.length() < 1 && keyString.length() > 256) {
            throw new IllegalArgumentException("Key lenght should be in between 1 and 256");
        }

        byte[] tempKey = keyString.getBytes();
        short[] key = new short[tempKey.length];
        int keyLength = tempKey.length;

        for (int i = 0; i < keyLength; i++) {
            key[i] = (short) ((short) tempKey[i] & 0xff);
        }
        ksa(key);

    }

    public static void main(String[] args) {
        try{
            byte[] key = "test".getBytes();
            RC4 rc = new RC4(new String(key));
            String plainText = "as213423t5df";
            System.out.println("Plaintext is " + plainText);
            byte[] enText = rc.encrypt(plainText.getBytes());
            String encrypted = new String(enText, "UTF-8");
            System.out.println("Encrypter is " + encrypted);
            byte[] deText = rc.decrypt(enText);
            System.out.println("Decrypted is " + new String(deText));
        }
        catch(Exception e){
            e.printStackTrace();
        }
        
    }

    public void ksa(short[] key) {
        short temp;
        S = new short[256];
        T = new short[256];

        for (int i = 0; i < 256; i++) {
            S[i] = (short) i;
        }

        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + S[i] + key[i % key.length]) % 256;

            temp = S[i];
            S[i] = S[j];
            S[j] = temp;
        }
        System.arraycopy(S, 0, T, 0, S.length);
    }

    public byte[] genPad(int length) {
        System.arraycopy(S, 0, T, 0, S.length);
        int i = 0, j = 0;
        short temp;
        byte[] tempPpad = new byte[length];
        for (int k = 0; k < length; k++) {
            i = (i + 1) % 256;
            j = (j + T[i]) % 256;

            temp = T[i];
            T[i] = T[j];
            T[j] = temp;

            tempPpad[k] = (byte) (T[(T[i] + T[j]) % 256]);
        }
        return tempPpad;
    }

    public byte[] encrypt(byte[] plain) {
        byte[] pad = genPad(plain.length);
        byte[] encrypt = new byte[plain.length];
        for (int i = 0; i < plain.length; i++) {
            encrypt[i] = (byte) (plain[i] ^ pad[i]);
        }
        return encrypt;
    }

    public byte[] decrypt(byte[] cipher) {
        byte[] plain = encrypt(cipher);
        return plain;
    }
}