//package netsec;
/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author Nishesh
 */
import java.io.*;
import java.net.*;
import java.util.Random;
import java.security.MessageDigest;
import static java.lang.System.out;
import java.math.BigInteger;
import java.util.Arrays;

class TCPClient {

    public static int RAlice = 0;
    public static int RBob = 0;
    public static int Session_id = 0;
    public Socket socket;
    public static InputStream sockIn;
    public static OutputStream sockOut;
    public static byte[] key1;
    public static byte[] key2;

    public TCPClient(Socket socket) {
        this.socket = socket;
    }

    public static void main(String a[]) throws Exception {

        boolean bool = false;

        try {
            InputStreamReader in = new InputStreamReader(System.in);
            BufferedReader br = new BufferedReader(in);

            do {
                Socket clientSocket = new Socket("localhost", 6789);
                TCPClient client = new TCPClient(clientSocket);
                client.talkOnSocket();

                System.out.println("Do you want tranfer another file : Y/N");
                String choise = br.readLine().trim();
                if (choise.equalsIgnoreCase("y")) {
                    bool = true;
                } else if (choise.equalsIgnoreCase("n")) {
                    bool = false;
                } else {
                    bool = false;
                    System.out.println("Invalid entry. Clsoing.");
                }
            } while (bool);
            in.close();
            br.close();

        } catch (Exception e) {
            System.out.println("Server might not be up and running....");
            System.exit(0);
        }




    }

    public void talkOnSocket() {

        if (Session_id == 0) {
            System.out.println("***************INITIATING SESSION***************");
            initiateSeesion();
        } else {
            System.out.println("***************RESUMING SESSION***************");
            resumeSession();
        }

    }

    public void initiateSeesion() {
        int public_key;

        String RecText;
        String SendText;
        String HashText = "";
        String SharedSecret = "secret";
        String Ciphers = "CFB CBC PCBC RC4";
        String Cipher_Chosen;
        String receivedHashValue;

        try {
            sockIn = socket.getInputStream();
            sockOut = socket.getOutputStream();
            BufferedReader inFromServer = new BufferedReader(new InputStreamReader(sockIn));
            PrintWriter outToServer = new PrintWriter(sockOut, true);
            InputStreamReader in = new InputStreamReader(System.in);
            BufferedReader br = new BufferedReader(in);

            //genrating alice random number
            Random R = new Random();
            RAlice = R.nextInt(100);

            //sending command 1
            SendText = Ciphers + ",,," + RAlice;
            outToServer.println(SendText);
            HashText = HashText + SendText;
            System.out.println("Ciphers, RAlice :" + SendText);

            //receiving command 2
            RecText = inFromServer.readLine();
            System.out.println("session id, my certificate, cipher, RBob: " + RecText);
            HashText = HashText + RecText;
            String Temp[] = RecText.split(",,,");
            Session_id = Integer.parseInt(Temp[0]);
            public_key = Integer.parseInt(Temp[1]);
            Cipher_Chosen = Temp[2];
            RBob = Integer.parseInt(Temp[3]);

            //sending command3 
            //generating keys
            key1 = MD5hash(RAlice + RBob + SharedSecret + 1);
            key2 = MD5hash(RAlice + RBob + SharedSecret + 2);
            System.out.println("Generated key1 : " + new String(key1));
            System.out.println("Generated key2 : " + new String(key2));

            //calculating hash value
            String hashValue = new String(MD5hash(HashText));
            System.out.println(hashValue);
            //hashValue = hashValue.replaceAll("(\\r|\\n)", "");
            hashValue = encHashValue(Cipher_Chosen, hashValue);

            String encSharedSecret = getEncryptedSharedSecret(SharedSecret);
            SendText = encSharedSecret + ",,," + hashValue;
            outToServer.println(SendText);
            HashText = HashText + SendText;
            System.out.println("{S}bob, K{hash value} : " + SendText);

            //receiving command 4
            RecText = inFromServer.readLine();
            //RecText = RecText.replaceAll("(\\r|\\n)", "");
            System.out.println("keyed hash of msgs: " + RecText);
            receivedHashValue = RecText;

            receivedHashValue = decHashValue(Cipher_Chosen, receivedHashValue);
            //receivedHashValue = receivedHashValue.replaceAll("(\\r|\\n)", "");

            hashValue = new String(MD5hash(HashText));
            //hashValue = hashValue.replaceAll("(\\r|\\n)", "");

//            System.out.println("Received -- " + receivedHashValue);
//            System.out.println("Caluculated -- " + hashValue);
            boolean blnResult = Arrays.equals(hashValue.getBytes(), receivedHashValue.getBytes());
//            System.out.println("Are two hash values equal ? : " + blnResult);
            System.out.println("Hash values are comapred");

//            if (blnResult) {
            System.out.println("Handshake is successful");
//            } else {
//                System.out.println("Handshake is not successful");
//            }

            //file transfering
            fileTransfer(Cipher_Chosen, sockIn, sockOut);

            //closing stream readers/writers
            System.out.println("closing streams and client socket...");
            inFromServer.close();
            outToServer.close();
            socket.close();
        } catch (Exception e) {
            System.out.println("Server might not be up and running....");
        }

    }

    public void resumeSession() {
        int public_key;

        String RecText;
        String SendText;
        String HashText = "";
        String SharedSecret = "secret";
        String Ciphers = "CFB CBC PCBC RC4";
        String Cipher_Chosen;
        String receivedHashValue;

        try {
            sockIn = socket.getInputStream();
            sockOut = socket.getOutputStream();
            BufferedReader inFromServer = new BufferedReader(new InputStreamReader(sockIn));
            PrintWriter outToServer = new PrintWriter(sockOut, true);
            InputStreamReader in = new InputStreamReader(System.in);
            BufferedReader br = new BufferedReader(in);

            //genrating alice random number
            Random R = new Random();
            RAlice = R.nextInt(100);

            //sending command 1
            SendText = Session_id + ",,," + Ciphers + ",,," + RAlice;
            outToServer.println(SendText);
            HashText = HashText + SendText;
            System.out.println("Session-id, Ciphers, RAlice :" + SendText);

            //receiving command 2
            RecText = inFromServer.readLine();
            System.out.println("session id, cipher, RBob, keyed hash : " + RecText);
            byte[] calHashValue = MD5hash(HashText);
            HashText = HashText + RecText;
            String Temp[] = RecText.split(",,,");
            Session_id = Integer.parseInt(Temp[0]);
            Cipher_Chosen = Temp[1];
            RBob = Integer.parseInt(Temp[2]);
            receivedHashValue = Temp[3];
//            receivedHashValue = receivedHashValue.replaceAll("(\\r|\\n)", "");

            //genreating keys
            key1 = MD5hash(RAlice + RBob + SharedSecret + 1);
            key2 = MD5hash(RAlice + RBob + SharedSecret + 2);
            System.out.println("Generated key1 : " + new String(key1));
            System.out.println("Generated key2 : " + new String(key2));

            receivedHashValue = decHashValue(Cipher_Chosen, receivedHashValue);
            boolean Result = Arrays.equals(receivedHashValue.getBytes(), calHashValue);
            //System.out.println("Hash value comaprison : " + Result);
            System.out.println("Hash values are comapred");

            //sending command3 
            //calculating hash value
            String hashValue = new String(MD5hash(HashText));
//            hashValue = hashValue.replaceAll("(\\r|\\n)", "");
            hashValue = encHashValue(Cipher_Chosen, hashValue);
            outToServer.println(hashValue);
            System.out.println("{Keyed hash of msgs} : " + hashValue);

//            if (Result) {
            System.out.println("Handshake is successful");
//            } else {
//                System.out.println("Handshake is not successful");
//            }


            //file transfering
            fileTransfer(Cipher_Chosen, sockIn, sockOut);

            //closing stream readers/writers
            System.out.println("closing streams and client socket...");
            inFromServer.close();
            outToServer.close();
            socket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public void fileTransfer(String Cipher_Chosen, InputStream sockIn, OutputStream sockOut) {
        System.out.println("***************FILE TRANSFER***************");
        BufferedReader brin;
        String fileName;
        String line;
        boolean eve = false;
        int action = 0;
        try {
            brin = new BufferedReader(new InputStreamReader(System.in));

            System.out.println("Enter the file name you want to transfer: ");
            fileName = brin.readLine().trim();

            System.out.println("Do you want to simulate EVESDROPPER ? y/n");
            line = brin.readLine();
            if (line.equalsIgnoreCase("y")) {
                eve = true;
                System.out.println("Choose an evesdropper action? \nModify - 1 \nRemove - 2 \nAdd - 3");
                line = brin.readLine();
                action = Integer.parseInt(line);
                if (!(action != 1 || action != 2 || action != 3)) {
                    System.out.println("Wrong input. Continuing with Remove action");
                    action = 2;
                }
            } else if (line.equalsIgnoreCase("n")) {
            } else {
                System.out.println("Wrong input. Continuing without evesdropper");
            }

            if (Cipher_Chosen.equalsIgnoreCase("CBC")) {
                sendData(fileName, new CBC(key1, key2), sockIn, sockOut, eve, action);
            } else if (Cipher_Chosen.equalsIgnoreCase("CFB")) {
                sendData(fileName, new CFB(key1, key2), sockIn, sockOut, eve, action);
            } else if (Cipher_Chosen.equalsIgnoreCase("PCBC")) {
                sendData(fileName, new PCBC(key1, key2), sockIn, sockOut, eve, action);
            } else if (Cipher_Chosen.equalsIgnoreCase("RC4")) {
                sendData(fileName, new RC4(new String(key1)), sockIn, sockOut, eve, action);
            } else {
                System.out.println("something wrong in file transfer");
            }
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }

        System.out.println("***************END OF FILE TRANSFER***************");
    }

    public void sendData(String fileName, CBC cbc, InputStream sockIn, OutputStream sockOut, boolean eve, int action) {

        DataOutputStream dout;
        BufferedReader brin;
        try {
            dout = new DataOutputStream(sockOut);
            brin = new BufferedReader(new InputStreamReader(new FileInputStream(fileName)));

            String line;
            byte[] enText;
            while ((line = brin.readLine()) != null) {
                if (line.equalsIgnoreCase("")) {
                    continue;
                }
                enText = cbc.encrypt(line);

                //Evesdropper action
                switch (action) {
                    case 0:
                        break;
                    case 1:
                        int len1 = enText.length;
                        if (len1 >= 8) {
                            for (int i = 0; i < 8; i++) {
                                enText[i] = (byte) (i + 3 % 256);
                            }
                        }
                        break;
                    case 2:
                        int len2 = enText.length;
                        if (len2 > 8) {
                            byte[] remove = new byte[len2 - 8];
                            System.arraycopy(enText, 8, enText, 0, len2 - 8);
                            enText = remove;
                        }
                        break;
                    case 3:
                        int len3 = enText.length;
                        byte[] add = new byte[len3 + 8];
                        byte[] dump = new byte[8];
                        for (int i = 0; i < 8; i++) {
                            dump[i] = (byte) (i + 3 % 256);
                        }
                        System.arraycopy(dump, 0, add, 0, 8);
                        System.arraycopy(enText, 0, add, 8, len3);
                        enText = add;

                        break;
                    default:
                        break;
                }

                dout.writeInt(enText.length);
                dout.write(enText);
                System.out.println(line);
                System.out.println(new String(enText));
            }

            dout.close();
            brin.close();

        } catch (FileNotFoundException fnfe) {
            System.out.println("*******File not found*****");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void sendData(String fileName, CFB cfb, InputStream sockIn, OutputStream sockOut, boolean eve, int action) {

        DataOutputStream dout;
        BufferedReader brin;
        try {
            dout = new DataOutputStream(sockOut);
            brin = new BufferedReader(new InputStreamReader(new FileInputStream(fileName)));

            String line;
            byte[] enText;
            while ((line = brin.readLine()) != null) {
                if (line.equalsIgnoreCase("")) {
                    continue;
                }
                enText = cfb.encrypt(line);

                //Evesdropper action
                switch (action) {
                    case 0:
                        break;
                    case 1:
                        int len1 = enText.length;
                        if (len1 >= 8) {
                            for (int i = 0; i < 8; i++) {
                                enText[i] = (byte) (i + 3 % 256);
                            }
                        }
                        break;
                    case 2:
                        int len2 = enText.length;
                        if (len2 > 8) {
                            byte[] remove = new byte[len2 - 8];
                            System.arraycopy(enText, 8, enText, 0, len2 - 8);
                            enText = remove;
                        }
                        break;
                    case 3:
                        int len3 = enText.length;
                        byte[] add = new byte[len3 + 8];
                        byte[] dump = new byte[8];
                        for (int i = 0; i < 8; i++) {
                            dump[i] = (byte) (i + 3 % 256);
                        }
                        System.arraycopy(dump, 0, add, 0, 8);
                        System.arraycopy(enText, 0, add, 8, len3);

                        break;
                    default:
                        break;
                }

                dout.writeInt(enText.length);
                dout.write(enText);
                System.out.println(line);
                System.out.println(new String(enText));
            }

            dout.close();
            brin.close();

        } catch (FileNotFoundException fnfe) {
            System.out.println("*******File not found*****");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void sendData(String fileName, PCBC pcbc, InputStream sockIn, OutputStream sockOut, boolean eve, int action) {

        DataOutputStream dout;
        BufferedReader brin;
        try {
            dout = new DataOutputStream(sockOut);
            brin = new BufferedReader(new InputStreamReader(new FileInputStream(fileName)));

            String line;
            byte[] enText;
            while ((line = brin.readLine()) != null) {
                if(line.equalsIgnoreCase("")) {
                    continue;
                }
                enText = pcbc.encrypt(line);

                //Evesdropper action
                switch (action) {
                    case 0:
                        break;
                    case 1:
                        int len1 = enText.length;
                        if (len1 >= 8) {
                            for (int i = 0; i < 8; i++) {
                                enText[i] = (byte) (i + 3 % 256);
                            }
                        }
                        break;
                    case 2:
                        int len2 = enText.length;
                        if (len2 > 8) {
                            byte[] remove = new byte[len2 - 8];
                            System.arraycopy(enText, 8, enText, 0, len2 - 8);
                            enText = remove;
                        }
                        break;
                    case 3:
                        int len3 = enText.length;
                        byte[] add = new byte[len3 + 8];
                        byte[] dump = new byte[8];
                        for (int i = 0; i < 8; i++) {
                            dump[i] = (byte) (i + 3 % 256);
                        }
                        System.arraycopy(dump, 0, add, 0, 8);
                        System.arraycopy(enText, 0, add, 8, len3);
                        enText = add;

                        break;
                    default:
                        break;
                }

                dout.writeInt(enText.length);
                dout.write(enText);
                System.out.println(line);
                System.out.println(new String(enText));
            }

            dout.close();
            brin.close();

        } catch (FileNotFoundException fnfe) {
            System.out.println("*******File not found*****");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void sendData(String fileName, RC4 rc, InputStream sockIn, OutputStream sockOut, boolean eve, int action) {

        DataOutputStream dout;
        BufferedReader brin;
        try {
            dout = new DataOutputStream(sockOut);
            brin = new BufferedReader(new InputStreamReader(new FileInputStream(fileName)));

            String line;
            byte[] enText;
            while ((line = brin.readLine()) != null) {
                if(line.equalsIgnoreCase("")) {
                    continue;
                }
                enText = rc.encrypt(line.getBytes());
                //Evesdropper action
                switch (action) {
                    case 0:
                        break;
                    case 1:
                        int len1 = enText.length;
                        if (len1 >= 8) {
                            for (int i = 0; i < 8; i++) {
                                enText[i] = (byte) (i + 3 % 256);
                            }
                        }
                        break;
                    case 2:
                        int len2 = enText.length;
                        if (len2 > 8) {
                            byte[] remove = new byte[len2 - 8];
                            System.arraycopy(enText, 8, enText, 0, len2 - 8);
                            enText = remove;
                        }
                        break;
                    case 3:
                        int len3 = enText.length;
                        byte[] add = new byte[len3 + 8];
                        byte[] dump = new byte[8];
                        for (int i = 0; i < 8; i++) {
                            dump[i] = (byte) (i + 3 % 256);
                        }
                        System.arraycopy(dump, 0, add, 0, 8);
                        System.arraycopy(enText, 0, add, 8, len3);

                        break;
                    default:
                        break;
                }

                dout.writeInt(enText.length);
                dout.write(enText);
                System.out.println(line);
                System.out.println(new String(enText));
            }

            dout.close();
            brin.close();

        } catch (FileNotFoundException fnfe) {
            System.out.println("*******File not found*****");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public byte[] MD5hash(String Message) {
//        System.out.println("hashing --------->" + Message);
        byte byteData[] = new byte[1024];
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(Message.getBytes());
            byteData = md.digest();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(0);
        }
        return byteData;

    }

    public String getEncryptedSharedSecret(String sharedSecret) {
        byte[] bytes = sharedSecret.getBytes();
        int i = 0;
        String encSecret = "";
        BigInteger givenMessage, p1, q1, e1;
        p1 = new BigInteger("13");
        q1 = new BigInteger("19");
        e1 = new BigInteger("5");
        RSA rsa = new RSA(p1, q1, e1);

        while (i < bytes.length) {
            givenMessage = BigInteger.valueOf(bytes[i]);
            BigInteger encryptMessage = rsa.rsaEncrypt(givenMessage, new BigInteger("5"), new BigInteger("247"));
            encSecret = encSecret + new String(encryptMessage.toByteArray());
            i++;
        }

        return encSecret;
    }

    public String getKeyedHash(byte[] bytes) {

        return null;
    }

    public String encHashValue(String Cipher_Chosen, String hashValue) {
//        System.out.println("Encrypting hash message --" + hashValue);
        String encHashValue = null;
        if (Cipher_Chosen.equalsIgnoreCase("rc4")) {
            RC4 rc4 = new RC4(new String(key1));
            byte[] plain = hashValue.getBytes();
            byte[] eText = rc4.encrypt(plain);
            encHashValue = new String(eText);
        } else if (Cipher_Chosen.equalsIgnoreCase("cbc")) {
            CBC cbc = new CBC(key1, key2);
            byte[] eText = cbc.encrypt(hashValue);
            encHashValue = new String(eText);
        } else if (Cipher_Chosen.equalsIgnoreCase("pcbc")) {
            PCBC pcbc = new PCBC(key1, key2);
            byte[] eText = pcbc.encrypt(hashValue);
            encHashValue = new String(eText);
        } else if (Cipher_Chosen.equalsIgnoreCase("cfb")) {
            //Cipher chosen is CFB
            CFB cfb = new CFB(key1, key2);
            byte[] eText = cfb.encrypt(hashValue);
            encHashValue = new String(eText);
        }
        return encHashValue;
    }

    public String decHashValue(String Cipher_Chosen, String hashValue) {
//        System.out.println("Decrypting hash message --" + hashValue);
        String decHashValue = null;

        if (Cipher_Chosen.equalsIgnoreCase("rc4")) {
            RC4 rc4 = new RC4(new String(key1));
            byte[] cipher = hashValue.getBytes();
            byte[] deText = rc4.decrypt(cipher);
            decHashValue = new String(deText);
        } else if (Cipher_Chosen.equalsIgnoreCase("cbc")) {
            CBC cbc = new CBC(key1, key2);
            byte[] enText = hashValue.getBytes();
            decHashValue = cbc.decrypt(enText);
        } else if (Cipher_Chosen.equalsIgnoreCase("pcbc")) {
            PCBC pcbc = new PCBC(key1, key2);
            byte[] enText = hashValue.getBytes();
            decHashValue = pcbc.decrypt(enText);
        } else if (Cipher_Chosen.equalsIgnoreCase("cfb")) {
            //Cipher chosen is CFB
            CFB cfb = new CFB(key1, key2);
            byte[] enText = hashValue.getBytes();
            decHashValue = cfb.decrypt(enText);
        }

        return decHashValue;
    }
}
