//package netsec;
/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author Siva
 */
import java.util.*;
import java.io.*;
import java.net.*;
import java.util.Random;
import java.security.MessageDigest;
import static java.lang.System.out;
import java.util.Arrays;
import static java.lang.System.out;
import java.math.BigInteger;

class TCPServer {

    public static int RBob = 0;
    public static int RAlice = 0;
//    public static int Session_id = 0;
    public Socket conSocket;
    public static InputStream sockIn;
    public static OutputStream sockOut;
    public static byte[] key1;
    public static byte[] key2;
    HashMap hashMap;

    public TCPServer(Socket socket) {
        this.conSocket = socket;
    }

    public TCPServer() {
    }

    public static void main(String a[]) throws Exception {

        TCPServer server = new TCPServer();

        ServerSocket welcomeSocket = new ServerSocket(6789);
        while (true) {
            System.out.println("Waiting for the client to connect...");
            Socket connectionSocket = welcomeSocket.accept();
            server.talkOnSocket(connectionSocket);
        }

    }

    public void talkOnSocket(Socket socket) {

        this.conSocket = socket;

        try {
            sockIn = conSocket.getInputStream();
            sockOut = conSocket.getOutputStream();
            BufferedReader inFromClient = new BufferedReader(new InputStreamReader(sockIn));

            String command1 = inFromClient.readLine();
            String[] Temp = command1.split(",,,");
            if (Temp.length == 2) {
                System.out.println("***************INITIATING SESSION***************");
                initiateSession(command1);
            } else if (Temp.length == 3) {
                System.out.println("***************RESUMING SESSION***************");
                resumeSession(command1);
            }

            inFromClient.close();
            sockIn.close();
            sockOut.close();
            conSocket.close();
        } catch (Exception e) {
        }
    }

    public void initiateSession(String command1) {
        hashMap = new HashMap();
        String HashText = "";
        String RecText;
        String SendText;
        String Ciphers;
        String SharedSecret;
        byte[] RecHash;
        byte[] TempHash;
        int Session_id;
        String Cipher_Chosen = "";
        int p = 0;
        int public_key = 7;
        ArrayList<String> options = new ArrayList<String>();

        try {
            BufferedReader inFromClient = new BufferedReader(new InputStreamReader(sockIn));
            PrintWriter outToClient = new PrintWriter(sockOut, true);
            InputStreamReader in = new InputStreamReader(System.in);
            BufferedReader br = new BufferedReader(in);

            //receiving command 1
            RecText = command1;
            System.out.println("Ciphers, RAlice: " + RecText);
            String[] Temp = RecText.split(",,,");
            Ciphers = Temp[0];
            RAlice = Integer.parseInt(Temp[1]);
            HashText = HashText + RecText;
            //sending command 2
            RBob = 100 + (int) (Math.random() * ((200 - 100) + 1));
            Session_id = 200 + (int) (Math.random() * ((500 - 200) + 1));

            options.add("CBC");
            options.add("CFB");
            options.add("PCBC");
            options.add("RC4");

//            System.out.println(options);
            System.out.println("Choose one of the below Cipher options");
            System.out.println("CBC CFB PCBC RC4");
            String choice = br.readLine().trim();
            if(choice.equalsIgnoreCase("CBC") || choice.equalsIgnoreCase("CFB") || choice.equalsIgnoreCase("PCBC") || choice.equalsIgnoreCase("RC4")){
                Cipher_Chosen = choice.toUpperCase();
            }else{
                System.out.println("Not a valid choice...Try again...");
                choice = br.readLine().trim();
                if(choice.equalsIgnoreCase("CBC") || choice.equalsIgnoreCase("CFB") || choice.equalsIgnoreCase("PCBC") || choice.equalsIgnoreCase("RC4")){
                    Cipher_Chosen = choice.toUpperCase();
                }else{
                    System.out.println("Sorry....Not a valid choice...Exiting...");
                }
            }
            
//            Cipher_Chosen = Cipher_Chosen.toUpperCase();
//            if (!options.contains(Cipher_Chosen)) {
//                System.out.println("Not a Valid Cipher,Choose a Valid Cipher...");
//                Cipher_Chosen = br.readLine();
//                Cipher_Chosen = Cipher_Chosen.toUpperCase();
//                if (!options.contains(Cipher_Chosen)) {
//                    out.println("Not a Valid Cipher....System exiting");
//                    System.exit(0);
//                }
//            }

            SendText = Session_id + ",,," + public_key + ",,," + Cipher_Chosen + ",,," + RBob;
            outToClient.println(SendText);
            HashText = HashText + SendText;
            System.out.println("seesion id, my certificate, cipher, Rbob: " + SendText);

            //receiving command 3
            RecText = inFromClient.readLine();
            System.out.println("{S}bob, K{keys hash}:" + RecText);
            //RecText = RecText.replaceAll("(\\r|\\n)", "");
            Temp = RecText.split(",,,");
            String deSharedSecret = getDecryptedSharedSecret(Temp[0]);
            SharedSecret = deSharedSecret;

            //storing seesion id and shared secret
            hashMap.put(Session_id, SharedSecret);

            String receivedHashValue = Temp[1];
            //receivedHashValue = receivedHashValue.replaceAll("(\\r|\\n)", "");

            //generating keys
            key1 = MD5hash(RAlice + RBob + SharedSecret + 1);
            key2 = MD5hash(RAlice + RBob + SharedSecret + 2);
            System.out.println("Generated key1 : " + new String(key1));
            System.out.println("Generated key2 : " + new String(key2));

            receivedHashValue = decHashValue(Cipher_Chosen, receivedHashValue);
            //receivedHashValue = receivedHashValue.replaceAll("(\\r|\\n)", "");

            String hashValue = new String(MD5hash(HashText));
            //hashValue = hashValue.replaceAll("(\\r|\\n)", "");

//            System.out.println("Received -- " + receivedHashValue);
//            System.out.println("Caluculated -- " + hashValue);
            boolean Result = Arrays.equals(receivedHashValue.getBytes(), hashValue.getBytes());
//            System.out.println("Are two hash values equal ? : " + Result);
            System.out.println("Hash values are compared");
            
            HashText = HashText + RecText;

            //sending command 4
            SendText = new String(MD5hash(HashText));
            //SendText = SendText.replaceAll("(\\r|\\n)", "");

            SendText = encHashValue(Cipher_Chosen, SendText);
            System.out.println("keyed hash of msgs : " + SendText);
            outToClient.println(SendText);

//            if (Result) {
                System.out.println("Handshake is successful");
//            } else {
//                System.out.println("Handshake is not successful");
//            }

            //file transfering
            fileTransfer(Cipher_Chosen, sockIn, sockOut);

            //closing stream readers/writers
            System.out.println("closing streams and client socket...");
            inFromClient.close();
            outToClient.close();

        } catch (Exception e) {
            System.out.println("Client socket might be closed...");
        }
        // welcomeSocket.setSoTimeout(20000);

    }

    public void resumeSession(String command1) {
        String HashText = "";
        String RecText;
        String SendText;
        String Ciphers;
        String SharedSecret;
        byte[] RecHash;
        byte[] TempHash;
        int Session_id;
        String Cipher_Chosen="";
        int p = 0;
        int public_key = 7;
        ArrayList<String> options = new ArrayList<String>();

        try {
            BufferedReader inFromClient = new BufferedReader(new InputStreamReader(sockIn));
            PrintWriter outToClient = new PrintWriter(sockOut, true);
            InputStreamReader in = new InputStreamReader(System.in);
            BufferedReader br = new BufferedReader(in);

            //receiving command 1
            RecText = command1;
            System.out.println("session id, Ciphers, RAlice: " + RecText);
            String[] Temp = RecText.split(",,,");
            Session_id = Integer.parseInt(Temp[0]);
            Ciphers = Temp[1];
            RAlice = Integer.parseInt(Temp[2]);
            HashText = HashText + RecText;

            options.add("CBC");
            options.add("CFB");
            options.add("PCBC");
            options.add("RC4");

//            System.out.println(options);
            System.out.println("Choose one of the below Cipher options");
            System.out.println("CBC CFB PCBC RC4");
            String choice = br.readLine().trim();
            if(choice.equalsIgnoreCase("CBC") || choice.equalsIgnoreCase("CFB") || choice.equalsIgnoreCase("PCBC") || choice.equalsIgnoreCase("RC4")){
                Cipher_Chosen = choice.toUpperCase();
            }else{
                System.out.println("Not a valid choice...Try again...");
                choice = br.readLine().trim();
                if(choice.equalsIgnoreCase("CBC") || choice.equalsIgnoreCase("CFB") || choice.equalsIgnoreCase("PCBC") || choice.equalsIgnoreCase("RC4")){
                    Cipher_Chosen = choice.toUpperCase();
                }else{
                    System.out.println("Sorry....Not a valid choice...Exiting...");
                    System.exit(0);
                }
            }
            
//            Cipher_Chosen = Cipher_Chosen.toUpperCase();
//            if (!options.contains(Cipher_Chosen)) {
//                System.out.println("Not a Valid Cipher,Choose a Valid Cipher...");
//                Cipher_Chosen = br.readLine();
//                Cipher_Chosen = Cipher_Chosen.toUpperCase();
//                if (!options.contains(Cipher_Chosen)) {
//                    out.println("Not a Valid Cipher....System exiting");
//                    System.exit(0);
//                }
//            }

            //generating keys
            RBob = 100 + (int) (Math.random() * ((200 - 100) + 1));
            SharedSecret = (String) hashMap.get(Session_id);
            key1 = MD5hash(RAlice + RBob + SharedSecret + 1);
            key2 = MD5hash(RAlice + RBob + SharedSecret + 2);
            System.out.println("Generated key1 : " + new String(key1));
            System.out.println("Generated key2 : " + new String(key2));

            //sending command 2
            byte[] calHashValue = MD5hash(HashText);
            String hashValue = new String(calHashValue);
//            hashValue = hashValue.replaceAll("(\\r|\\n)", "");

            //hashValue = encHashValue(Cipher_Chosen, hashValue);
            SendText = Session_id + ",,," + Cipher_Chosen + ",,," + RBob + ",,," + hashValue;
            HashText = HashText + SendText;
            outToClient.println(SendText);
            System.out.println("session id, cipher, Rbob, {keyed hash} : " + SendText);


            //receiving command 3
            RecText = inFromClient.readLine();
            System.out.println("{keyed hash of msgs} : " + RecText);
//            RecText = RecText.replaceAll("(\\r|\\n)", "");
            String receivedHashValue = RecText;
            //receivedHashValue = decHashValue(Cipher_Chosen, receivedHashValue);
            calHashValue = MD5hash(HashText);

            boolean Result = Arrays.equals(receivedHashValue.getBytes(), calHashValue);
//            System.out.println("Hash value comparision : " + Result);
            System.out.println("Hash values are compared");
//            if (Result) {
                System.out.println("Handshake is successful");
//            } else {
//                System.out.println("Handshake is not successful");
//            }

            //file transfering
            fileTransfer(Cipher_Chosen, sockIn, sockOut);

            //closing stream readers/writers
            System.out.println("closing streams and client socket...");
            inFromClient.close();
            outToClient.close();

        } catch (Exception e) {
            System.out.println("Client socket might be closed...");
        }
        // welcomeSocket.setSoTimeout(20000);

    }

    public void fileTransfer(String Cipher_Chosen, InputStream sockIn, OutputStream sockOut) {
        System.out.println("***************FILE TRANSFER***************");
        if (Cipher_Chosen.equalsIgnoreCase("CBC")) {
            readData(new CBC(key1, key2), sockIn, sockOut);
        } else if (Cipher_Chosen.equalsIgnoreCase("CFB")) {
            readData(new CFB(key1, key2), sockIn, sockOut);
        } else if (Cipher_Chosen.equalsIgnoreCase("PCBC")) {
            readData(new PCBC(key1, key2), sockIn, sockOut);
        } else if (Cipher_Chosen.equalsIgnoreCase("RC4")) {
            readData(new RC4(new String(key1)), sockIn, sockOut);
        } else {
            System.out.println("something wrong in file transfer");
        }
        System.out.println("***************END OF FILE TRANSFER***************");
    }

    public void readData(CBC cbc, InputStream sockIn, OutputStream sockOut) {
        DataInputStream din;
        BufferedWriter brout = null;
        try {
            din = new DataInputStream(sockIn);
            brout = new BufferedWriter(new OutputStreamWriter(new FileOutputStream("output.txt", true)));
            brout.write("***********************" + new Date().toString() + "***********************");
            brout.newLine();

            byte[] enText;
            byte[] orgResidue = new byte[8];
            byte[] calResidue = new byte[8];
            boolean integrity = true;
            String deText;
            int n = 0;
            try {
                n = din.readInt();
                while (n > 0) {
                    enText = new byte[n];
                    din.readFully(enText);
                    System.arraycopy(enText, enText.length - 8, orgResidue, 0, 8);
                    deText = cbc.decrypt(enText);
                    System.out.println(new String(enText));
                    System.out.println(deText);

                    enText = cbc.encrypt(deText);
                    System.arraycopy(enText, enText.length - 8, calResidue, 0, 8);
                    boolean comp = Arrays.equals(orgResidue, calResidue);
                    if (comp) {
                        System.out.println("Integrity ? " + comp);
                    } else {
                        System.out.println("Integrity ? " + comp);
                        integrity = false;
                    }

                    brout.write(deText);
                    brout.newLine();
                    n = din.readInt();
                }

            } catch (EOFException eof) {
                brout.write("*********************** End of writing ***********************");
                brout.newLine();
            }

            System.out.println("IS THE FILE TAMPERED? " + (!integrity));
            din.close();
            brout.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void readData(CFB cfb, InputStream sockIn, OutputStream sockOut) {
        DataInputStream din;
        BufferedWriter brout = null;
        try {
            din = new DataInputStream(sockIn);
            brout = new BufferedWriter(new OutputStreamWriter(new FileOutputStream("output.txt", true)));
            brout.write("***********************" + new Date().toString() + "***********************");
            brout.newLine();

            byte[] enText;
            String deText;
            int n = 0;
            try {
                n = din.readInt();
                while (n > 0) {
                    enText = new byte[n];
                    din.readFully(enText);
                    deText = cfb.decrypt(enText);
                    System.out.println(new String(enText));
                    System.out.println(deText);
                    brout.write(deText);
                    brout.newLine();
                    n = din.readInt();
                }
            } catch (EOFException eof) {
                brout.write("*********************** End of writing ***********************");
                brout.newLine();
            }
            din.close();
            brout.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void readData(PCBC pcbc, InputStream sockIn, OutputStream sockOut) {
        DataInputStream din;
        BufferedWriter brout = null;
        try {
            din = new DataInputStream(sockIn);
            brout = new BufferedWriter(new OutputStreamWriter(new FileOutputStream("output.txt", true)));
            brout.write("***********************" + new Date().toString() + "***********************");
            brout.newLine();

            byte[] enText;
            String deText;
            boolean integrity = true;
            int n = 0;
            try {
                n = din.readInt();
                while (n > 0) {
                    enText = new byte[n];
                    din.readFully(enText);
                    deText = pcbc.decrypt(enText);
                    String last = deText.substring(deText.length() - 8, deText.length());
                    if (last.equalsIgnoreCase("00000000")) {
                        System.out.println("Integrity ? True");
                    } else {
                        integrity = false;
                        System.out.println("Integrity ? False");
                    }
                    System.out.println(new String(enText));
                    System.out.println(deText);
                    brout.write(deText);
                    brout.newLine();
                    n = din.readInt();
                }
            } catch (EOFException eof) {
                brout.write("*********************** End of writing ***********************");
                brout.newLine();
            }
            System.out.println("IS THE FILE TAMPERED? " + (!integrity));
            din.close();
            brout.close();

        } catch (Exception e) {

            e.printStackTrace();
        }
    }

    public void readData(RC4 rc, InputStream sockIn, OutputStream sockOut) {
        DataInputStream din;
        BufferedWriter brout = null;
        try {
            din = new DataInputStream(sockIn);
            brout = new BufferedWriter(new OutputStreamWriter(new FileOutputStream("output.txt", true)));
            brout.write("***********************" + new Date().toString() + "***********************");
            brout.newLine();

            byte[] enText;
            byte[] deText;
            int n = 0;
            try {
                n = din.readInt();
                while (n > 0) {
                    enText = new byte[n];
                    din.readFully(enText);
                    deText = rc.decrypt(enText);
                    System.out.println(new String(enText));
                    System.out.println(new String(deText));
                    brout.write(new String(deText, "UTF-8"));
                    brout.newLine();
                    n = din.readInt();
                }
            } catch (EOFException eof) {
                brout.write("*********************** End of writing ***********************");
                brout.newLine();
            }
            din.close();
            brout.close();

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

    public String getDecryptedSharedSecret(String enSharedSecret) {
        BigInteger p1, q1, e1, givenMessage;
        p1 = new BigInteger("13");
        q1 = new BigInteger("19");
        e1 = new BigInteger("5");
        RSA rsa = new RSA(p1, q1, e1);
        int i = 0;
        String decsecret = "";
        byte[] bytes1 = enSharedSecret.getBytes();

        while (i < bytes1.length) {
            givenMessage = BigInteger.valueOf(bytes1[i]);
            BigInteger decryptMessage = rsa.rsaDecrypt(givenMessage);
            decsecret = decsecret + new String(decryptMessage.toByteArray());
            i++;
        }

        return decsecret;
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