import java.io.*;
import java.lang.*;
import java.nio.ByteBuffer;
import java.util.*;
import java.math.*;
import java.util.concurrent.ThreadLocalRandom;
import java.net.*;

public class Bob {
    final static int prime = 1021;
    final static int g = 10;
    static int portNumber = 3334;
    static int portNumber_AB = 3335;
    static int Kb = 0;
    static String Kb_string;
    static String KbPacket_Decrypted;
    public static void main(String[] args) throws IOException {

        Socket BobCDH = new Socket("127.0.0.1", portNumber);
        BobCDH.setSoTimeout(2000);
        PrintWriter b_out = new PrintWriter(BobCDH.getOutputStream(),true);
        BufferedReader b_in = new BufferedReader(new InputStreamReader(BobCDH.getInputStream()));

        System.out.println("Bob established connection with KDC");
        //start CDH with KDC
        int c = ThreadLocalRandom.current().nextInt(1, 1022);
        //int g_c_unmod = (int)Math.pow(g, c);
        int g_c = 1;
        for(int i=0; i<c; i++) {
            g_c = (g_c*g)%prime;
        }
        //Bob sends g^c mod p to the KDC
        System.out.println("Bob sends g_c to KDC");
        System.out.println("Sending g_c=" + g_c + " to KDC");
        b_out.println(g_c);
        //b_out.flush();

        //Bob receives g^d mod p from the KDC
        String g_d_string = b_in.readLine();
        int g_d = Integer.parseInt(g_d_string);
        System.out.println("Received g_d=" + g_d);

        //Bob calculates (g^d)^c mod p, sends to KDC
        //int g_d_c_unmod = (int)Math.pow(g_d, c);
        int g_d_c = 1;
        for(int i=0; i<c; i++) {
            g_d_c = (g_d_c*g_d)%prime;
        }
        System.out.println("g_d_c: " + g_d_c);
        b_out.println(g_d_c);
        //b_out.flush();

        String g_c_d_string = b_in.readLine();
        int g_c_d = Integer.parseInt(g_c_d_string);
        System.out.println("Received g_c_d=" + g_c_d);

        if(g_c_d != g_d_c) {
            System.out.println("CDH Failed");
        }

        if(g_c_d == g_d_c) {
            System.out.println("Diffie-Hellman Completed Successfully! -Bob");
            Kb = g_c_d;
            Kb_string = Integer.toBinaryString(Kb);
            if(Kb_string.length() < 10) {
                int difference = 10 - Kb_string.length();
                for (int i = 0; i < difference; i++) {
                    String pad = "0";
                    Kb_string = pad.concat(Kb_string);
                }
            }
        }

        BobCDH.close();

        //now that Bob has key Kb with the KDH, Bob becomes a server to connect to Alice to begin Needham-Schroeder
        ServerSocket Bob = new ServerSocket(portNumber_AB);
        Socket toAlice = Bob.accept();
        toAlice.setSoTimeout(2000);

        System.out.println("Bob accepted connection from Alice");

        PrintWriter a_out = new PrintWriter(toAlice.getOutputStream(), true);
        BufferedReader a_in = new BufferedReader(new InputStreamReader(toAlice.getInputStream()));

        String KbPacket = a_in.readLine();
        System.out.println("Received KbPacket from Alice: " + KbPacket);

        //Bob will now decrypt this packet using private key Kb shared with the KDC

        KeyGen KGKb = new KeyGen();
        Encryption eKb = new Encryption();

        KGKb.generate(Kb_string);

        List<String> KbPacket_blocks = split(KbPacket, 8);
        List<String> KbPacket_dBlocks = new ArrayList<String>();
        for(String block : KbPacket_blocks) {
            //use subkeys in reverse order
            int[] KaPout_int = eKb.encrypt(block, KGKb.getK2(), KGKb.getK1());
            String KbPout_string1 = Arrays.toString(KaPout_int).replaceAll(",\\s+", "");
            String KbPout_string2 = KbPout_string1.replaceAll("\\[", "");
            String KbPout_string = KbPout_string2.replaceAll("]", "");
            //KbPacket_Decrypted = KbPacket_Decrypted.concat(KbPout_string);
            KbPacket_dBlocks.add(KbPout_string);
        }

        //since session key Ks contained in the first 2 bytes, we know where to look:
        //we know session key Ks is the first 2 8-bit blocks or elements of KaPacket_dBlocks
        String Ks_padded = KbPacket_dBlocks.get(0).concat(KbPacket_dBlocks.get(1));
        System.out.println("Padded session key: " + Ks_padded);
        //we know Ks_padded has 6 leading zeros in elements 0-5
        String Ks = Ks_padded.substring(6, 16);
        System.out.println("Recovered session key Ks: " + Ks);
        //hooray! Bob now has the session key

        //send session key to Alice now?
        a_out.println(Ks);
        //a_out.flush();

        String answer = a_in.readLine();
        System.out.println(answer);
        if(answer.equals("success")) {
            System.out.println(Ks);
            System.out.println("Needleshoes has been a success!");
        }

        toAlice.close();


    }


    public static List<String> split(String text, int size) {
        List<String> output = new ArrayList<String>((text.length() + size - 1)/size);

        for(int start=0; start < text.length(); start += size) {
            output.add(text.substring(start, Math.min(text.length(), start+size)));
        }
        return output;
    }

    public static int PSNG0or1() {
        Random r = new Random();
        return r.nextInt((1-0) + 1) + 0;
    }
}
