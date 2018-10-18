//import com.sun.security.ntlm.Server;

import java.io.*;
import java.lang.*;
import java.nio.ByteBuffer;
import java.util.*;
import java.math.*;
import java.util.concurrent.ThreadLocalRandom;
import java.net.*;

public class KDC {
    final static int prime = 1021;
    final static int g = 10;
    static int Ka = 0;
    static String Ka_string;
    static int Kb = 0;
    static String Kb_string;
    static int[] Ks = new int[10];
    static String Ks_string;
    static String N2;
    static String Step2_Encrypted_Kb;
    static String Step2_Encrypted_Ka;
    static int portNumber = 3333;
    public static void main(String[] args) throws IOException {
        ServerSocket KDC = new ServerSocket(portNumber);
        Socket toAlice_CDH = KDC.accept();
        PrintWriter a0_out = new PrintWriter(toAlice_CDH.getOutputStream(), true);
        BufferedReader a0_in = new BufferedReader(new InputStreamReader(toAlice_CDH.getInputStream()));
        //assume AliceCDH connects first
        //start CDH with AliceCDH
        int b = ThreadLocalRandom.current().nextInt(1, 1022);

        System.out.println("Accepted connection from Alice");

        System.out.println("b=" + b);

        //int g_b_unmod = (int)Math.pow(g, b);
        int g_b = 1;
        for(int i=0; i<b; i++) {
            g_b = (g_b*g)%prime;
        }
        System.out.println("g_b=" + g_b);
        //int g_b = g_b_unmod%prime;

        a0_out.println(g_b);
        //a0_out.flush();

        System.out.println("Sent g_b=" + g_b);

        //KDC receives g_a from Alice
        System.out.println("Waiting for g_a from Alice");
        String g_a_string = a0_in.readLine();
        int g_a = Integer.parseInt(g_a_string);
        System.out.println("Received g_a=" + g_a);
        //KDC computes (g^a)^b mod p, sends to Alice
        int g_a_b = 1;
        for(int i=0; i<b; i++) {
            g_a_b = (g_a_b*g_a)%prime;
        }
        //int g_a_b_unmod = (int)Math.pow(g_a, b);
        //int g_a_b = g_a_b_unmod%prime;
        a0_out.println(g_a_b);
        //a0_out.flush();

        System.out.println("Sent g_a_b=" + g_a_b);

        String g_b_a_string = a0_in.readLine();
        int g_b_a = Integer.parseInt(g_b_a_string);
        System.out.println("Received g_b_a=" + g_b_a);

        if(g_b_a != g_a_b) {
            System.out.println("CDH Failed");
        }

        if(g_b_a == g_a_b) {
            System.out.println("Diffie-Hellman Completed Successfully! -KDC");
            Ka = g_a_b;
            Ka_string = Integer.toBinaryString(Ka);
            if(Ka_string.length() < 10) {
                int difference = 10 - Ka_string.length();
                for(int i=0; i<difference; i++) {
                    String pad = "0";
                    Ka_string = pad.concat(Ka_string);
                }
            }
        }

        //at this point, AliceCDH will disconnect, BobCDH will connect

        toAlice_CDH.close();

        System.out.println("KDC disconnects from Alice");

        Socket toBob_CDH = KDC.accept();
        PrintWriter b_out = new PrintWriter(toBob_CDH.getOutputStream(), true);
        BufferedReader b_in = new BufferedReader(new InputStreamReader(toBob_CDH.getInputStream()));

        System.out.println("KDC established connection with Bob for CDH");

        //pick a new random variable within range
        int d = ThreadLocalRandom.current().nextInt(1, 1022);

        int g_d_unmod = (int)Math.pow(g, d);
        int g_d = g_d_unmod%prime;
        b_out.println(g_d);
        //b_out.flush();

        //KDC receives g_c from Bob
        String g_c_string = b_in.readLine();
        int g_c = Integer.parseInt(g_c_string);
        //KDC computes (g^a)^b mod p, sends to Bob
        int g_c_d_unmod = (int)Math.pow(g_c, d);
        int g_c_d = g_c_d_unmod%prime;
        b_out.println(g_c_d);
        //b_out.flush();

        String g_d_c_string = b_in.readLine();
        int g_d_c = Integer.parseInt(g_d_c_string);

        if(g_d_c == g_c_d) {
            System.out.println("Diffie-Hellman Completed Successfully! -KDC");
            Kb = g_c_d;
            Kb_string = Integer.toBinaryString(Kb);
            System.out.println("Kb_string length " + Kb_string.length());
            if(Kb_string.length() < 10) {
                int difference = 10 - Kb_string.length();
                for(int i=0; i<difference; i++) {
                    String pad = "0";
                    Kb_string = pad.concat(Kb_string);
                }
            }
        }
        //CDH is done, terminate connection to Bob
        toBob_CDH.close();

        ///now NeedleShoes can begin; establish connection with Alice again for Step 1-2
        Socket toAlice_Step1 = KDC.accept();
        PrintWriter a1_out = new PrintWriter(toAlice_Step1.getOutputStream(), true);
        BufferedReader a1_in = new BufferedReader(new InputStreamReader(toAlice_Step1.getInputStream()));

        System.out.println("KDC established connection with Alice for N-S Step 1");

        //KDC receives concatenated string
        //we know IDa, IDb are each 16-bits (2 bytes) long, N1 is 32-bits (4 bytes) -- KDC "skips ahead" to get N1
        String receive = a1_in.readLine();
        String N1 = receive.substring(receive.length() - 32);
        String IDa = receive.substring(0, 15);
        String IDb = receive.substring(16,31);

        //KDC checks to make sure it separated the string correctly
        String test = IDa.concat(IDb).concat(N1);

        if(!test.equals(receive)) {
            System.out.println("Problem processing Step 1");
            System.exit(0);
        }

        //generate a nonce here N2 to pad second encryption; increase security against replay attacks
        int[] N2_int = new int[32];
        for (int i = 0; i<32; i++) {
            //N2_int[i] = (int)Math.round(Math.random( ));
            N2_int[i] = PSNG0or1();
        }
        String N2_string1 = Arrays.toString(N2_int).replaceAll(",\\s+", "");
        String N2_string2 = N2_string1.replaceAll("\\[", "");
        N2 = N2_string2.replaceAll("]", "");

        ///Now, KDC generates 10bit random number session key Ks
        for (int i = 0; i<10; i++) {
            //Ks[i] = (int)Math.round(Math.random( ));
            Ks[i] = PSNG0or1();
        }
        String Ks_string0 = Arrays.toString(Ks).replaceAll(",\\s+", "");
        String Ks_string1 = Ks_string0.replaceAll("\\[", "");
        Ks_string = Ks_string1.replaceAll("]", "");

        KeyGen KGKb = new KeyGen();
        Encryption encKb = new Encryption();

        ///pad the session key with 6 leading 0s to make it the same 16-bit/2byte length as IDa
        String Ks_pad = "000000";
        String Ks_string_padded = Ks_pad.concat(Ks_string);

        //now encrypt Ks || IDa || N2 with key Kb
        KGKb.generate(Kb_string);
        String step2Kb = Ks_string_padded.concat(IDa).concat(N2);
        ////now, divide step2Kb into 8-bit blocks to be encrypted and then concatenated

        List<String> step2Kb_blocks = split(step2Kb, 8);
        for(String block : step2Kb_blocks) {
            int[] kb2out_int = encKb.encrypt(block, KGKb.getK1(), KGKb.getK2());
            String kb2out_string1 = Arrays.toString(kb2out_int).replaceAll(",\\s+", "");
            String kb2out_string2 = kb2out_string1.replaceAll("\\[", "");
            String kb2out_string = kb2out_string2.replaceAll("]", "");
            Step2_Encrypted_Kb = Step2_Encrypted_Kb.concat(kb2out_string);
        }

        //now, the Kb packet has been successfully encrypted
        //move onto the Ka packet
        KeyGen KGKa = new KeyGen();
        Encryption encKa = new Encryption();

        KGKa.generate(Ka_string);
        String step2Ka = Ks_string_padded.concat(IDb).concat(N1).concat(Step2_Encrypted_Kb);

        List<String> step2Ka_blocks = split(step2Ka, 8);
        for(String block : step2Ka_blocks) {
            int[] ka2out_int = encKa.encrypt(block, KGKa.getK1(), KGKa.getK2());
            String ka2out_string1 = Arrays.toString(ka2out_int).replaceAll(",\\s+", "");
            String ka2out_string2 = ka2out_string1.replaceAll("\\[", "");
            String ka2out_string = ka2out_string2.replaceAll("]", "");
            Step2_Encrypted_Ka = Step2_Encrypted_Ka.concat(ka2out_string);
        }

        //now, step 2 is finished, send this Ka encrypted packet back to Alice
        a1_out.println(Step2_Encrypted_Ka);
        //a1_out.flush();

        //the KDC's job is now complete
        toAlice_Step1.close();
        KDC.close();

        System.out.println("KDC completed Step 1 with Alice. My job is now complete!");

    }

    public static int PSNG0or1() {
        Random r = new Random();
        return r.nextInt((1-0) + 1) + 0;
    }

    public static List<String> split(String text, int size) {
        List<String> output = new ArrayList<String>((text.length() + size - 1)/size);

        for(int start=0; start < text.length(); start += size) {
            output.add(text.substring(start, Math.min(text.length(), start+size)));
        }
        return output;
    }
}
