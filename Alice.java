import java.io.*;
import java.lang.*;
import java.nio.ByteBuffer;
import java.util.*;
import java.math.*;
import java.util.concurrent.ThreadLocalRandom;
import java.net.*;

public class Alice {
    final static int prime = 1021;
    final static int g = 10;
    static int portNumber = 3333;
    static int portNumber_AB = 3335;
    static int Ka = 0;
    static String Ka_string;
    public static String IDa;
    public static String IDb;
    public static String N1;
    static String KaPacket_Decrypted;
    static String KbPacket;
    public static void main(String[] args) throws IOException {
        KbPacket = "";
        Socket AliceCDH = new Socket("127.0.0.1", portNumber);
        AliceCDH.setSoTimeout(2000);
        PrintWriter cdh_out = new PrintWriter(AliceCDH.getOutputStream(),true);
        BufferedReader cdh_in = new BufferedReader(new InputStreamReader(AliceCDH.getInputStream()));
        //start CDH with KDC
        System.out.println("Established connection to KDC");
        int a = ThreadLocalRandom.current().nextInt(1, 1022);

        System.out.println("a=" + a);

        //int g_a_unmod = (int)Math.pow(g, a);
        int g_a = 1;
        for(int i=0; i<a; i++) {
            g_a = (g_a*g)%prime;
        }
        System.out.println("g_a=" + g_a);
        //int g_a = g_a_unmod%prime;
        //Alice sends g^a mod p to the KDC
        System.out.println("Sending g_a=" + g_a + " to KDC");
        cdh_out.println(g_a);
        //cdh_out.flush();

        //Alice receives g^b mod p from the KDC
        String g_b_string = cdh_in.readLine();
        int g_b = Integer.parseInt(g_b_string);
        System.out.println("Received g_b=" + g_b);

        //Alice calculates (g^b)^a mod p, sends to KDC
        //int g_b_a_unmod = (int)Math.pow(g_b, a);
        int g_b_a = 1;
        for(int i=0; i<a; i++) {
            g_b_a = (g_b_a*g_b)%prime;
        }
        //int g_b_a = g_b_a_unmod%prime;
        System.out.println("g_b_a: " + g_b_a);
        cdh_out.println(g_b_a);
        //cdh_out.flush();

        System.out.println("Sent g_b_a=" + g_b_a);

        String g_a_b_string = cdh_in.readLine();
        int g_a_b = Integer.parseInt(g_a_b_string);
        System.out.println("Received g_a_b=" + g_a_b);

        if(g_b_a != g_a_b) {
            System.out.println("CDH Failed");
        }

        if(g_b_a == g_a_b) {
            System.out.println("Diffie-Hellman Completed Successfully! -Alice");
            Ka = g_b_a;
            Ka_string = Integer.toBinaryString(Ka);
            System.out.println("Ka_string length " + Ka_string.length());
            if(Ka_string.length() < 10) {
                int difference = 10 - Ka_string.length();
                for(int i=0; i<difference; i++) {
                    String pad = "0";
                    Ka_string = pad.concat(Ka_string);
                }
            }
        }
        //System.out.println(Ka);
        //System.out.println(Ka_string);

        AliceCDH.close();

        //now Alice generates first nonce N1 to send to KDC to begin Needham-Schroeder
        //N1 is different for each session
        //with my construction, IDa and IDb are also different for each session

        ///Alice generates random IDa, IDb each 2-bytes long
        int[] IDa_int = new int[16];
        for (int i = 0; i<16; i++) {
            //IDa_int[i] = (int)Math.round(Math.random( ));
            IDa_int[i] = PSNG0or1();
        }
        String IDa_string1 = Arrays.toString(IDa_int).replaceAll(",\\s+", "");
        String IDa_string2 = IDa_string1.replaceAll("\\[", "");
        IDa = IDa_string2.replaceAll("]", "");

        int[] IDb_int = new int[16];
        for (int i = 0; i<16; i++) {
            //IDb_int[i] = (int)Math.round(Math.random( ));
            IDb_int[i] = PSNG0or1();
        }
        String IDb_string1 = Arrays.toString(IDb_int).replaceAll(",\\s+", "");
        String IDb_string2 = IDb_string1.replaceAll("\\[", "");
        IDb = IDb_string2.replaceAll("]", "");

        /////generate first nonce N1 also as random number, 32-bit length (4 bytes)
        int[] N1_int = new int[32];
        for (int i = 0; i<32; i++) {
            //N1_int[i] = (int)Math.round(Math.random( ));
            N1_int[i] = PSNG0or1();
        }
        String N1_string1 = Arrays.toString(N1_int).replaceAll(",\\s+", "");
        String N1_string2 = N1_string1.replaceAll("\\[", "");
        N1 = N1_string2.replaceAll("]", "");
        System.out.println("N1 length: " + N1.length());

        Socket A2KDC = new Socket("127.0.0.1", portNumber);
        A2KDC.setSoTimeout(2000);
        PrintWriter A2KDCout = new PrintWriter(A2KDC.getOutputStream(),true);
        BufferedReader A2KDCin = new BufferedReader(new InputStreamReader(A2KDC.getInputStream()));

        //concatenate IDa || IDb || N1 for Alice to send to KDC
        String step1 = IDa.concat(IDb).concat(N1);
        System.out.println("Alice sends initial packet to KDC " + step1);
        A2KDCout.println(step1);
        //A2KDCout.flush();

        //now Alice receives Ka packet from KDC
        String KaPacket = A2KDCin.readLine();
        System.out.println("Alice received KaPacket from KDC");
        System.out.println(KaPacket);

        KeyGen KGKa = new KeyGen();
        Encryption eKa = new Encryption();

        System.out.println(Ka_string);
        KGKa.generate(Ka_string);

        //Alice now decrypts KaPacket byte by byte to receive the session key
        //uses key shared w KDC Ka to do this
        List<String> KaPacket_blocks = split(KaPacket, 8);
        List<String> KaPacket_dBlocks = new ArrayList<String>();
        for(String block : KaPacket_blocks) {
            System.out.println(block);
            //use subkeys in reverse order
            int[] KaPout_int = eKa.encrypt(block, KGKa.getK2(), KGKa.getK1());
            String KaPout_string1 = Arrays.toString(KaPout_int).replaceAll(",\\s+", "");
            String KaPout_string2 = KaPout_string1.replaceAll("\\[", "");
            String KaPout_string = KaPout_string2.replaceAll("]", "");
            System.out.println("KaPacket Decrypted block: " + KaPout_string);
            //KaPacket_Decrypted = KaPacket_Decrypted.concat(KaPout_string);
            KaPacket_dBlocks.add(KaPout_string);
        }

        //we know session key Ks is the first 2 8-bit blocks or elements of KaPacket_dBlocks
        String Ks_padded = KaPacket_dBlocks.get(0).concat(KaPacket_dBlocks.get(1));
        System.out.println("Ks_padded = " + Ks_padded);
        //we know Ks_padded has 6 leading zeros in elements 0-5
        String Ks = Ks_padded.substring(6, 16);
        System.out.println("Session key Ks = " + Ks);
        //hooray! Alice now has the session key

        //now Alice must retrieve encrypted KbPacket to send to Bob
        //because we have fixed variable lengths, KbPacket is elements 8-16 of KaPacket_dBlocks
        for(int i=8; i<16; i++) {
            KbPacket = KbPacket.concat(KaPacket_dBlocks.get(i));
        }

        A2KDC.close();

        //finally, Alice is ready to talk to Bob
        Socket A2B = new Socket("127.0.0.1", portNumber_AB);
        PrintWriter A2Bout = new PrintWriter(A2B.getOutputStream(),true);
        BufferedReader A2Bin = new BufferedReader(new InputStreamReader(A2B.getInputStream()));

        System.out.println("Alice sends KbPacket to Bob " + KbPacket);
        A2Bout.println(KbPacket);
        //A2Bout.flush();
        //System.out.println(KbPacket);

        //now Alice receives the decrypted session key from Bob, checks to make sure
        String Ks_FromBob = A2Bin.readLine();
        System.out.println("Received Ks from Bob: " + Ks_FromBob);

        if(Ks_FromBob.equals(Ks)) {
            A2Bout.println("success");
            //A2Bout.flush();
            System.out.println("Needleshoes has been a success!");
            System.out.println(Ks);
        }

        A2B.close();

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
