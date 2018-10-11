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
    static int portNumber = 3333;
    static int Kb = 0;
    static String Kb_string;
    static String KbPacket_Decrypted;
    public static void main(String[] args) throws IOException {

        Socket BobCDH = new Socket("127.0.0.1", portNumber);
        PrintWriter b_out = new PrintWriter(BobCDH.getOutputStream(),true);
        BufferedReader b_in = new BufferedReader(new InputStreamReader(BobCDH.getInputStream()));

        //start CDH with KDC
        int c = ThreadLocalRandom.current().nextInt(1, 1022);
        int g_c_unmod = (int)Math.pow(g, c);
        int g_c = g_c_unmod%prime;
        //Bob sends g^c mod p to the KDC
        b_out.print(g_c);

        //Bob receives g^d mod p from the KDC
        int g_d = b_in.read();
        //Bob calculates (g^d)^c mod p, sends to KDC
        int g_d_c_unmod = (int)Math.pow(g_d, c);
        int g_d_c = g_d_c_unmod%prime;
        b_out.print(g_d_c);

        int g_c_d = b_in.read();

        if(g_c_d == g_d_c) {
            System.out.println("Diffie-Hellman Completed Successfully! -Bob");
            Kb = g_c_d;
            Kb_string = Integer.toBinaryString(Kb);
        }

        BobCDH.close();

        //now that Bob has key Kb with the KDH, Bob becomes a server to connect to Alice to begin Needham-Schroeder
        ServerSocket Bob = new ServerSocket(0);
        Socket toAlice = Bob.accept();

        PrintWriter a_out = new PrintWriter(toAlice.getOutputStream(), true);
        BufferedReader a_in = new BufferedReader(new InputStreamReader(toAlice.getInputStream()));

        String KbPacket = a_in.readLine();

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
            KbPacket_Decrypted = KbPacket_Decrypted.concat(KbPout_string);
            KbPacket_dBlocks.add(KbPout_string);
        }

        //since session key Ks contained in the first 2 bytes, we know where to look:
        //we know session key Ks is the first 2 8-bit blocks or elements of KaPacket_dBlocks
        String Ks_padded = KbPacket_dBlocks.get(0).concat(KbPacket_dBlocks.get(1));
        //we know Ks_padded has 6 leading zeros in elements 0-5
        String Ks = Ks_padded.substring(6, 15);
        //hooray! Bob now has the session key

        //send session key to Alice now?
        a_out.print(Ks);


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
