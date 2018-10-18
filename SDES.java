//Jessup Barrueco
//Cryptography and Network Security 1
//Simplified DES

import java.io.*;
import java.lang.*;
import java.nio.ByteBuffer;
import java.util.*;
import java.math.*;
import java.util.concurrent.ThreadLocalRandom;

class KeyGen {
    private int[] key = new int[10];
    private int[] k1 = new int[8];
    private int[] k2 = new int[8];
    private boolean flag = false;

    KeyGen() {
    }
    public void generate(String inKey) {
        int[] key = new int[10];
        char c;
        String ts;
        try {
            for(int i=0; i<10; i++) {
                c = inKey.charAt(i);
                ts = Character.toString(c);
                key[i] = Integer.parseInt(ts);

                if(key[i] !=0 && key[i] != 1) {
                    System.out.println("Invalid Key!");
                    System.exit(0);
                    return;
                }
            }
        }
        catch(Exception e) {
            System.out.println("Invalid Key!");
            System.exit(0);
            return;
        }
        this.key = key;
        System.out.println("Input key: " + Arrays.toString(this.key));

        permutationP10();
        System.out.println("After Permutation P10 Key: " + Arrays.toString(this.key));

        rotateLeft();
        System.out.println("After LeftShift LS-1 Key: " + Arrays.toString(this.key));

        this.k1 = permutationP8();
        System.out.println("After Permutation P8, Subkey K1 Generated: " + Arrays.toString(this.k1));

        rotateLeft();
        System.out.println("After Left-Shift LS-2 Key: " + Arrays.toString(this.key));

        this.k2 = permutationP8();
        System.out.println("Subkey K2 Generated: " + Arrays.toString(this.k2));

        flag = true;
    }
    private void permutationP10() { //follows 3 5 2 7 4 10 1 9 8 6
        int[] temp = new int[10];
        temp[0] = key[2];
        temp[1] = key[4];
        temp[2] = key[1];
        temp[3] = key[6];
        temp[4] = key[3];
        temp[5] = key[9];
        temp[6] = key[0];
        temp[7] = key[8];
        temp[8] = key[7];
        temp[9] = key[5];

        key = temp;
    }

    private void rotateLeft() { //performs circular left shift/rotation (LS-1) separately on first 5 bits and 2nd 5 bits
        int[] temp = new int[10];

        int[] RH = new int[5];
        int[] LH = new int[5];

        LH[0] = key[0];
        LH[1] = key[1];
        LH[2] = key[2];
        LH[3] = key[3];
        LH[4] = key[4];

        RH[0] = key[5];
        RH[1] = key[6];
        RH[2] = key[7];
        RH[3] = key[8];
        RH[4] = key[9];

        temp[0] = LH[1];
        temp[1] = LH[2];
        temp[2] = LH[3];
        temp[3] = LH[4];
        temp[4] = LH[0];
        temp[5] = RH[1];
        temp[6] = RH[2];
        temp[7] = RH[3];
        temp[8] = RH[4];
        temp[9] = RH[0];

        key = temp;
    }

    private int[] permutationP8() { //follows 6 3 7 4 8 5 10 9
        int[] temp = new int[8];

        temp[0] = key[5];
        temp[1] = key[2];
        temp[2] = key[6];
        temp[3] = key[3];
        temp[4] = key[7];
        temp[5] = key[4];
        temp[6] = key[9];
        temp[7] = key[8];

        return temp;
    }

    public int[] getK1() {
        if(!flag) {
            System.out.println("Error: Keys not generated yet!");
            return null;
        }
        return k1;
    }

    public int[] getK2() {
        if(!flag) {
            System.out.println("Error: Keys not generated yet!");
            return null;
        }
        return k2;
    }
}

class Encryption {
    private int[] K1 = new int[8];
    private int[] K2 = new int[8];
    private int[] plaintext = new int[8];

    void SaveParams(String pt, int[] k1, int[] k2) {
        int[] plain = new int[8];
        char c;
        String ts;
        try {
            for(int i=0; i<8; i++) {
                c = pt.charAt(i);
                ts = Character.toString(c);
                plain[i] = Integer.parseInt(ts);

                if(plain[i] != 0 && plain[i] != 1) {
                    System.out.println("Invalid plaintext!");
                    System.exit(0);
                    return;
                }
            }
        }
        catch(Exception e) {
            System.out.println("Invalid plaintext!");
            System.exit(0);
            return;
        }

        this.plaintext = plain;

//        System.out.println("Plaintext array: " + Arrays.toString(this.plaintext));

        this.K1 = k1;
        this.K2 = k2;
    }

    void InitialPermutation() { //perform IP in [2 6 3 1 4 8 5 7]
        int[] temp = new int[8];

        temp[0] = plaintext[1];
        temp[1] = plaintext[5];
        temp[2] = plaintext[2];
        temp[3] = plaintext[0];
        temp[4] = plaintext[3];
        temp[5] = plaintext[7];
        temp[6] = plaintext[4];
        temp[7] = plaintext[6];

        this.plaintext = temp;

//        System.out.println("Initial Permutation (IP): " + Arrays.toString(this.plaintext));

    }

    void InverseInitialPermutation() { //4 1 3 5 7 2 8 6
        int[] temp = new int[8];

        temp[0] = plaintext[3];
        temp[1] = plaintext[0];
        temp[2] = plaintext[2];
        temp[3] = plaintext[4];
        temp[4] = plaintext[6];
        temp[5] = plaintext[1];
        temp[6] = plaintext[7];
        temp[7] = plaintext[5];

        this.plaintext = temp;
    }

    int[] F(int[] R, int[] SK) { //mapping function, inputs 4bit Right Half of plaintext & 8-bit SubKey, produces 4-bit output
        int[] temp = new int[8];

        //expansion/permutation [4 1 2 3 / 2 3 4 1]
        temp[0] = R[3];
        temp[1] = R[0];
        temp[2] = R[1];
        temp[3] = R[2];
        temp[4] = R[1];
        temp[5] = R[2];
        temp[6] = R[3];
        temp[7] = R[0];

//        System.out.println("Expansion/Permutation on RH: " + Arrays.toString(temp));

        //now XOR bit by bit with subkey
        temp[0] = temp[0] ^ SK[0];
        temp[1] = temp[1] ^ SK[1];
        temp[2] = temp[2] ^ SK[2];
        temp[3] = temp[3] ^ SK[3];
        temp[4] = temp[4] ^ SK[4];
        temp[5] = temp[5] ^ SK[5];
        temp[6] = temp[6] ^ SK[6];
        temp[7] = temp[7] ^ SK[7];

//        System.out.println("XOR with Key: " + Arrays.toString(temp));

        //generate SBoxes
        final int[][] S0 = { {1,0,3,2} , {3,2,1,0} , {0,2,1,3} , {3,1,3,2} };
        final int[][] S1 = { {0,1,2,3} , {2,0,1,3} , {3,0,1,0} , {2,1,0,3} };

        int d11 = temp[0]; //1st bit of 1st half
        int d14 = temp[3]; //4th bit of 1st half
        int row1 = BOPs.B2D(d11, d14); //for input in S0

        int d12 = temp[1]; //2nd bit of 1st half
        int d13 = temp[2]; //3rd bit of 1st half
        int col1 = BOPs.B2D(d12, d13); //for input in S0

        int o1 = S0[row1][col1];
        int[] out1 = BOPs.D2B(o1);

//        System.out.println("S-Box S0: " + Arrays.toString(out1));

        int d21 = temp[4]; //1st bit of 2nd half
        int d24 = temp[7]; //4th bit of 2nd half
        int row2 = BOPs.B2D(d21, d24);

        int d22 = temp[5]; //2nd bit of 2nd half
        int d23 = temp[6]; //3rd bit of 2nd half
        int col2 = BOPs.B2D(d22, d23);

        int o2 = S1[row2][col2];

        int[] out2 = BOPs.D2B(o2);

//        System.out.println("S-Box S1: " + Arrays.toString(out2));

        //4 output bits from 2 SBoxes
        int[] out = new int[4];
        out[0] = out1[0];
        out[1] = out1[1];
        out[2] = out2[0];
        out[3] = out2[1];

        //permutation P4 [2 4 3 1]
        int[] P4 = new int[4];
        P4[0] = out[1];
        P4[1] = out[3];
        P4[2] = out[2];
        P4[3] = out[0];

//        System.out.println("Permutation P4: " + Arrays.toString(P4));

        return P4;
    }

    /////function FK(L, R, SK) = (L (XOR) F(R, SK), R) -- returns 8bit output
    int[] FK(int[] L, int[] R, int[] SK) {
        int[] temp = new int[4];
        int[] out = new int[8];

        temp = F(R, SK);

        //XOR left half with output of F
        out[0] = L[0] ^ temp[0];
        out[1] = L[1] ^ temp[1];
        out[2] = L[2] ^ temp[2];
        out[3] = L[3] ^ temp[3];

        out[4] = R[0];
        out[5] = R[1];
        out[6] = R[2];
        out[7] = R[3];

        return out;
    }

    ////switch function exchanges L and R 4bits
    int[] SW(int[] input) {
        int[] temp = new int[8];

        temp[0] = input[4];
        temp[1] = input[5];
        temp[2] = input[6];
        temp[3] = input[7];
        temp[4] = input[0];
        temp[5] = input[1];
        temp[6] = input[2];
        temp[7] = input[3];

        return temp;
    }

    int[] encrypt(String pt, int[] LK, int[] RK) {
        SaveParams(pt, LK, RK);
        InitialPermutation();
        //1st round: separate LH and RH from 8bit plaintext
        int[] LH = new int[4];
        int[] RH = new int[4];
        LH[0] = plaintext[0];
        LH[1] = plaintext[1];
        LH[2] = plaintext[2];
        LH[3] = plaintext[3];

        RH[0] = plaintext[4];
        RH[1] = plaintext[5];
        RH[2] = plaintext[6];
        RH[3] = plaintext[7];

//        System.out.println("1st round LH: " + Arrays.toString(LH));
//        System.out.println("1st round RH: " + Arrays.toString(RH));

        //1st round with SubKey (SK) K1
        int[] r1 = new int[8];
        r1 = FK(LH, RH, K1);
//        System.out.println("After 1st round: " + Arrays.toString(r1));

        //switch LH and RH of output
        int[] temp = new int[8];
        temp = SW(r1);
        //System.out.println("After Switch function: " + Arrays.toString(temp));

        //for 2nd round, separate LH and RH again
        LH[0] = temp[0];
        LH[1] = temp[1];
        LH[2] = temp[2];
        LH[3] = temp[3];

        RH[0] = temp[4];
        RH[1] = temp[5];
        RH[2] = temp[6];
        RH[3] = temp[7];

        //System.out.println("2nd round LH: " + Arrays.toString(LH));
        //System.out.println("2nd round RH: " + Arrays.toString(RH));

        //2nd round with SK K2
        int[] r2 = new int[8];
        r2 = FK(LH, RH, K2);
        plaintext = r2;
        //System.out.println("After 2nd round: " + Arrays.toString(this.plaintext));

        InverseInitialPermutation();

        //System.out.println("After Inverse IP (Result): " + Arrays.toString(this.plaintext));

        //encryption done: return 8bit output
        return plaintext;
    }

}

public class SDES {
    public static void main(String[] args) {
        ///idea: args[0] is command for en/decrypt
        /////////args[1] is for either plain or ciphertext
        /////////args[2] is key to be used
        KeyGen KG = new KeyGen();
        Encryption enc = new Encryption();
//        Scanner s = new Scanner(System.in);

        String in;   //input
        String key;  //key
//        String decryptionAns; //do we perform decryption?
//        String savekey;

        int[] out_int = new int[8]; //ciphertext for output
        String out;
        //int[] decrypted = new int[8];

//        if (args[0].equals("encrypt")) {
//            try {
//                in = args[1];
//                key = args[2];
//                KG.generate(key);
//                out_int = enc.encrypt(in, KG.getK1(), KG.getK2());
//                String out_string1 = Arrays.toString(out_int).replaceAll(",\\s+", "");
//                String out_string2 = out_string1.replaceAll("\\[", "");
//                out = out_string2.replaceAll("]", "");
//                //need to find some way to return this ciphertext
//            }
//            catch(InputMismatchException e) {
//                System.out.println("Error occurred: Invalid Input");
//            }
//            catch(Exception e) {
//                System.out.println("Error occurred" + e);
//            }
//        }
//
//        if (args[0].equals("decrypt")) {
//            try {
//                in = args[1];
//                key = args[2];
//                KG.generate(key);
//                out_int = enc.encrypt(in, KG.getK2(), KG.getK1());
//                String out_string1 = Arrays.toString(out_int).replaceAll(",\\s+", "");
//                String out_string2 = out_string1.replaceAll("\\[", "");
//                out = out_string2.replaceAll("]", "");
//                //need to find some way to return this decrypted text
//            }
//            catch(InputMismatchException e) {
//                System.out.println("Error occurred: Invalid Input");
//            }
//            catch(Exception e) {
//                System.out.println("Error occurred" + e);
//            }
//        }
//        try {
//            System.out.println("Enter 8-bit Plaintext: ");
//            pt = s.next();
//
//            System.out.println("Enter 10-bit Key: ");
//            key = s.next();
//            savekey = key;
//
//            System.out.println("Key Generation...");
//            KG.generate(key);
//            ct = enc.encrypt(pt, KG.getK1(), KG.getK2());
//            System.out.println("Encrypted: " + Arrays.toString(ct));
//
//            String ciphertext = Arrays.toString(ct).replaceAll(",\\s+", "");
//            String ciphertext1 = ciphertext.replaceAll("\\[", "");
//            String ciphertext2 = ciphertext1.replaceAll("]", "");
//
//            //convert binary string output into byte array for socket programming
//            byte[] outCipher = new BigInteger(ciphertext2, 2).toByteArray();
//
//            System.out.println("Would you like to decrypt as well? Y for yes, N for no: ");
//            decryptionAns = s.next();
//            if(decryptionAns.equals("Y")) {
//                System.out.println("For Decryption, two SubKeys will be used in Reverse Order:");
//                KG.generate(savekey);
//                decrypted = enc.encrypt(ciphertext2, KG.getK2(), KG.getK1());
//                System.out.println("Decrypted: " + Arrays.toString(decrypted));
//            }
        }

//        catch(InputMismatchException e) {
//            System.out.println("Error occurred: Invalid Input");
//        }
//        catch(Exception e) {
//            System.out.println("Error occurred" + e);
//        }
//    }


}

//class CDH {
//    public int CDH() throws IOException {
//        final int prime = 1021;
//        final int g = 10;
//        //was this the correct allocation number?????
//        ByteBuffer buf = ByteBuffer.allocate(128);
//
//        //when Alice runs CDH, Ka = output
//        //for Bob, Kb = output
//        int output = 0;
//
//        //Client picks random number a in the range 1-1021
//        //nextInt is inclusive of bottom value, exclusive of top; add 1 to the max
//        int a = ThreadLocalRandom.current().nextInt(1, 1022);
//        int b = ThreadLocalRandom.current().nextInt(1, 1022);
//
////        ServerSocket KDC = new ServerSocket(0);
////        Socket client = KDC.accept();
////        OutputStream sockOut = client.getOutputStream();
////        InputStream sockIn = client.getInputStream();
////        System.out.println("Client connected on port " + KDC.getLocalPort() + " servicing requests:");
//
//        //client computes g to the power of a, reduce mod prime
//        int g_a_unmod = (int)Math.pow(g, a);
//        int g_a = g_a_unmod%prime;
//
//        //server picks b, sends g^b mod p
//        int g_b_unmod = (int)Math.pow(g, b);
//        int g_b = g_b_unmod%prime;
//
//        //client receives g^b, computes (g^b)^a mod p
//        int g_b_a_unmod = (int)Math.pow(g_b, a);
//        int g_b_a = g_b_a_unmod%prime;
//
//        //server receives g^a, computes (g^a)^b mod p
//        int g_a_b_unmod = (int)Math.pow(g_a, b);
//        int g_a_b = g_a_b_unmod%prime;
//
//
//        //verify g_b_a == g_a_b
//        if(g_b_a == g_a_b) {
//            output = g_a_b;
//            buf.putInt(g_a_b);
//
////            sockOut.write(buf.array());
////            sockIn.read(buf.array());
//        }
//
//        return output;
//        ///how do we know output is 10bits long? must be that length to be a key
//
//    }
//}

class BOPs { //binary operator functions stored here
    static int B2D(int...bits) { //gets binary digits as input and returns decimal number
        int temp=0;
        int base=1;
        for(int i=bits.length-1 ; i>=0; i--) {
            temp = temp + (bits[i]*base);
            base = base*2;
        }
        return temp;
    }
    static int[] D2B(int n) { //gets decimal number as input and returns array of binary
        if(n==0) {
            int[] zero = new int[2];
            zero[0] = 0;
            zero[1] = 0;
            return zero;
        }
        int[] temp = new int[10];
        int count = 0;
        for (int i=0; n!=0; i++) {
            temp[i] = n % 2;
            n = n/2;
            count++;
        }
        int[] temp2 = new int[count];
        for(int i=count-1, j=0; i>=0 && j<count; i--, j++) {
            temp2[j] = temp[i];
        }
        //require 2-bits at output: add leading 0
        if(count<2) {
            temp = new int[2];
            temp[0] = 0;
            temp[1] = temp2[0];
            return temp;
        }
        return temp2;
    }
}