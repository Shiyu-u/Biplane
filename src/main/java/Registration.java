import it.unisa.dia.gas.jpbc.Element;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static util.CryptoUtil.getHash;

public class Registration {
    public static byte[][] cre = new byte[Setup.n][];
    public static String bsk_U = "cb9505e39aaf290d7a8ae4fb72c7583d84aae8f256877ff0bfe6bc525aaee5f9";
    public static String Add_U = "0x522b74B76a339A271b8b8E3D11f7d87100796b67";

    public static Element esk_U;
    public static Element epk_U;

    public static long UTime_Reg = 0;
    public static long STime_Reg = 0;
    //KeyGen

    public static void KeyGen(){
        long Time1 = System.currentTimeMillis();
        esk_U = Setup.pairing.getZr().newRandomElement().duplicate().getImmutable();
        // Compute the corresponding public key
        epk_U = Setup.P_1.powZn(esk_U).duplicate().getImmutable();
        long Time2 = System.currentTimeMillis();
        UTime_Reg += Time2 - Time1;
    }

    public static void signUp(String ID_U, String pw_U, Element esk_U, int t, int n, String ID_Si) throws NoSuchAlgorithmException {
        long UTime1 = System.currentTimeMillis();
        Element r = Setup.pairing.getZr().newRandomElement().duplicate().getImmutable();
        Element pwStar = PasswordHardening.blindPw(ID_U, pw_U, r);
        long UTime2 = System.currentTimeMillis();
        UTime_Reg += UTime2 - UTime1;

        long STime1 = System.currentTimeMillis();
        DisSecSharing.DisSecSharing(t, n);
        Element[] sigmaStar = new Element[n];
        for (int i=0;i<n;i++){
            sigmaStar[i] = PasswordHardening.Sign(DisSecSharing.s[i], pwStar);
        }
        long STime2 = System.currentTimeMillis();
        STime_Reg +=STime2 - STime1;

        long UTime3 = System.currentTimeMillis();
        Element sigma = PasswordHardening.aggregateSig(sigmaStar, DisSecSharing.S, r, t, n, pwStar);
        byte[] hpw = PasswordHardening.getHpw(sigma, pw_U);
        long STime3 = System.currentTimeMillis();
        for (int i=0;i<n;i++){
            MessageDigest digest = MessageDigest.getInstance("SHA3-256");
            cre[i] = digest.digest((hpw.toString() + ID_Si).getBytes());
        }
        long UTime4 = System.currentTimeMillis();
        long STime4 = System.currentTimeMillis();
        UTime_Reg += UTime4 - UTime3;
        STime_Reg += STime4 - STime3;
        System.out.println("Utime_Reg:" + UTime_Reg);
        System.out.println("AllSTime_Reg:" + STime_Reg);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        KeyGen();
        System.out.println(esk_U);
        System.out.println(epk_U);
        signUp("user", "password", esk_U, Setup.t, Setup.n, Setup.ID_S[1]);
        System.out.println(cre);
    }
}
