import it.unisa.dia.gas.jpbc.Element;
import util.CryptoUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class KeyManagement {
    public static byte[] cesk;
    public static byte[] cbsk;


    public static String hIDU;

    public static long UTime_KM = 0;
    public static long STime_KM = 0;

    public static byte[] HPassReq(String ID_U, String pw_U, int n, int t) throws NoSuchAlgorithmException {
        long UTime1 = System.currentTimeMillis();
        Element r = Setup.pairing.getZr().newRandomElement().duplicate().getImmutable();
        Element pwStar = PasswordHardening.blindPw(ID_U, pw_U, r);
        long UTime2 = System.currentTimeMillis();
        UTime_KM += UTime2 - UTime1;

        long STime1 = System.currentTimeMillis();
        Element[] sigmaStar = new Element[n];
        for (int i=0;i<n;i++){
            sigmaStar[i] = PasswordHardening.Sign(DisSecSharing.s[i], pwStar);
        }
        long STime2 = System.currentTimeMillis();
        STime_KM += STime2 - STime1;

        long UTime3 = System.currentTimeMillis();
        Element sigma = PasswordHardening.aggregateSig(sigmaStar, DisSecSharing.S, r, t, n, pwStar);
        byte[] hpw = PasswordHardening.getHpw(sigma, pw_U);
        long UTime4 = System.currentTimeMillis();
        UTime_KM += UTime4 - UTime3;
        System.out.println("AllSTime_KM:" + STime_KM);
        return hpw;
    }

    public static void keyAuth(Element esk_U, String bsk_U, Element epk_U, byte[] hpw_U, String ID_U) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        long UTime1 = System.currentTimeMillis();
        cbsk = CryptoUtil.AESEncrypt(hpw_U, bsk_U.getBytes());
        cesk = CryptoUtil.AESEncrypt(hpw_U, esk_U.toBytes());
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        hIDU = Arrays.toString(digest.digest((ID_U).getBytes()));
        long UTime2 = System.currentTimeMillis();
        UTime_KM += UTime2 - UTime1;
    }

    public static byte[][] keyRetri(String ID_U, byte[] hpw, byte[] cesk, byte[] cbsk) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        long UTime1 =System.currentTimeMillis();
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
//        byte[] hID = digest.digest((ID_U).getBytes());

        byte[] esk_R = CryptoUtil.AESDecrypt(hpw, cesk);
        byte[] bsk_R = CryptoUtil.AESDecrypt(hpw, cbsk);
        byte[][] keys_R = new byte[3][];
        keys_R[0] = esk_R;
        keys_R[1] = bsk_R;
        keys_R[2] = Registration.epk_U.duplicate().getImmutable().toBytes();
        long UTime2 =System.currentTimeMillis();
        UTime_KM = UTime2 - UTime1;
        System.out.println("UTime_KM:"+ UTime_KM);
        return keys_R;
    }

    static boolean ByteCompare(byte[] b1, byte[] b2)
    {
        if (b1.length != b2.length) return false;
        if (b1 == null || b2 == null) return false;
        for (int i = 0; i < b1.length; i++)
            if (b1[i] != b2[i])
                return false;
        return true;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        DisSecSharing.DisSecSharing(Setup.t, Setup.n);
        byte[] hpw = HPassReq("user", "password", Setup.n, Setup.t);
        System.out.println(hpw);
        Element esk = Setup.pairing.getZr().newRandomElement().duplicate().getImmutable();
        Element epk = Setup.P_1.duplicate().getImmutable().mulZn(esk);
        keyAuth(esk, Registration.bsk_U, epk, hpw, "user");
        System.out.println(cesk);
        System.out.println(cbsk);
        System.out.println(hIDU);

        Registration.KeyGen();
        byte[][] keys = keyRetri("user", hpw, cesk, cbsk);
        System.out.println(ByteCompare(keys[0], esk.toBytes()));
        System.out.println(ByteCompare(keys[1], Registration.bsk_U.getBytes()));
    }
}
