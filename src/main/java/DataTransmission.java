import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import util.CryptoUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class DataTransmission {

    public static long UTime_DT = 0;
    public static long STime_DT = 0;

    static class DualOutput {
        private final Element element;

        private final byte[] byteArray;

        public DualOutput(Element element, byte[] byteArray) {
            this.element = element;
            this.byteArray = byteArray;
        }

        public Element getElement() {
            return element;
        }

        public byte[] getByteArray() {
            return byteArray;
        }
    }
    public static DualOutput DataSend(String ID_U, Element epk_Si, String ID_Si, String plaintext) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        long UTime1 = System.currentTimeMillis();
        Element alpha = Setup.pairing.getZr().newRandomElement().duplicate().getImmutable();
        Element y = epk_Si.mulZn(alpha).duplicate().getImmutable();
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        byte[] k = digest.digest(y.toBytes());
        Element c0 = Setup.P_1.mulZn(alpha).duplicate().getImmutable();
        byte[] c1 = CryptoUtil.AESEncrypt(k, (plaintext + ID_U + ID_Si).getBytes());
        long UTime2 = System.currentTimeMillis();
        long UTime_DT = UTime2 - UTime1;
        System.out.println("UTime_DT:" + UTime_DT);
        return new DualOutput(c0, c1);
    }

    public static byte[] DataRec(DualOutput C, Element esk_Si) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        long STime1 = System.currentTimeMillis();
        Element c0 = C.getElement();
        byte[] c1 = C.getByteArray();
        Element y = c0.mulZn(esk_Si).getImmutable();
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        byte[] k = digest.digest(y.toBytes());
        byte[] m = CryptoUtil.AESDecrypt(k, c1);
        long STime2 = System.currentTimeMillis();
        long STime_DT = STime2 - STime1;
        System.out.println("STime_DT:" + STime_DT);
        return m;
    }

    public static void main(String[] args) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        Element esk = Setup.pairing.getZr().newRandomElement().duplicate().getImmutable();
        Element epk = Setup.P_1.mulZn(esk).duplicate().getImmutable();
        DualOutput C = DataSend("user", epk, "server", "1234");
        byte[] m = DataRec(C, esk);
        String mString = new String(m);
        System.out.println(mString);
    }
}
