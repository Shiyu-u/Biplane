import it.unisa.dia.gas.jpbc.Element;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Set;

public class test {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        String ID = "Biplane_User";
        String pw = "password";
        Setup.generateEKS();
        Registration.KeyGen();
        Registration.signUp(ID, pw, Registration.esk_U, Setup.t, Setup.n, Setup.ID_S[1]);
        byte[] hpw = KeyManagement.HPassReq(ID, pw, Setup.n, Setup.t);
        KeyManagement.keyAuth(Registration.esk_U, Registration.bsk_U, Registration.epk_U, hpw, ID);

        byte[][] keys_R = KeyManagement.keyRetri(ID, hpw, KeyManagement.cesk, KeyManagement.cbsk);

        DataTransmission.DualOutput C = DataTransmission.DataSend(ID, Setup.epk_S[1], Setup.ID_S[1], "plaintext");

        byte[] m = DataTransmission.DataRec(C, Setup.esk_S[1]);

        System.out.println(m);
    }
}
