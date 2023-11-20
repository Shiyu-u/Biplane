import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.math.ec.ECPoint;
import util.CryptoUtil;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static util.CryptoUtil.scalarMultiply;

public class PasswordHardening {
    public static Element blindPw(String ID, String pw, Element r) throws NoSuchAlgorithmException {
        Element hashpw = CryptoUtil.stringHashToG(pw, Setup.pairing.getG1(), Setup.pairing).getImmutable();
        return hashpw.mulZn(r).duplicate().duplicate();
//        return pwStar;
    }

    public static Element Sign(Element si, Element msg){
        return msg.mulZn(si).duplicate().getImmutable();
    }

    public static Element aggregateSig(Element[] sigmaStar, Element[] S_i, Element r, int t, int n, Element pwStar) {
        boolean[] accept = new boolean[n];
        for (int i = 0; i < n; i++) {
            Element left = Setup.pairing.pairing(sigmaStar[i], Setup.P_2).getImmutable().powZn(Setup.pairing.getGT().newRandomElement().getImmutable()).getImmutable();
            Element right = Setup.pairing.pairing(pwStar, S_i[i]);
            if (left.isEqual(right)) {
                accept[i] = true;
            } else accept[i] = false;
        }
        Element aggSigma = sigmaStar[0].duplicate().getImmutable();
        Element[] x = new Element[t];
        for (int i=0; i< t; i++){
            x[i] = Setup.pairing.getZr().newElement(i+1).getImmutable();
        }
        Element[] lambda = computeLagrangeCoefficients(x, t);
        int num = 0;
        for (int i=0; i<n; i++){
            if (num> t-1){
                break;
            }
            if(accept[i] = true){
                Element term = sigmaStar[i].duplicate().getImmutable();
                term.mulZn(lambda[i]);
                aggSigma.add(term);
                num++;
            }
        }
        aggSigma.mulZn(r.invert()).getImmutable();
        return aggSigma;
    }

    public static byte[] getHpw(Element sigma, String pw_U) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        return digest.digest((sigma.toString() + pw_U).getBytes());
    }

    private static Element[] computeLagrangeCoefficients(Element[] x, int t) {
        Element[] coefficients = new Element[t];

        for (int i = 0; i < t; i++) {
            coefficients[i] = computeLagrangeCoefficient(x, i, t);
        }

        return coefficients;
    }

    private static Element computeLagrangeCoefficient(Element[] x, int index, int t) {
        Element numerator = Setup.pairing.getZr().newOneElement().duplicate().getImmutable();
        Element denominator = Setup.pairing.getZr().newOneElement().duplicate().getImmutable();
//        Element lambda = numerator.mulZn(denominator.invert());

        for (int j = 0; j < t; j++) {
            if (j != index) {
//                numerator = x[j].mulZn(numerator);
//                denominator = x[j].sub(x[index]).mul(denominator);
//                Element invertedDeno = denominator.invert();
//                lambda = numerator.mul(invertedDeno).mulZn(lambda);
                numerator.mul(x[j]);
                denominator.mul(x[j].sub(x[index]));
            }
        }
//        return lambda;
        return numerator.mul(denominator.invert()).duplicate().getImmutable();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        int n = 2;
        int t = 2;
        String pw = "password";
        Element r = Setup.pairing.getZr().newRandomElement();
        Element bpw = blindPw("user", pw, r);

        Element[] s =  new Element[n];
        Element[] sigmaStari = new Element[n];
        Element[] S = new Element[n];
        s[0] = Setup.pairing.getZr().newRandomElement();
        s[1] = Setup.pairing.getZr().newRandomElement();
        S[0] = Setup.P_2.mulZn(s[0]);
        S[1] = Setup.P_2.mulZn(s[1]);
        sigmaStari[0] = Sign(s[0], bpw);
        sigmaStari[1] = Sign(s[1], bpw);

        Element sigma = aggregateSig(sigmaStari, S, r, t, n, bpw);
        byte[] hpw = getHpw(sigma, pw);

        System.out.println(bpw);
        System.out.println(sigmaStari);
        System.out.println(sigma);
        System.out.println(hpw.toString());
    }
}
