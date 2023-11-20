import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.f.TypeFCurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pbc.curve.PBCTypeFCurveGenerator;

public class Setup {
    public static int t=3;
    public static int n=5;

    // Curva standard P-256/secp256r1
//    public static BigInteger p256 = new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951");
//    public static FinitePrimeField z256 = new FinitePrimeField(p256);
//    public static BigInteger a256 = new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16);
//    public static BigInteger b256 = new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
//    public static PrimeCurve E256 = new PrimeCurve(z256, a256, b256, 256);
//    public static Point P256 = E256.getPoint(new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16));
//    public static BigInteger n256 = new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369");
//    public static ECDHKey k256 = ECDHPhase1(E256, P256, n256);
//    public static String bsk_U = "cb9505e39aaf290d7a8ae4fb72c7583d84aae8f256877ff0bfe6bc525aaee5f9";
//    public static String Add_U = "0x522b74B76a339A271b8b8E3D11f7d87100796b67";

    //F-Curve
    public static Pairing pairing = PairingFactory.getPairing("f.properties");
    public static Element P_1 = pairing.getG1().newRandomElement().getImmutable();
    public static Element P_2 = pairing.getG2().newRandomElement().getImmutable();

    public static Element[] esk_S = new Element[n];
    public static Element[] epk_S = new Element[n];

    public static String[] ID_S = new String[n];


    //Generate Encryption Keys of S_i
    public static void generateEKS(){
        for (int i=0;i<n;i++){
            esk_S[i] = pairing.getZr().newRandomElement().getImmutable();
            epk_S[i] = P_1.mulZn(esk_S[i]).getImmutable();
            ID_S[i] = String.valueOf(i);
        }
    }
}
