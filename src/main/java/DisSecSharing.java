import it.unisa.dia.gas.jpbc.Element;

import java.math.BigInteger;


public class DisSecSharing {
    public static Element[][] a = new Element[Setup.n][Setup.t];
    public static Element[][] aP = new Element[Setup.n][Setup.t];
    public static Element[][] f = new Element[Setup.n][Setup.n];

    public static Element[] s = new Element[Setup.n];

    public static Element[] S = new Element[Setup.n];

    public static boolean[] validFj = new boolean[Setup.n];
    public static void DisSecSharing(int t, int n){
        for (int i=0;i<n;i++){
            generateAi(t, i);
            computeAPi(t, i);
            computeFi(t, n, i);
        }
        Element[] fj = new Element[n];
        for (int i=0;i<n;i++){
            for (int k=0;k<n;k++){
                fj[k] = f[k][i];
            }
            verifyFj(t, n, fj, aP, i);
            computeSi(n, fj, i);

            S[i] = Setup.P_2.mulZn(s[i]);
        }
    }

    private static void generateAi(int t, int i){
        for (int j=0; j< t; j++){
            a[i][j] = Setup.pairing.getZr().newRandomElement().duplicate().getImmutable();
        }
    }

    private static void computeAPi(int t, int i){
        for (int j=0; j< t; j++){
            aP[i][j] = Setup.P_1.duplicate().mulZn(a[i][j]).getImmutable();
        }
    }

    private static void computeFi(int t, int n, int i){
        for (int k=0; k<n; k++){
            f[i][k] = Setup.pairing.getZr().newZeroElement().duplicate().getImmutable();
            if (k != i){
                Element x = Setup.pairing.getZr().newElement(i).duplicate().getImmutable();
                for (int j=0;j<t;j++){
                    Element term = a[i][j].mulZn(x.pow(BigInteger.valueOf(j))).duplicate().getImmutable();
                    f[i][k].add(term);
                }
            }
        }
    }

    private static void verifyFj(int t, int n, Element[] fj, Element[][] aP, int i) {
        for (int k = 0; k < n; k++) {
            if (k != i) {
                Element left = Setup.P_1.mulZn(fj[k]).duplicate().getImmutable();
                Element right = Setup.pairing.getG1().newZeroElement().duplicate().getImmutable();
                for (int m = 0; i < t; i++) {
                    Element term1 = Setup.pairing.getZr().newElement(i).pow(BigInteger.valueOf(m)).duplicate().getImmutable();
                    Element term2 = aP[k][m].mulZn(term1).duplicate().getImmutable();
                    right.add(term2);
                }
                if (left.isEqual(right)) {
                    validFj[k] = true;
                } else validFj[k] = false;
            } else {
                validFj[k] = true;
            }
        }
    }

    private static void computeSi(int n, Element[] fj, int i){
        s[i] = Setup.pairing.getZr().newZeroElement();
        for (int j=0;j<n;j++){
            s[i] = s[i].add(fj[i]);
        }
    }

    public static void main(String[] args){
        DisSecSharing(Setup.t, Setup.n);
        System.out.println(a);
        System.out.println(aP);
        System.out.println(f);
        System.out.println(s);
        System.out.println(S);
        for (int i=0;i<validFj.length;i++){
            System.out.println(validFj[i]);
        }
    }
}
