package org.digidoc4j.ddoc.c14n.common;

public final class Helper {

    public static boolean IsVisibleChar(int p)
    {
        boolean bA;
        boolean aZ;
        boolean lA;
        boolean buA;
        boolean auZ;
        boolean uA;
        boolean b0;
        boolean a9;
        boolean uN;
        boolean x;
        boolean isAlpha;

        bA = !(p < 97);
        aZ = !(p > 122);
        lA = (bA && aZ);
        buA = !(p < 65);
        auZ = !(p > 90);
        uA = (buA && auZ);
        b0 = !(p < 48);
        a9 = !(p > 57);
        uN = (b0 && a9);
        x = ("\'\"=[]()<>+-;:.?\u0040/".indexOf(((char)p)) > -1);
        isAlpha = (lA || (uA || (uN || x)));
        return isAlpha;
    }

}
