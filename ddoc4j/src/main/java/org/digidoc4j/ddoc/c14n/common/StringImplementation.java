package org.digidoc4j.ddoc.c14n.common;

public class StringImplementation {

    public static String Substring(String that, int start, int len)
    {
        return that.substring(start, (start + len));
    }

    public static String Replace(String that, String a, String b)
    {
        return that.replaceAll(a, b);
    }

    public static String Concat(Object[] e)
    {
        StringBuffer b;
        Object v;
        Object[] objectArray3;
        int num4;

        b = new StringBuffer();
        objectArray3 = e;

        for (num4 = 0; (num4 < (objectArray3.length)); num4++)
        {
            v = objectArray3[num4];
            b.append(v);
        }

        return b.toString();
    }

}
