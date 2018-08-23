package ee.sk.digidoc.c14n.common;

public class StringImplementation {



    public static String PadLeft(String that, int totalWidth, char paddingChar)
    {
        String u;
        String p;

        u = ((String)that);

        for (p = Convert.ToString(paddingChar); (u.length() < totalWidth); u = p+ u)
        {
        }

        return u;
    }

    public static String Substring(String that, int start, int len)
    {
        String s;

        s = ((String)that);
        return s.substring(start, (start + len));
    }

    public static String Replace(String that, String a, String b)
    {
        //return Convert.ReplaceString(((String)that), a, b);
        return that.replaceAll(a, b);
    }

    public static boolean op_Inequality(String a, String b)
    {
        return !a.equals(b);
    }

    public static String Concat(Object[] e)
    {
        StringBuffer b;
        Object v;
        Object[] objectArray3;
        int num4;

        b = new StringBuffer();
        objectArray3 = e;

        for (num4 = 0; (num4 < ((int)objectArray3.length)); num4++)
        {
            v = objectArray3[num4];
            b.append(v);
        }

        return b.toString();
    }

}
