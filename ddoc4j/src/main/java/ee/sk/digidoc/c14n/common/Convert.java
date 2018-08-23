package ee.sk.digidoc.c14n.common;

import java.util.ArrayList;

public final class Convert {


    public Convert()
    {
    }



    public static String BytesToHuman(long bytes)
    {
        String[] u;
        int x;
        long p;
        boolean z;
        String[] stringArray5;

        stringArray5 = new String[]
                {
                        "bytes",
                        "KB",
                        "MB",
                        "GB"
                };
        u = stringArray5;
        x = 0;
        p = bytes;
        z = true;
        while (z)
        {
            z = false;

            if (!(p < ((long)1024)))
            {

                if ((x < ((int)u.length)))
                {
                    p = (p / ((long)1024));
                    x++;
                    z = true;
                }

            }

        }
        return new Long(p)+ " "+ u[x];
    }

    public static String ToHexString(String e)
    {
        String z;
        char var;
        String string3;
        int num4;

        z = "";
        string3 = e;

        for (num4 = 0; (num4 < string3.length()); num4++)
        {
            var = string3.charAt(num4);
            z = z+ Convert.ToHexString(var);
        }

        return z;
    }

    public static int[] ToInt32(byte[] e)
    {
        int[] i;
        int x;

        i = new int[((int)e.length)];

        for (x = 0; (x < ((int)e.length)); x++)
        {
            i[x] = Convert.ToInt32(e[x]);
        }

        return i;
    }

    public static int ToInt32(String e)
    {
        int num0;

        try
        {
            num0 = Integer.parseInt(e);
        }
        catch (java.lang.Throwable __exc)
        {
            num0 = 0;
        }

        return num0;
    }

    public static int ToInt32(byte e)
    {
        int b;

        b = 0;

        if ((e < 0))
        {
            b = (256 + e);
        }
        else
        {
            b = e;
        }

        return (b & 255);
    }

    public static String ToHexString(long e)
    {
        return Convert.ToHexString(Convert.ToByteArray(e));
    }

    public static String ToHexString(int e, boolean LeadingZero)
    {
        String z;

        z = Integer.toHexString(e);

        if (LeadingZero)
        {

            if (((z.length() % 2) == 1))
            {
                return "0"+ z;
            }

        }

        return z;
    }

    public static String ToHexString(int e)
    {
        return Convert.ToHexString(e, true);
    }

    public static String ToHexString(long pi, int length)
    {
        String e;
        int z;

        e = Convert.ToHexString(pi);

        for (z = (length - e.length()); (z-- > 0); e = "0"+ e)
        {
        }

        return e;
    }

    public static String ToHexString(int pi, int length)
    {
        String e;
        int z;

        e = Convert.ToHexString(pi);

        for (z = (length - e.length()); (z-- > 0); e = "0"+ e)
        {
        }

        return e;
    }

    public static String ToString(char b)
    {
        char[] x;
        char[] charArray2;

        charArray2 = new char[]
                {
                        b
                };
        x = charArray2;
        return String.valueOf(x);
    }

    public static String ToString(int b)
    {
        byte[] x;
        byte[] byteArray2;

        byteArray2 = new byte[]
                {
                        ((byte)b)
                };
        x = byteArray2;
        return new String(x);
    }

    public static String ToString(byte[] bytes, String charset)
    {
        String string0;

        try
        {
            string0 = new String(bytes, charset);
        }
        catch (java.lang.Throwable __exc)
        {
            string0 = null;
        }

        return string0;
    }

    public static byte[] FromHexBytes(byte[] val)
    {
        return Convert.FromHexString(Convert.ToString(val));
    }

    public static byte[] FromHexString(String val)
    {
        byte[] s;
        int i;


        if (((val.length() % 2) == 1))
        {
            return Convert.FromHexString("0"+ val);
        }

        s = new byte[(val.length() / 2)];

        for (i = 0; (i < (val.length() - 1)); i = (i + 2))
        {
            s[(i / 2)] = ((byte)Integer.parseInt(StringImplementation.Substring(val, i, (int)2), (int)16));
        }

        return s;
    }

    public static String ToString(byte[] e)
    {
        return new String(e);
    }

    public static String ToString(byte[] e, int offset, int len)
    {
        return new String(e, offset, len);
    }

    public static String ToString(byte[] e, int offset, int len, String enc)
    {
        String u;

        u = null;
        try
        {
            u = new String(e, offset, len, enc);
        }
        catch (java.lang.Throwable __exc)
        {
        }

        return u;
    }

    public static String ToHexString(byte[] e)
    {

        if ((e == null))
        {
            return null;
        }

        return Convert.ToHexString(e, (int)0, ((int)e.length));
    }

    public static String ToHexString(byte[] e, int offset, int length)
    {
        String x;
        int i;

        x = "";

        for (i = offset; (i < (offset + length)); i++)
        {
            x = x+ Convert.ToHexString(Convert.ToInt32(e[i]));
        }

        return x;
    }

    public static byte[] ToByteArray(int[] e)
    {
        byte[] n;
        int i;

        n = new byte[((int)e.length)];

        for (i = 0; (i < ((int)e.length)); i++)
        {
            n[i] = Convert.ToByte(e[i]);
        }

        return n;
    }

    private static byte ToByte(int p)
    {
        return ((byte)p);
    }

    public static byte[] ToByteArray(long n)
    {
        byte[] b;

        b = new byte[]
                {
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        ((byte)n)
                };
        n = (n >> 8);
        b[6] = ((byte)n);
        n = (n >> 8);
        b[5] = ((byte)n);
        n = (n >> 8);
        b[4] = ((byte)n);
        n = (n >> 8);
        b[3] = ((byte)n);
        n = (n >> 8);
        b[2] = ((byte)n);
        n = (n >> 8);
        b[1] = ((byte)n);
        n = (n >> 8);
        b[0] = ((byte)n);
        return b;
    }

    public static byte[] ToByteArray(String e)
    {
        return new String(e).getBytes();
    }

    public static byte[] ToByteArray(String e, String charset)
    {
        byte[] u;

        u = null;
        try
        {
            u = new String(e).getBytes(charset);
        }
        catch (java.lang.Throwable __exc)
        {
        }

        return u;
    }

    public static byte[] ToByteArray(byte[] FileBytes, int offset, int length)
    {
        byte[] n;
        int i;

        n = new byte[length];

        for (i = 0; (i < length); i++)
        {
            n[i] = FileBytes[(offset + i)];
        }

        return n;
    }

    public static int ToInt16(byte hi, byte lo)
    {
        return Convert.ToInt16(Convert.ToInt32(hi), Convert.ToInt32(lo));
    }

    public static int ToInt16(int hi, int lo)
    {
        int x;

        x = 0;
        x = (x + (hi << 8));
        x = (x + lo);
        return x;
    }

    public static int ToInt16(long p)
    {
        return ((int)p);
    }

    public static long ToLong(String s, int radix)
    {
        long _return;

        _return = ((long)0);
        try
        {
            _return = Long.parseLong(s, radix);
        }
        catch (java.lang.Throwable __exc)
        {
            _return = ((long)0);
        }

        return _return;
    }

    public static String ReplaceString(String whom, String what, String with)
    {
        StringBuffer b;
        int i;

        b = new StringBuffer(whom);
        i = b.indexOf(what);
        while (!(i == -1))
        {
            b.replace(i, (i + what.length()), with);
            i = b.indexOf(what);
        }
        return b.toString();
    }

    public static String ReplaceWhitespaces(String subject, String e)
    {
        String x;

        x = subject;
        x = StringImplementation.Replace(x, "\t", e);
        x = StringImplementation.Replace(x, "\n", e);
        x = StringImplementation.Replace(x, "\r", e);
        x = StringImplementation.Replace(x, " ", e);
        return x;
    }

    public static String ReplaceWhitespaces(String DataString)
    {
        return Convert.ReplaceWhitespaces(DataString, "_");
    }

    /**
     * converts 1 to 4 bytes from an array to an int32
     */
    public static int ToInt32(byte[] b, int offset)
    {
        int ret;
        boolean seek;
        int i;

        ret = 0;
        seek = true;
        i = 0;
        while (seek)
        {

            if ((i == 4))
            {
                seek = false;
            }
            else
            {

                if (!((offset + i) < ((int)b.length)))
                {
                    seek = false;
                }

            }


            if (seek)
            {
                ret = (ret << 8);
                ret = (ret + Convert.ToInt32(b[(i + offset)]));
                i++;
            }

        }
        return ret;
    }

    public static String BytesToString(byte[] p, String charset)
    {
        String u;

        u = null;
        try
        {
            u = new String(p, charset);
        }
        catch (java.lang.Throwable __exc)
        {
        }

        return u;
    }

    /**
     * converts object list to int array
     */
    public static int[] ToInt32Array(ArrayList u)
    {
        int[] x;
        int i;

        x = new int[u.size()];

        for (i = 0; (i < u.size()); i++)
        {
            x[i] = ((Integer)u.get(i)).intValue();
        }

        return x;
    }

}
