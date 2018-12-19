package org.digidoc4j.ddoc.c14n.common;

public final class Convert {


    public Convert()
    {
    }

    public static int ToInt32(String e)
    {
        int num0;

        try
        {
            num0 = Integer.parseInt(e);
        }
        catch (Throwable ex)
        {
            num0 = 0;
        }

        return num0;
    }

    public static int ToInt32(byte e)
    {
        int b;

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

    public static String ToString(char b) {
        char[] x;
        char[] charArray2;

        charArray2 = new char[]
                {
                        b
                };
        x = charArray2;
        return String.valueOf(x);
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
            s[(i / 2)] = ((byte)Integer.parseInt(StringImplementation.Substring(val, i, 2), 16));
        }

        return s;
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

    public static byte[] ToByteArray(String e, String charset)
    {
        byte[] u;

        u = null;
        try
        {
            u = new String(e).getBytes(charset);
        }
        catch (Throwable ex)
        {
        }

        return u;
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

                if (!((offset + i) < (b.length)))
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

}
