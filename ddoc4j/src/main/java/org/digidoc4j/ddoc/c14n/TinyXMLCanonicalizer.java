package org.digidoc4j.ddoc.c14n;

import org.digidoc4j.ddoc.DigiDocException;
import org.digidoc4j.ddoc.factory.CanonicalizationFactory;

import java.io.ByteArrayOutputStream;
import java.io.RandomAccessFile;

public class TinyXMLCanonicalizer implements CanonicalizationFactory {


    public TinyXMLCanonicalizer()
    {
    }


    public void init() throws DigiDocException
    {
        try
        {
        }
        catch (java.lang.Throwable exc)
        {
            throw new DigiDocException((int)0, "unknown", exc);
        }

    }

    public byte[] canonicalize(String filename, String uri) throws DigiDocException
    {
        RandomAccessFile f = null;
        byte[] data;
        byte[] byteArray3;
        int n;
        try
        {
            f = new RandomAccessFile(filename, "r");
            data = new byte[((int)f.length())];
            n = f.read(data);
            if(n <= 0) return null;
            byteArray3 = this.canonicalize(data, uri);
        }
        catch (java.lang.Throwable exc)
        {
            throw new DigiDocException((int)0, "unknown", exc);
        } finally {
            try {
                if(f != null) f.close();
            } catch(Exception ex) {}
        }
        return byteArray3;
    }

    /**
     * will parse the xml document and return its canonicalized version
     */
    public byte[] canonicalize(byte[] data, String uri) throws DigiDocException
    {
        TinyXMLParser p;
        TinyXMLCanonicalizerHandler h;
        byte[] byteArray3;

        try
        {
            p = new TinyXMLParser();
            h = new TinyXMLCanonicalizerHandler();
            p.Parse(h, TinyXMLCanonicalizer.NormalizeLineBreaks(data));
            byteArray3 = h.get_Bytes();
        }
        catch (java.lang.Throwable exc)
        {
            throw new DigiDocException((int)0, "unknown", exc);
        }

        return byteArray3;
    }

    public static byte[] NormalizeLineBreaks(byte[] data)
    {
        int len;
        ByteArrayOutputStream o;
        byte[] n;
        int i;
        byte c;
        boolean skip;

        len = ((int)data.length);
        o = new ByteArrayOutputStream(len);
        n = new byte[]
                {
                        10
                };

        for (i = 0; (i < len); i++)
        {
            c = data[i];

            if ((c == 13))
            {
                skip = false;

                if (((i + 1) < len))
                {
                    c = data[(i + 1)];

                    if ((c == 10))
                    {
                        skip = true;
                    }

                }


                if (!skip)
                {
                    o.write(n, (int)0, (int)1);
                }

            }
            else
            {
                o.write(data, i, (int)1);
            }

        }

        return o.toByteArray();
    }

}
