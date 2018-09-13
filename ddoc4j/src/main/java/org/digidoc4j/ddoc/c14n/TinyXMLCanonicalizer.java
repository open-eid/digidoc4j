package org.digidoc4j.ddoc.c14n;

import org.digidoc4j.ddoc.DigiDocException;
import org.digidoc4j.ddoc.factory.CanonicalizationFactory;

import java.io.ByteArrayOutputStream;

public class TinyXMLCanonicalizer implements CanonicalizationFactory {


    public TinyXMLCanonicalizer()
    {
    }

    public void init()
    {
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
        catch (Throwable exc)
        {
            throw new DigiDocException(0, "unknown", exc);
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

        len = (data.length);
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
                    o.write(n, 0, 1);
                }

            }
            else
            {
                o.write(data, i, 1);
            }
        }
        return o.toByteArray();
    }

}
