package org.digidoc4j.ddoc.factory;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Special input stream used to filter out BOM
 * (byte-order-marks) from the beginning of xml signature
 * or signed doc xml file.
 * @author Veiko Sinivee
 */
public class SignatureInputStream
        extends FilterInputStream
{
    boolean bXml;

    /**
     * Constructor for SignatureInputStream
     * @param in real input stream to be filtered
     */
    public SignatureInputStream(InputStream in)
    {
        super(in);
        bXml = false;
    }

    public int read() throws IOException
    {
        int b = super.read();
        if(!bXml) {
            while(b != '<' && b != -1)
                b = super.read();
            bXml = true;
        }
        return b;
    }
}
