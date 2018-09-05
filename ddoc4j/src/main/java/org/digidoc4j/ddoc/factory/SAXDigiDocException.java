package org.digidoc4j.ddoc.factory;

import org.digidoc4j.ddoc.DigiDocException;
import org.xml.sax.SAXException;

import java.io.IOException;

/**
 * SAXExcepton subclass, that
 * has the same data as DigiDocException
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class SAXDigiDocException extends SAXException
{
    private int m_code;
    private Throwable m_detail;

    /** Creates new SAXDigiDocException */
    public SAXDigiDocException(int code, String msg)
    {
        super(msg);
        m_code = code;
        m_detail = null;
    }

    /** Creates new SAXDigiDocException */
    public SAXDigiDocException(String msg)
    {
        super(msg);
        m_detail = null;
    }

    /**
     * Accessor for error code
     * @return error code
     */
    public int getCode() {
        return m_code;
    }

    /**
     * Accessor for nested exception
     * @return nested exception
     */
    public Throwable getNestedException() {
        return m_detail;
    }

    /**
     * Mutator for nested exception
     * @param detail nested exception
     */
    public void setNestedException(Throwable t) {
        m_detail = t;
    }

    /**
     * Factory method to handle excetions
     * @param ex Exception object to use
     * @param code error code
     */
    public static void handleException(DigiDocException ex)
            throws SAXDigiDocException
    {
        SAXDigiDocException ex1 =
                new SAXDigiDocException(ex.getCode(), ex.getMessage());
        if(ex.getNestedException() != null)
            ex1.setNestedException(ex.getNestedException());
        throw ex1;
    }

    /**
     * Factory method to handle excetions
     * @param ex Exception object to use
     * @param code error code
     */
    public static void handleException(IOException ex)
            throws SAXDigiDocException
    {
        SAXDigiDocException ex1 =
                new SAXDigiDocException(DigiDocException.ERR_WRITE_FILE, ex.getMessage());
        ex1.setNestedException(ex);
        throw ex1;
    }

    /**
     * Converts this exception to an equivalent
     * DigiDocException
     * @return DigiDocException
     */
    public DigiDocException getDigiDocException()
    {
        return new DigiDocException(m_code, getMessage(), m_detail);
    }
}
