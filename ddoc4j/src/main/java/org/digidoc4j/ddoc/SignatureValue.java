package org.digidoc4j.ddoc;

import java.io.Serializable;
import java.util.ArrayList;

/**
 * Models the SignatureValue element of
 * XML-DSIG
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class SignatureValue implements Serializable
{
    private static final long serialVersionUID = 1L;
    /** signature value id */
    private String m_id;
    /** actual signature value data */
    private byte[] m_value;
    private Signature m_sig;

    /** RSA signatures have 128 bytes */
    public static final int SIGNATURE_VALUE_LENGTH = 128;


    /**
     * Creates new SignatureValue
     */
    public SignatureValue() {
        m_id = null;
        m_value = null;
    }

    /**
     * Creates new SignatureValue
     * @param id SignatureValue id
     * @param value actual RSA signature value
     * @throws DigiDocException for validation errors
     */
    public SignatureValue(String id, byte[] value, boolean isEC)
            throws DigiDocException
    {
        setId(id);
        setValue(value, isEC);
    }

    /**
     * Creates new SignatureValue
     * @param id SignatureValue id
     * @param value actual RSA signature value
     * @throws DigiDocException for validation errors
     */
    public SignatureValue(Signature sig, byte[] value)
            throws DigiDocException
    {
        setId(sig.getId() + "-SIG");
        m_sig = sig;
        setValue(value, sig.isEllipticCurveSiganture());
    }

    /**
     * Creates new SignatureValue
     * @param id SignatureValue id
     * @throws DigiDocException for validation errors
     */
    public SignatureValue(Signature sig, String id)
            throws DigiDocException
    {
        m_sig = sig;
        if(id != null)
            setId(id);
        else
            setId(sig.getId() + "-SIG");
        sig.setSignatureValue(this);
    }

    /**
     * Accessor for id attribute
     * @return value of id attribute
     */
    public String getId() {
        return m_id;
    }

    /**
     * Mutator for id attribute
     * @param str new value for id attribute
     * @throws DigiDocException for validation errors
     */
    public void setId(String str)
            throws DigiDocException
    {
        DigiDocException ex = validateId(str);
        if(ex != null)
            throw ex;
        m_id = str;
    }

    /**
     * Helper method to validate an id
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateId(String str)
    {
        DigiDocException ex = null;
        if(str == null)
            ex = new DigiDocException(DigiDocException.ERR_SIGNATURE_VALUE_ID,
                    "Id is a required attribute", null);
        return ex;
    }

    /**
     * Accessor for value attribute
     * @return value of value attribute
     */
    public byte[] getValue() {
        return m_value;
    }

    /**
     * Mutator for value attribute
     * @param str new value for value attribute
     * @throws DigiDocException for validation errors
     */
    public void setValue(byte[] data, boolean isEC)
            throws DigiDocException
    {
        DigiDocException ex = validateValue(data, isEC);
        if(ex != null)
            throw ex;
        m_value = data;
    }

    /**
     * Helper method to validate a signature value
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateValue(byte[] value, boolean isEC)
    {
        DigiDocException ex = null;
        if(value == null || (value.length < SIGNATURE_VALUE_LENGTH && !isEC))
            ex = new DigiDocException(DigiDocException.ERR_SIGNATURE_VALUE_ID,
                    "RSA signature value must be at least 128 bytes", null);
        return ex;
    }

    /**
     * Helper method to validate the whole
     * SignatureValue object
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();
        // VS: 2.3.24 - fix to allowe SignatureValue without Id atribute
        DigiDocException ex = validateValue(m_value, (m_sig != null) ? m_sig.isEllipticCurveSiganture() : false);
        if(ex != null)
            errs.add(ex);
        return errs;
    }


}
