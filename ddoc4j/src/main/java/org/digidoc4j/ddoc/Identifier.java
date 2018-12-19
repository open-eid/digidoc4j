package org.digidoc4j.ddoc;

import java.io.Serializable;
import java.util.ArrayList;

/**
 * Models an XML-DSIG/ETSI Identifier structure.
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class Identifier implements Serializable
{
    private static final long serialVersionUID = 1L;
    /** Qualifier - OIDAsURI or OIDAsURN */
    private String m_qualifier;
    /** oid / urn */
    private String m_oidOrUrn;

    public static String OIDAsURI = "OIDAsURI";
    public static String OIDAsURN = "OIDAsURN";
    public static String BDOC_210_OID = "urn:oid:1.3.6.1.4.1.10015.1000.3.2.1";

    /**
     * Identifier constructor
     * @param qualifier Qualifier value
     * @throws DigiDocException for validation errors
     */
    public Identifier(String qualifier)
            throws DigiDocException
    {
        setQualifier(qualifier);
        m_oidOrUrn = null;
    }

    /**
     * Accessor for Qualifier attribute
     * @return value of Qualifier attribute
     */
    public String getQualifier()
    {
        return m_qualifier;
    }

    /**
     * Mutator for Qualifier attribute
     * @param str new value for Qualifier attribute
     * @throws DigiDocException for validation errors
     */
    public void setQualifier(String str)
            throws DigiDocException
    {
        DigiDocException ex = validateQualifier(str);
        if(ex != null)
            throw ex;
        m_qualifier = str;
    }

    /**
     * Helper method to validate an Qualifier
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateQualifier(String str)
    {
        DigiDocException ex = null;
        if(str == null || (!str.equals(OIDAsURI) && !str.equals(OIDAsURN)))
            ex = new DigiDocException(DigiDocException.ERR_INPUT_VALUE,
                    "Qualifier is a required attribute and must be OIDAsURI or OIDAsURN", null);
        return ex;
    }

    /**
     * Accessor for Uri content
     * @return value of Uri content
     */
    public String getUri()
    {
        return m_oidOrUrn;
    }

    /**
     * Mutator for Uri content
     * @param str new value for Uri content
     */
    public void setUri(String str)
    {
        m_oidOrUrn = str;
    }

    /**
     * Helper method to validate the whole
     * Identifier object
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();
        DigiDocException ex = validateQualifier(m_qualifier);
        if(ex != null)
            errs.add(ex);
        return errs;
    }
}
