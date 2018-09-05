package org.digidoc4j.ddoc;

import java.io.Serializable;

/**
 * Models an XML-DSIG/ETSI SpUri structure.
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class SpUri extends SigPolicyQualifier implements Serializable
{
    private static final long serialVersionUID = 1L;
    /** URI */
    private String m_uri;

    public SpUri(String uri)
    {
        m_uri = uri;
    }

    /**
     * Accessor for SPURI content
     * @return value of SPURI content
     */
    public String getUri()
    {
        return m_uri;
    }

    /**
     * Mutator for SPURI content
     * @param uri new value for SPURI content
     */
    public void setUri(String uri)
    {
        m_uri = uri;
    }

}
