package ee.sk.digidoc;

import java.io.Serializable;
import java.util.ArrayList;

/**
 * Models an XML-DSIG/ETSI ObjectIdentifier structure.
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class ObjectIdentifier implements Serializable
{
    private static final long serialVersionUID = 1L;
    /** Identifier element (mandatory) */
    private Identifier m_identifier;
    /** Description element (optional) */
    private String m_description;
    /** DocumentationReferences (optional) */
    private ArrayList m_docRefs;

    /**
     * Constructor for ObjectIdentifier
     * @param id Identifier object
     * @throws DigiDocException for validation errors
     */
    public ObjectIdentifier(Identifier id)
            throws DigiDocException
    {
        setIdentifier(id);
        m_description = null;
        m_docRefs = null;
    }

    /**
     * Accessor for Identifier attribute
     * @return value of Identifier attribute
     */
    public Identifier getIdentifier()
    {
        return m_identifier;
    }

    /**
     * Mutator for Identifier attribute
     * @param id new value for Identifier attribute
     * @throws DigiDocException for validation errors
     */
    public void setIdentifier(Identifier id)
            throws DigiDocException
    {
        DigiDocException ex = validateIdentifier(id);
        if(ex != null)
            throw ex;
        m_identifier = id;
    }

    /**
     * Helper method to validate an Identifier
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateIdentifier(Identifier id)
    {
        DigiDocException ex = null;
        if(id == null)
            ex = new DigiDocException(DigiDocException.ERR_INPUT_VALUE,
                    "Identifier is a required attribute", null);
        return ex;
    }

    /**
     * Accessor for Description content
     * @return value of Description content
     */
    public String getDescription()
    {
        return m_description;
    }

    /**
     * Mutator for Description content
     * @param str new value for Description content
     */
    public void setUri(String str)
    {
        m_description = str;
    }

    /**
     * return the count of DocumentationReference objects
     * @return count of DocumentationReference objects
     */
    public int countDocumentationReferences()
    {
        return ((m_docRefs == null) ? 0 : m_docRefs.size());
    }

    /**
     * Adds a new DocumentationReference object
     * @param dof new object to be added
     */
    public void addDataObjectFormat(String dor)
    {
        if(m_docRefs == null)
            m_docRefs = new ArrayList();
        m_docRefs.add(dor);
    }

    /**
     * Retrieves DocumentationReference element with the desired index
     * @param idx DocumentationReference index
     * @return DocumentationReference element or null if not found
     */
    public String getDocumentationReference(int idx)
    {
        if(m_docRefs != null && idx < m_docRefs.size()) {
            return (String)m_docRefs.get(idx);
        }
        return null; // not found
    }

    /**
     * Helper method to validate the whole
     * Identifier object
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();
        DigiDocException ex = validateIdentifier(m_identifier);
        if(ex != null)
            errs.add(ex);
        return errs;
    }
}
