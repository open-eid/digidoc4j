package org.digidoc4j.ddoc;

import java.io.Serializable;
import java.util.ArrayList;

/**
 * Models an XML-DSIG/ETSI DataObjectFormat structure.
 * This structure is used to hold the mime type of a
 * signed data object.
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class DataObjectFormat implements Serializable
{
    private static final long serialVersionUID = 1L;
    /** ObjectReference - xsd:anyURI (mandatory) */
    private String m_objectReference;
    /** Description - xsd:string (optional) */
    private String m_description;
    /** ObjectIdentifier - ObjectIdentifierType (optional) */
    private ObjectIdentifier m_objectIdentifier;
    /** MimeType - xsd:string (optional) */
    private String m_mimeType;
    /** Encoding - xsd:anyURI (optional) */
    private String m_encoding;

    /**
     * DataObjectFormat constructor
     * @param objRef ObjectReference value
     * @throws DigiDocException for validation errors
     */
    public DataObjectFormat(String objRef)
            throws DigiDocException
    {
        setObjectReference(objRef);
        m_description = null;
        m_mimeType = null;
        m_encoding = null;
        m_objectIdentifier = null;
    }

    /**
     * Accessor for ObjectReference attribute
     * @return value of ObjectReference attribute
     */
    public String getObjectReference()
    {
        return m_objectReference;
    }

    /**
     * Mutator for ObjectReference attribute
     * @param str new value for ObjectReference attribute
     * @throws DigiDocException for validation errors
     */
    public void setObjectReference(String str)
            throws DigiDocException
    {
        DigiDocException ex = validateObjectReference(str);
        if(ex != null)
            throw ex;
        m_objectReference = str;
    }

    /**
     * Helper method to validate an ObjectReference
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateObjectReference(String str)
    {
        DigiDocException ex = null;
        if(str == null || str.trim().length() == 0)
            ex = new DigiDocException(DigiDocException.ERR_INPUT_VALUE,
                    "ObjectReference is a required attribute", null);
        return ex;
    }

    /**
     * Accessor for Description attribute
     * @return value of Description attribute
     */
    public String getDescription()
    {
        return m_description;
    }

    /**
     * Mutator for Description attribute
     * @param str new value for Description attribute
     */
    public void setDescription(String str)
    {
        m_description = str;
    }

    /**
     * Accessor for MimeType attribute
     * @return value of MimeType attribute
     */
    public String getMimeType()
    {
        return m_mimeType;
    }

    /**
     * Mutator for MimeType attribute
     * @param str new value for MimeType attribute
     */
    public void setMimeType(String str)
    {
        m_mimeType = str;
    }

    /**
     * Accessor for Encoding attribute
     * @return value of Encoding attribute
     */
    public String getEncoding()
    {
        return m_encoding;
    }

    /**
     * Mutator for Encoding attribute
     * @param str new value for Encoding attribute
     */
    public void setEncoding(String str)
    {
        m_encoding = str;
    }

    /**
     * Accessor for ObjectIdentifier element
     * @return value of ObjectIdentifier element
     */
    public ObjectIdentifier getObjectIdentifier()
    {
        return m_objectIdentifier;
    }

    /**
     * Mutator for ObjectIdentifier element
     * @param oid new value for ObjectIdentifier element
     */
    public void setObjectIdentifier(ObjectIdentifier oid)
    {
        m_objectIdentifier = oid;
    }


    /**
     * Helper method to validate the whole
     * DataObjectFormat object
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();
        DigiDocException ex = validateObjectReference(m_objectReference);
        if(ex != null)
            errs.add(ex);
        if(m_objectIdentifier != null) {
            ArrayList e = m_objectIdentifier.validate();
            if(e != null && e.size() > 0)
                errs.addAll(e);
        }
        return errs;
    }

}
