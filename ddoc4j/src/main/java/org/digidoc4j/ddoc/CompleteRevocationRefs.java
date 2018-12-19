package org.digidoc4j.ddoc;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Vector;

/**
 * Models the ETSI CompleteRevocationRefs element
 * This contains some data from the OCSP response
 * and it's digest
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class CompleteRevocationRefs implements Serializable
{
    private static final long serialVersionUID = 1L;

    /** vector of ocsp refs */
    private Vector m_ocspRefs;
    /** parent object - UnsignedProperties ref */
    private UnsignedProperties m_unsignedProps;

    /**
     * Creates new CompleteRevocationRefs
     * Initializes everything to null
     */
    public CompleteRevocationRefs() {
        m_ocspRefs = null;
        m_unsignedProps = null;
    }


    /**
     * Accessor for UnsignedProperties attribute
     * @return value of UnsignedProperties attribute
     */
    public UnsignedProperties getUnsignedProperties()
    {
        return m_unsignedProps;
    }

    /**
     * Mutator for UnsignedProperties attribute
     * @param uprops value of UnsignedProperties attribute
     */
    public void setUnsignedProperties(UnsignedProperties uprops)
    {
        m_unsignedProps = uprops;
    }


    /**
     * Get the n-th OcspRef object
     * @param nIdx OcspRef index
     * @return OcspRef object
     */
    public OcspRef getOcspRefById(int nIdx)
    {
        if(m_ocspRefs != null && nIdx < m_ocspRefs.size())
            return (OcspRef)m_ocspRefs.elementAt(nIdx);
        else
            return null;
    }

    /**
     * Get OcspRef object by uri
     * @param uri OcspRef uri
     * @return OcspRef object
     */
    public OcspRef getOcspRefByUri(String uri)
    {
        for(int i = 0; (m_ocspRefs != null) && (i < m_ocspRefs.size()); i++) {
            OcspRef orf = (OcspRef)m_ocspRefs.elementAt(i);
            if(orf.getUri().equals(uri))
                return orf;
        }
        return null;
    }

    /**
     * Get the last OcspRef object
     * @return OcspRef object
     */
    public OcspRef getLastOcspRef()
    {
        if(m_ocspRefs != null && m_ocspRefs.size() > 0)
            return (OcspRef)m_ocspRefs.elementAt(m_ocspRefs.size()-1);
        else
            return null;
    }

    /**
     * Add a new OcspRef
     * @param orf OcspRef object
     */
    public void addOcspRef(OcspRef orf)
    {
        if(m_ocspRefs == null)
            m_ocspRefs = new Vector();
        m_ocspRefs.add(orf);
    }

    /**
     * Count the number of OcspRef objects
     * @return number of OcspRef objects
     */
    public int countOcspRefs() { return (m_ocspRefs != null) ? m_ocspRefs.size() : 0; }

    /**
     * Helper method to validate the whole
     * CompleteRevocationRefs object
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();
        for(int i = 0; (m_ocspRefs != null) && (i < m_ocspRefs.size()); i++) {
            OcspRef orf = (OcspRef)m_ocspRefs.elementAt(i);
            ArrayList errs2 = orf.validate();
            if(errs2 != null && errs2.size() > 0)
                errs.addAll(errs2);
        }
        return errs;
    }



}
