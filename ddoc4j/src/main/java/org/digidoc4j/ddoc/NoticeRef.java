package org.digidoc4j.ddoc;

import java.io.Serializable;
import java.util.ArrayList;

/**
 * Models an XML-DSIG/ETSI NoticeRef structure.
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class NoticeRef implements Serializable
{
    private static final long serialVersionUID = 1L;
    /** Organization - xsd:string, (mandatory) */
    private String m_organization;
    /** NoticeNumbers - list of int-s (optional) */
    private ArrayList m_noticeNumbers;

    /**
     * Constructor for NoticeRef
     * @param org Organization
     */
    public NoticeRef(String org)
    {
        m_organization = org;
        m_noticeNumbers = null;
    }

    /**
     * Accessor for Organization attribute
     * @return value of Organization attribute
     */
    public String getOrganization()
    {
        return m_organization;
    }

    /**
     * Mutator for Organization attribute
     * @param str new value for Organization attribute
     * @throws DigiDocException for validation errors
     */
    public void setOrganization(String str)
            throws DigiDocException
    {
        DigiDocException ex = validateOrganization(str);
        if(ex != null)
            throw ex;
        m_organization = str;
    }

    /**
     * Helper method to validate an Organization
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateOrganization(String str)
    {
        DigiDocException ex = null;
        if(str == null)
            ex = new DigiDocException(DigiDocException.ERR_INPUT_VALUE,
                    "Organization is a required attribute", null);
        return ex;
    }

    /**
     * return the count of NoticeNumbers
     * @return count of NoticeNumbers
     */
    public int countNoticeNumbers()
    {
        return ((m_noticeNumbers == null) ? 0 : m_noticeNumbers.size());
    }

    /**
     * Adds a new NoticeNumber
     * @param n new NoticeNumber to be added
     */
    public void addNoticeNumber(int n)
    {
        if(m_noticeNumbers == null)
            m_noticeNumbers = new ArrayList();
        m_noticeNumbers.add(new Integer(n));
    }

    /**
     * Retrieves NoticeNumber with the desired index
     * @param idx NoticeNumber index
     * @return NoticeNumber or null if not found
     */
    public int getNoticeNumber(int idx)
    {
        if(m_noticeNumbers != null && idx < m_noticeNumbers.size()) {
            return ((Integer)m_noticeNumbers.get(idx)).intValue();
        }
        return 0; // not found
    }

    /**
     * Helper method to validate the whole
     * Identifier object
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();
        DigiDocException ex = validateOrganization(m_organization);
        if(ex != null)
            errs.add(ex);
        return errs;
    }
}
