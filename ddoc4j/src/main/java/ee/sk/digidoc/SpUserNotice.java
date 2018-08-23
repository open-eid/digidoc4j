package ee.sk.digidoc;

import java.io.Serializable;
import java.util.ArrayList;

/**
 * Models an XML-DSIG/ETSI NoticeRef structure.
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class SpUserNotice extends SigPolicyQualifier implements Serializable
{
    private static final long serialVersionUID = 1L;
    /** NoticeRef (optional) */
    private NoticeRef m_noticeRef;
    /** ExplicitText (optional) */
    private String m_explicitText;

    /**
     * Default constructor for SpUserNotice
     */
    public SpUserNotice()
    {
        m_noticeRef = null;
        m_explicitText = null;
    }

    /**
     * Accessor for NoticeRef element
     * @return value of NoticeRef element
     */
    public NoticeRef getNoticeRef()
    {
        return m_noticeRef;
    }

    /**
     * Mutator for NoticeRef content
     * @param nrf new value for NoticeRef content
     */
    public void setNoticeRef(NoticeRef nrf)
    {
        m_noticeRef = nrf;
    }

    /**
     * Accessor for ExplicitText element
     * @return value of ExplicitText element
     */
    public String getExplicitText()
    {
        return m_explicitText;
    }

    /**
     * Mutator for ExplicitText content
     * @param str new value for ExplicitText content
     */
    public void setExplicitText(String str)
    {
        m_explicitText = str;
    }

    /**
     * Helper method to validate the whole
     * Identifier object
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();
        if(m_noticeRef != null)
            errs = m_noticeRef.validate();
        return errs;
    }
}
