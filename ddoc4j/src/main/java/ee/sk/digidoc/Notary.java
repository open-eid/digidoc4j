package ee.sk.digidoc;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;

/**
 * Models an OCSP confirmation of the
 * validity of a given signature in the
 * given context.
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class Notary implements Serializable
{
    private static final long serialVersionUID = 1L;
    /** notary id (in XML) */
    private String m_id;
    /** OCSP response data */
    private byte[] m_ocspResponseData;
    /** OCSP responder id */
    private String m_responderId;
    /** response production timestamp */
    private Date m_producedAt;
    /** certificate serial number used for this notary */
    private String m_certNr;

    /**
     * Creates new Notary and
     * initializes everything to null
     */
    public Notary() {
        m_ocspResponseData = null;
        m_id = null;
        m_responderId = null;
        m_producedAt = null;
        m_certNr = null;
    }

    /**
     * Creates new Notary and
     * @param id new Notary id
     * @param resp OCSP response data
     */
    public Notary(String id, byte[] resp, String respId, Date prodAt)
    {
        m_ocspResponseData = resp;
        m_id = id;
        m_responderId = respId;
        m_producedAt = prodAt;
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
    //throws DigiDocException
    {
        //DigiDocException ex = validateId(str);
        //if(ex != null)
        //    throw ex;
        m_id = str;
    }

    /**
     * Accessor for certNr attribute
     * @return value of certNr attribute
     */
    public String getCertNr() {
        return m_certNr;
    }

    /**
     * Mutator for certNr attribute
     * @param nr new value of certNr attribute
     */
    public void setCertNr(String nr) {
        m_certNr = nr;
    }

    /**
     * Accessor for producedAt attribute
     * @return value of producedAt attribute
     */
    public Date getProducedAt()
    {
        return m_producedAt;
    }

    /**
     * Mutator for producedAt attribute
     * @param dt new value for producedAt attribute
     */
    public void setProducedAt(Date dt)
    {
        m_producedAt = dt;
    }

    /**
     * Accessor for responderId attribute
     * @return value of responderId attribute
     */
    public String getResponderId()
    {
        return m_responderId;
    }

    /**
     * Mutator for responderId attribute
     * @param str new value for responderId attribute
     */
    public void setResponderId(String str)
    {
        m_responderId = str;
    }

    /**
     * Mutator for ocspResponseData attribute
     * @param data new value for ocspResponseData attribute
     */
    public void setOcspResponseData(byte[] data)
    {
        m_ocspResponseData = data;
    }

    /**
     * Accessor for ocspResponseData attribute
     * @return value of ocspResponseData attribute
     */
    public byte[] getOcspResponseData()
    {
        return m_ocspResponseData;
    }

    /**
     * Helper method to validate the whole
     * SignedProperties object
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();

        return errs;
    }

}
