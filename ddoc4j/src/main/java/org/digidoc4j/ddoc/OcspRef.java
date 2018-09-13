package org.digidoc4j.ddoc;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;

/**
 * Models the ETSI OCSPRef element
 * This contains some data from the OCSP response
 * and it's digest
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class OcspRef implements Serializable
{
    private static final long serialVersionUID = 1L;
    /** <OCSPIdentifier> URI attribute */
    private String m_uri;
    /** <ResponderId> element */
    private String m_responderId;
    /** ProducedAt element */
    private Date m_producedAt;
    /** digest algorithm uri/id */
    private String m_digestAlgorithm;
    /** digest value */
    private byte[] m_digestValue;

    /**
     * Creates new OcspRef
     * Initializes everything to null
     */
    public OcspRef() {
        m_uri = null;
        m_responderId = null;
        m_producedAt = null;
        m_digestAlgorithm = null;
        m_digestValue = null;
    }

    /**
     * Creates new OcspRef
     * @param uri notary uri value
     * @param respId responder id
     * @param producedAt OCSP producedAt timestamp
     * @param digAlg notary digest algorithm
     * @param digest notary digest
     * @throws DigiDocException for validation errors
     */
    public OcspRef(String uri, String respId,
                   Date producedAt, String digAlg, byte[] digest)
            throws DigiDocException
    {
        setUri(uri);
        setResponderId(respId);
        setProducedAt(producedAt);
        setDigestAlgorithm(digAlg);
        setDigestValue(digest);
    }


    /**
     * Accessor for uri attribute
     * @return value of uri attribute
     */
    public String getUri() {
        return m_uri;
    }

    /**
     * Mutator for uri attribute
     * @param str new value for uri attribute
     * @throws DigiDocException for validation errors
     */
    public void setUri(String str)
            throws DigiDocException
    {
        DigiDocException ex = validateUri(str);
        if(ex != null)
            throw ex;
        m_uri = str;
    }

    /**
     * Helper method to validate an uri
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateUri(String str)
    {
        DigiDocException ex = null;
        if(str == null)
            ex = new DigiDocException(DigiDocException.ERR_REVREFS_URI,
                    "OCSP ref uri must be in form: #<ref-id>", null);
        return ex;
    }

    /**
     * Accessor for responderId attribute
     * @return value of responderId attribute
     */
    public String getResponderId() {
        return m_responderId;
    }

    /**
     * Mutator for responderId attribute
     * @param str new value for responderId attribute
     * @throws DigiDocException for validation errors
     */
    public void setResponderId(String str)
            throws DigiDocException
    {
        DigiDocException ex = validateResponderId(str);
        if(ex != null)
            throw ex;
        m_responderId = str;
    }

    /**
     * Returns reponder-ids CN
     * @returns reponder-ids CN or null
     */
    public String getResponderCommonName() {
        String name = null;
        if(m_responderId != null) {
            int idx1 = m_responderId.indexOf("CN=");
            if(idx1 != -1) {
                idx1 += 2;
                while(idx1 < m_responderId.length() &&
                        !Character.isLetter(m_responderId.charAt(idx1)))
                    idx1++;
                int idx2 = idx1;
                while(idx2 < m_responderId.length() &&
                        m_responderId.charAt(idx2) != ',' &&
                        m_responderId.charAt(idx2) != '/')
                    idx2++;
                name = m_responderId.substring(idx1, idx2);
            }
        }
        return name;
    }

    /**
     * Helper method to validate a ResponderId
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateResponderId(String str)
    {
        DigiDocException ex = null;
        if(str == null)
            ex = new DigiDocException(DigiDocException.ERR_REVREFS_RESP_ID,
                    "ResponderId cannot be empty!", null);
        return ex;
    }

    /**
     * Accessor for producedAt attribute
     * @return value of producedAt attribute
     */
    public Date getProducedAt() {
        return m_producedAt;
    }

    /**
     * Mutator for producedAt attribute
     * @param str new value for producedAt attribute
     * @throws DigiDocException for validation errors
     */
    public void setProducedAt(Date d)
            throws DigiDocException
    {
        DigiDocException ex = validateProducedAt(d);
        if(ex != null)
            throw ex;
        m_producedAt = d;
    }

    /**
     * Helper method to validate producedAt timestamp
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateProducedAt(Date d)
    {
        DigiDocException ex = null;
        if(d == null)
            ex = new DigiDocException(DigiDocException.ERR_REVREFS_PRODUCED_AT,
                    "ProducedAt timestamp cannot be empty!", null);
        return ex;
    }

    /**
     * Accessor for digestAlgorithm attribute
     * @return value of digestAlgorithm attribute
     */
    public String getDigestAlgorithm() {
        return m_digestAlgorithm;
    }

    /**
     * Mutator for digestAlgorithm attribute
     * @param str new value for digestAlgorithm attribute
     * @throws DigiDocException for validation errors
     */
    public void setDigestAlgorithm(String str)
            throws DigiDocException
    {
        DigiDocException ex = validateDigestAlgorithm(str);
        if(ex != null)
            throw ex;
        m_digestAlgorithm = str;
    }

    /**
     * Helper method to validate a digest algorithm
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateDigestAlgorithm(String str)
    {
        DigiDocException ex = null;
        if(str == null ||
                !str.equals(SignedDoc.SHA1_DIGEST_ALGORITHM))
            ex = new DigiDocException(DigiDocException.ERR_DIGEST_ALGORITHM,
                    "Currently supports only SHA1", null);
        return ex;
    }

    /**
     * Accessor for digestValue attribute
     * @return value of digestValue attribute
     */
    public byte[] getDigestValue() {
        return m_digestValue;
    }


    /**
     * Mutator for digestValue attribute
     * @param data new value for digestValue attribute
     * @throws DigiDocException for validation errors
     */
    public void setDigestValue(byte[] data)
            throws DigiDocException
    {
        DigiDocException ex = validateDigestValue(data);
        if(ex != null)
            throw ex;
        m_digestValue = data;
    }


    /**
     * Helper method to validate a digest value
     * @param data input data
     * @return exception or null for ok
     */
    private DigiDocException validateDigestValue(byte[] data)
    {
        DigiDocException ex = null;
        if(data == null ||
                data.length != SignedDoc.SHA1_DIGEST_LENGTH)
            ex = new DigiDocException(DigiDocException.ERR_DIGEST_LENGTH,
                    "Invalid digest length", null);
        return ex;
    }

    /**
     * Helper method to validate the whole
     * CompleteRevocationRefs object
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();
        DigiDocException ex = validateUri(m_uri);
        if(ex != null)
            errs.add(ex);
        ex = validateResponderId(m_responderId);
        if(ex != null)
            errs.add(ex);
        ex = validateProducedAt(m_producedAt);
        if(ex != null)
            errs.add(ex);
        ex = validateDigestAlgorithm(m_digestAlgorithm);
        if(ex != null)
            errs.add(ex);
        ex = validateDigestValue(m_digestValue);
        if(ex != null)
            errs.add(ex);
        return errs;
    }


}
