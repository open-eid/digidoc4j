package org.digidoc4j.ddoc;

import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;

/**
 * Models the ETSI timestamp element(s)
 * Holds timestamp info and TS_RESP response.
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class TimestampInfo implements Serializable {
    private static final long serialVersionUID = 1L;
    /** elements Id atribute */
    private String m_id;
    /** parent object - Signature ref */
    private Signature m_signature;
    /** timestamp type */
    private int m_type;
    /** Include sublements */
    private ArrayList m_includes;
    /** timestamp token */
    private transient TimeStampResponse m_tresp;
    private transient TimeStampToken m_tsTok;
    private transient TimeStampTokenInfo m_tsTinfo;
    /** real hash calculated over the corresponding xml block */
    private byte[] m_hash;

    /** possible values for type atribute */
    public static final int TIMESTAMP_TYPE_UNKNOWN = 0;
    public static final int TIMESTAMP_TYPE_ALL_DATA_OBJECTS = 1;
    public static final int TIMESTAMP_TYPE_INDIVIDUAL_DATA_OBJECTS = 2;
    public static final int TIMESTAMP_TYPE_SIGNATURE = 3;
    public static final int TIMESTAMP_TYPE_SIG_AND_REFS = 4;
    public static final int TIMESTAMP_TYPE_REFS_ONLY = 5;
    public static final int TIMESTAMP_TYPE_ARCHIVE = 6;
    public static final int TIMESTAMP_TYPE_XADES = 7;

    /**
     * Creates new TimestampInfo
     * and initializes everything to null
     */
    public TimestampInfo() {
        m_id = null;
        m_signature = null;
        m_includes = null;
        m_hash = null;
        m_type = TIMESTAMP_TYPE_UNKNOWN;
        m_tsTok = null;
    }

    public TimestampInfo(String id, Signature sig, int type, byte[] hash, TimeStampToken tok) {
        m_id = id;
        m_signature = sig;
        m_includes = null;
        m_hash = hash;
        m_type = type;
        m_tsTok = tok;
    }

    public TimestampInfo(String id, Signature sig, int type, byte[] hash, TimeStampResponse tresp) {
        m_id = id;
        m_signature = sig;
        m_includes = null;
        m_hash = hash;
        m_type = type;
        m_tresp = tresp;
        m_tsTok = tresp.getTimeStampToken();
        m_tsTinfo = tresp.getTimeStampToken().getTimeStampInfo();
    }

    /**
     * Accessor for Signature attribute
     * @return value of Signature attribute
     */
    public Signature getSignature()
    {
        return m_signature;
    }

    public TimeStampResponse getTimeStampResponse() { return m_tresp; }
    public void setTimeStampResponse(TimeStampResponse rsp) { m_tresp = rsp; }

    /**
     * Mutator for Signature attribute
     * @param uprops value of Signature attribute
     */
    public void setSignature(Signature sig)
    {
        m_signature = sig;
    }

    /**
     * Creates new TimestampInfo
     * @param id Id atribute value
     * @param type timestamp type
     * @throws DigiDocException for validation errors
     */
    public TimestampInfo(String id, int type)
            throws DigiDocException
    {
        setId(id);
        setType(type);
        m_includes = null;
    }

    /**
     * Accessor for Hash attribute
     * @return value of Hash attribute
     */
    public byte[] getHash() {
        return m_hash;
    }

    /**
     * Mutator for Hash attribute
     * @param str new value for Hash attribute
     */
    public void setHash(byte[] b)
    {
        m_hash = b;
    }

    /**
     * Accessor for Id attribute
     * @return value of Id attribute
     */
    public String getId() {
        return m_id;
    }

    /**
     * Mutator for Id attribute
     * @param str new value for Id attribute
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
     * Helper method to validate Id
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateId(String str)
    {
        DigiDocException ex = null;
        if(str == null)
            ex = new DigiDocException(DigiDocException.ERR_TIMESTAMP_ID,
                    "Id atribute cannot be empty", null);
        return ex;
    }

    /**
     * Accessor for Type attribute
     * @return value of Type attribute
     */
    public int getType() {
        return m_type;
    }

    /**
     * Mutator for Type attribute
     * @param n new value for Type attribute
     * @throws DigiDocException for validation errors
     */
    public void setType(int n)
            throws DigiDocException
    {
        DigiDocException ex = validateType(n);
        if(ex != null)
            throw ex;
        m_type = n;
    }

    /**
     * Helper method to validate Type
     * @param n input data
     * @return exception or null for ok
     */
    private DigiDocException validateType(int n)
    {
        DigiDocException ex = null;
        if(n < TIMESTAMP_TYPE_ALL_DATA_OBJECTS || n > TIMESTAMP_TYPE_XADES)
            ex = new DigiDocException(DigiDocException.ERR_TIMESTAMP_TYPE,
                    "Invalid timestamp type", null);
        return ex;
    }

    /**
     * Accessor for TimeStampToken attribute
     * @return value of TimeStampToken attribute
     */
    public TimeStampToken getTimeStampToken() {
        return m_tsTok;
    }

    /**
     * Mutator for TimeStampToken TimeStampToken
     * @param tst new value for TimeStampResponse attribute
     * @throws DigiDocException for validation errors
     */
    public void setTimeStampToken(TimeStampToken tst)
            throws DigiDocException
    {
        DigiDocException ex = validateTimeStampToken(tst);
        if(ex != null)
            throw ex;
        m_tsTok = tst;
    }

    /**
     * Helper method to validate TimeStampToken
     * @param tst input data
     * @return exception or null for ok
     */
    private DigiDocException validateTimeStampToken(TimeStampToken tst)
    {
        DigiDocException ex = null;
        if(tst == null)
            ex = new DigiDocException(DigiDocException.ERR_TIMESTAMP_RESP,
                    "timestamp token cannot be null", null);
        return ex;
    }

    /**
     * return the count of IncludeInfo objects
     * @return count of IncludeInfo objects
     */
    public int countIncludeInfos()
    {
        return ((m_includes == null) ? 0 : m_includes.size());
    }

    /**
     * Adds a new IncludeInfo object
     * @param inc new object to be added
     */
    public void addIncludeInfo(IncludeInfo inc)
    {
        if(m_includes == null)
            m_includes = new ArrayList();
        inc.setTimestampInfo(this);
        m_includes.add(inc);
    }

    /**
     * Retrieves IncludeInfo element with the desired index
     * @param idx IncludeInfo index
     * @return IncludeInfo element or null if not found
     */
    public IncludeInfo getIncludeInfo(int idx)
    {
        if(m_includes != null && idx < m_includes.size()) {
            return (IncludeInfo)m_includes.get(idx);
        } else
            return null; // not found
    }

    /**
     * Retrieves the last IncludeInfo element
     * @return IncludeInfo element or null if not found
     */
    public IncludeInfo getLastIncludeInfo()
    {
        if(m_includes != null && m_includes.size() > 0) {
            return (IncludeInfo)m_includes.get(m_includes.size()-1);
        } else
            return null; // not found
    }

    /**
     * Retrieves timestamp responses signature
     * algorithm OID.
     * @return responses signature algorithm OID
     */
    public String getAlgorithmOid()
    {
        String oid = null;
        if(m_tsTinfo != null) {
            oid = m_tsTinfo.getMessageImprintAlgOID().getId();
        }
        return oid;
    }

    /**
     * Retrieves timestamp responses policy
     * @return responses policy
     */
    public String getPolicy()
    {
        String oid = null;
        if(m_tsTinfo != null) {
            oid = m_tsTinfo.getPolicy().getId();
        }
        return oid;
    }

    /**
     * Retrieves timestamp issuing time
     * @return timestamp issuing time
     */
    public Date getTime()
    {
        Date d = null;
        if(m_tsTinfo != null) {
            d = m_tsTok.getTimeStampInfo().getGenTime();
        }
        return d;
    }

    /**
     * Retrieves timestamp msg-imprint digest
     * @return timestamp msg-imprint digest
     */
    public byte[] getMessageImprint()
    {
        byte[] b = null;
        if(m_tsTok != null) {
            b = m_tsTok.getTimeStampInfo().getMessageImprintDigest();
        }
        return b;
    }

    /**
     * Retrieves timestamp nonce
     * @return timestamp nonce
     */
    public BigInteger getNonce()
    {
        BigInteger b = null;
        if(m_tsTok != null) {
            b = m_tsTok.getTimeStampInfo().getNonce();
        }
        return b;
    }

    /**
     * Retrieves timestamp serial number
     * @return timestamp serial number
     */
    public BigInteger getSerialNumber()
    {
        BigInteger b = null;
        if(m_tsTok != null) {
            b = m_tsTok.getTimeStampInfo().getSerialNumber();
        }
        return b;
    }

    /**
     * Retrieves timestamp is-ordered atribute
     * @return timestamp is-ordered atribute
     */
    public boolean isOrdered()
    {
        boolean b = false;
        if(m_tsTok != null) {
            b = m_tsTok.getTimeStampInfo().isOrdered();
        }
        return b;
    }

    /**
     * Retrieves timestamp is-ordered atribute
     * @return timestamp is-ordered atribute
     */
    public String getSignerCN()
    {
        String s = null;
        if(m_tsTok != null) {
            //SignerId = m_tsResp.getTimeStampToken().getSignedAttributes()
            //org.bouncycastle.cms.CMSSignedData cms = m_tsResp.getTimeStampToken().

        }
        return s;
    }

    /**
     * Helper method to validate the whole
     * TimestampInfo object
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();
        DigiDocException ex = validateId(m_id);
        if(ex != null)
            errs.add(ex);
        ex = validateType(m_type);
        if(ex != null)
            errs.add(ex);
        return errs;
    }

}
