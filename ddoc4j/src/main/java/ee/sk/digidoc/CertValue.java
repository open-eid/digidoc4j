package ee.sk.digidoc;

import java.io.Serializable;
import java.security.cert.X509Certificate;

/**
 * Models the ETSI <X509Certificate>
 * and <EncapsulatedX509Certificate> elements.
 * Holds certificate data. Such elements will
 * be serialized under the <CertificateValues>
 * and <X509Data> elements
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class CertValue implements Serializable
{
    private static final long serialVersionUID = 1L;
    /** elements id atribute if present */
    private String m_id;
    /** parent object - Signature ref */
    private Signature m_signature;
    /** CertID type - signer, responder, tsa */
    private int m_type;
    /** certificate */
    private X509Certificate m_cert;

    /** possible cert value type values */
    public static final int CERTVAL_TYPE_UNKNOWN = 0;
    public static final int CERTVAL_TYPE_SIGNER = 1;
    public static final int CERTVAL_TYPE_RESPONDER = 2;
    public static final int CERTVAL_TYPE_TSA = 3;
    public static final int CERTVAL_TYPE_CA = 4;
    public static final int CERTVAL_TYPE_RESPONDER_CA = 5;

    /**
     * Creates new CertValue
     * and initializes everything to null
     */
    public CertValue() {
        m_id = null;
        m_signature = null;
        m_cert = null;
        m_type = CERTVAL_TYPE_UNKNOWN;
    }

    /**
     * Parametrized constructor
     * @param id id atribute value
     * @param cert certificate
     * @param type cert value type
     * @param sig Signature ref
     */
    public CertValue(String id, X509Certificate cert, int type, Signature sig) {
        m_id = id;
        m_signature = sig;
        m_cert = cert;
        m_type = type;
    }

    /**
     * Accessor for Signature attribute
     * @return value of Signature attribute
     */
    public Signature getSignature()
    {
        return m_signature;
    }

    /**
     * Mutator for Signature attribute
     * @param uprops value of Signature attribute
     */
    public void setSignature(Signature sig)
    {
        m_signature = sig;
    }

    /**
     * Accessor for id attribute
     * @return value of certId attribute
     */
    public String getId() {
        return m_id;
    }

    /**
     * Mutator for id attribute
     * @param str new value for certId attribute
     */
    public void setId(String str)
    {
        m_id = str;
    }

    /**
     * Accessor for type attribute
     * @return value of type attribute
     */
    public int getType() {
        return m_type;
    }

    /**
     * Mutator for type attribute
     * @param n new value for issuer attribute
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
     * Helper method to validate type
     * @param n input data
     * @return exception or null for ok
     */
    private DigiDocException validateType(int n)
    {
        DigiDocException ex = null;
        if(n < 0 || n > CERTVAL_TYPE_TSA)
            ex = new DigiDocException(DigiDocException.ERR_CERTID_TYPE,
                    "Invalid CertValue type", null);
        return ex;
    }

    /**
     * Accessor for Cert attribute
     * @return value of Cert attribute
     */
    public X509Certificate getCert()
    {
        return m_cert;
    }

    /**
     * Mutator for Cert attribute
     * @param uprops value of Cert attribute
     */
    public void setCert(X509Certificate cert)
    {
        m_cert = cert;
    }


}
