package org.digidoc4j.ddoc;

import org.digidoc4j.ddoc.utils.ConfigManager;
import org.digidoc4j.ddoc.utils.ConvertUtils;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

/**
 * Models the ETSI <Cert> element
 * Holds info about a certificate but not
 * the certificate itself. Such elements will
 * be serialized under the <CompleteCertificateRefs>
 * element
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class CertID implements Serializable
{
    private static final long serialVersionUID = 1L;
    /** certs digest algorithm */
    private String m_digestAlgorithm;
    /** elements id atribute if present */
    private String m_id;
    /** URI atribute if used */
    private String m_uri;
    /** certs digest data */
    private byte[] m_digestValue;
    /** certs issuer DN */
    private String m_issuer;
    /** certs issuer serial number */
    private BigInteger m_serial;
    /** parent object - Signature ref */
    private Signature m_signature;
    /** CertID type - signer, responder, tsa */
    private int m_type;

    /** possible certid type values */
    public static final int CERTID_TYPE_UNKNOWN = 0;
    public static final int CERTID_TYPE_SIGNER = 1;
    public static final int CERTID_TYPE_RESPONDER = 2;
    public static final int CERTID_TYPE_TSA = 3;
    public static final int CERTID_TYPE_CA = 4;
    public static final int CERTID_TYPE_RESPONDER_CA = 5;

    /**
     * Creates new CertID
     * and initializes everything to null
     */
    public CertID() {
        m_id = null;
        m_uri = null;
        m_digestAlgorithm = null;
        m_digestValue = null;
        m_serial = null;
        m_issuer = null;
        m_signature = null;
        m_type = CERTID_TYPE_UNKNOWN;
    }

    /**
     * Creates new CertID
     * @param certId OCSP responders cert id (in XML)
     * @param digAlg OCSP responders certs digest algorithm id/uri
     * @param digest OCSP responders certs digest
     * @param serial OCSP responders certs issuers serial number
     * @param type CertID type: signer, responder or tsa
     * @throws DigiDocException for validation errors
     */
    public CertID(String certId, String digAlg, byte[] digest,
                  BigInteger serial, String issuer, int type)
            throws DigiDocException
    {
        setId(certId);
        setDigestAlgorithm(digAlg);
        setDigestValue(digest);
        setSerial(serial);
        if(issuer != null)
            setIssuer(issuer);
        setType(type);
        m_signature = null;
    }

    /**
     * Creates new CertID by using
     * default values for id and responders cert
     * @param sig Signature object
     * @param cert OCSP certificate for creating this ref data
     * @param type CertID type: signer, responder or tsa
     * @throws DigiDocException for validation errors
     */
    public CertID(Signature sig, X509Certificate cert, int type)
            throws DigiDocException
    {
        if(type == CertID.CERTID_TYPE_SIGNER)
            setId(sig.getId() + "-CERTINFO");
        if(type == CertID.CERTID_TYPE_RESPONDER)
            setId(sig.getId() + "-RESPONDER_CERTINFO");
        String sDigType = ConfigManager.instance().getDefaultDigestType(sig.getSignedDoc());
        String sDigAlg = ConfigManager.digType2Alg(sDigType);
        setDigestAlgorithm(sDigAlg);
        byte[] digest = null;
        try {
            digest = SignedDoc.digestOfType(cert.getEncoded(), sDigType);
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_CALCULATE_DIGEST);
        }
        setDigestValue(digest);
        setSerial(cert.getSerialNumber());
        setIssuer(ConvertUtils.convX509Name(cert.getIssuerX500Principal()));
        setType(type);
    }

    /**
     * Creates new CertID by using
     * default values for id and responders cert
     * @param sig Signature object
     * @param cert OCSP certificate for creating this ref data
     * @param type CertID type: signer, responder or tsa
     * @throws DigiDocException for validation errors
     */
    public CertID(Signature sig, X509Certificate cert, int type, String id)
            throws DigiDocException
    {
        setId(id);
        String sDigType = ConfigManager.instance().getDefaultDigestType(sig.getSignedDoc());
        String sDigAlg = ConfigManager.digType2Alg(sDigType);
        setDigestAlgorithm(sDigAlg);
        byte[] digest = null;
        try {
            digest = SignedDoc.digestOfType(cert.getEncoded(), sDigType);
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_CALCULATE_DIGEST);
        }
        setDigestValue(digest);
        setSerial(cert.getSerialNumber());
        setIssuer(ConvertUtils.convX509Name(cert.getIssuerX500Principal()));
        setType(type);
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
     * Accessor for certId attribute
     * @return value of certId attribute
     */
    public String getId() {
        return m_id;
    }

    /**
     * Mutator for certId attribute
     * @param str new value for certId attribute
     * @throws DigiDocException for validation errors
     */
    public void setId(String str)
            throws DigiDocException
    {
        if(m_signature != null && m_signature.getSignedDoc() != null &&
                !m_signature.getSignedDoc().getVersion().equals(SignedDoc.VERSION_1_3)) {
            DigiDocException ex = validateId(str);
            if(ex != null)
                throw ex;
        }
        m_id = str;
    }

    /**
     * Accessor for URI attribute
     * @return value of URI attribute
     */
    public String getUri() {
        return m_uri;
    }

    /**
     * Mutator for URI attribute
     * @param str new value for URI attribute
     */
    public void setUri(String str)
    {
        m_uri = str;
    }

    /**
     * Helper method to validate an certificate id
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateId(String str)
    {
        DigiDocException ex = null;
        if(str == null && !m_signature.getSignedDoc().getVersion().equals(SignedDoc.VERSION_1_3)
                && !m_signature.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC)
                && m_type == CERTID_TYPE_RESPONDER)
            ex = new DigiDocException(DigiDocException.ERR_RESPONDER_CERT_ID,
                    "Cert Id must be in form: <signature-id>-RESPONDER_CERTINFO", null);
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
                (!str.equals(SignedDoc.SHA1_DIGEST_ALGORITHM) &&
                        !str.equals(SignedDoc.SHA256_DIGEST_ALGORITHM_1) &&
                        !str.equals(SignedDoc.SHA256_DIGEST_ALGORITHM_2) &&
                        !str.equals(SignedDoc.SHA512_DIGEST_ALGORITHM)))
            ex = new DigiDocException(DigiDocException.ERR_DIGEST_ALGORITHM,
                    "Currently supports only SHA-1, SHA-256 or SHA-512 digest algorithm", null);
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
                (data.length != SignedDoc.SHA1_DIGEST_LENGTH &&
                        data.length != SignedDoc.SHA256_DIGEST_LENGTH &&
                        data.length != SignedDoc.SHA512_DIGEST_LENGTH))
            ex = new DigiDocException(DigiDocException.ERR_DIGEST_LENGTH,
                    "Invalid digest length", null);
        return ex;
    }

    /**
     * Accessor for serial attribute
     * @return value of serial attribute
     */
    public BigInteger getSerial() {
        return m_serial;
    }

    /**
     * Mutator for serial attribute
     * @param str new value for serial attribute
     * @throws DigiDocException for validation errors
     */
    public void setSerial(BigInteger i)
            throws DigiDocException
    {
        DigiDocException ex = validateSerial(i);
        if(ex != null)
            throw ex;
        m_serial = i;
    }

    /**
     * Helper method to validate a serial
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateSerial(BigInteger i)
    {
        DigiDocException ex = null;
        if(i == null) // check the uri somehow ???
            ex = new DigiDocException(DigiDocException.ERR_CERT_SERIAL,
                    "Certificates serial number cannot be empty!", null);
        return ex;
    }

    /**
     * Accessor for issuer attribute
     * @return value of issuer attribute
     */
    public String getIssuer() {
        return m_issuer;
    }

    /**
     * Mutator for issuer attribute
     * @param str new value for issuer attribute
     * @throws DigiDocException for validation errors
     */
    public void setIssuer(String str)
            throws DigiDocException
    {
        DigiDocException ex = validateIssuer(str);
        if(ex != null)
            throw ex;
        m_issuer = str;
    }

    /**
     * Helper method to validate issuer
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateIssuer(String str)
    {
        DigiDocException ex = null;
        if(str == null && m_signature != null &&
                (m_signature.getSignedDoc().getVersion().equals(SignedDoc.VERSION_1_3)))
            ex = new DigiDocException(DigiDocException.ERR_CREF_ISSUER,
                    "Issuer name cannot be empty", null);
        return ex;
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
        if(n < 0 || n > CERTID_TYPE_RESPONDER_CA)
            ex = new DigiDocException(DigiDocException.ERR_CERTID_TYPE,
                    "Invalid CertID type", null);
        return ex;
    }

    /**
     * Helper method to validate the whole
     * CertID object
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();
        DigiDocException ex = validateId(m_id);
        if(ex != null)
            errs.add(ex);
        ex = validateDigestAlgorithm(m_digestAlgorithm);
        if(ex != null)
            errs.add(ex);
        ex = validateDigestValue(m_digestValue);
        if(ex != null)
            errs.add(ex);
        ex = validateSerial(m_serial);
        if(ex != null)
            errs.add(ex);
        ex = validateIssuer(m_issuer);
        if(ex != null)
            errs.add(ex);
        ex = validateType(m_type);
        if(ex != null)
            errs.add(ex);
        return errs;
    }

}
