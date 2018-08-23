package ee.sk.digidoc;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;

/**
 * Models the KeyInfo block of an XML-DSIG
 * signature. In DigiDoc library the key info
 * allways contains only one subject certificate,
 * e.g. no uplinks and the smaller items like
 * RSA public key modulus and export are not
 * kept separately but calculated online from the
 * signers certificate. That means they are read-only
 * attributes.
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class KeyInfo implements Serializable
{
    private static final long serialVersionUID = 1L;
    /** parent object - Signature ref */
    private Signature m_signature;
    /** Id atribute value if set */
    private String m_id;


    /**
     * Creates new KeyInfo
     */
    public KeyInfo() {
        m_signature = null;
    }

    /**
     * Creates new KeyInfo
     * @param cert signers certificate
     */
    public KeyInfo(X509Certificate cert)
            throws DigiDocException
    {
        setSignersCertificate(cert);
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
     * Accessor for Id attribute
     * @return value of Id attribute
     */
    public String getId() {
        return m_id;
    }

    /**
     * Mutator for Id attribute
     * @param str new value for Id attribute
     */
    public void setId(String str)
    {
        m_id = str;
    }

    /**
     * Accessor for signersCert attribute
     * @return value of signersCert attribute
     */
    public X509Certificate getSignersCertificate() {
        X509Certificate cert = null;
        if(m_signature != null) {
            CertValue cval = m_signature.getCertValueOfType(CertValue.CERTVAL_TYPE_SIGNER);
            if(cval != null) {
                cert = cval.getCert();
            }
        }
        return cert;
    }

    /**
     * return certificate owners first name
     * @return certificate owners first name or null
     */
    public String getSubjectFirstName() {
        X509Certificate cert = getSignersCertificate();
        if(cert != null)
            return SignedDoc.getSubjectFirstName(cert);
        else
            return null;
    }

    /**
     * return certificate owners last name
     * @return certificate owners last name or null
     */
    public String getSubjectLastName() {
        X509Certificate cert = getSignersCertificate();
        if(cert != null)
            return SignedDoc.getSubjectLastName(cert);
        else
            return null;
    }

    /**
     * return certificate owners personal code
     * @return certificate owners personal code or null
     */
    public String getSubjectPersonalCode() {
        X509Certificate cert = getSignersCertificate();
        if(cert != null)
            return SignedDoc.getSubjectPersonalCode(cert);
        else
            return null;
    }

    /**
     * Mutator for signersCert attribute
     * @param cert new value for signersCert attribute
     * @throws DigiDocException for validation errors
     */
    public void setSignersCertificate(X509Certificate cert)
            throws DigiDocException
    {
        DigiDocException ex = validateSignersCertificate(cert);
        if(ex != null)
            throw ex;
        if(m_signature != null) {
            CertValue cval = m_signature.getOrCreateCertValueOfType(CertValue.CERTVAL_TYPE_SIGNER);
            cval.setCert(cert);
        }
    }

    /**
     * Helper method to validate a signers cert
     * @param cert input data
     * @return exception or null for ok
     */
    private DigiDocException validateSignersCertificate(X509Certificate cert)
    {
        DigiDocException ex = null;
        if(cert == null)
            ex = new DigiDocException(DigiDocException.ERR_SIGNERS_CERT,
                    "Signers certificate is required", null);
        return ex;
    }

    /**
     * return the signers certificates key modulus
     * @return signers certificates key modulus
     */
    public BigInteger getSignerKeyModulus()
    {
        X509Certificate cert = getSignersCertificate();
        if(cert != null)
            return ((RSAPublicKey)cert.getPublicKey()).getModulus();
        else
            return null;
    }

    /**
     * return the signers certificates key exponent
     * @return signers certificates key exponent
     */
    public BigInteger getSignerKeyExponent()
    {
        X509Certificate cert = getSignersCertificate();
        if(cert != null)
            return ((RSAPublicKey)cert.getPublicKey()).getPublicExponent();
        else
            return null;
    }

    /**
     * Helper method to validate the whole
     * KeyInfo object
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();
        DigiDocException ex = null;
        X509Certificate cert = getSignersCertificate();
        if(cert != null)
            ex = validateSignersCertificate(cert);
        if(ex != null)
            errs.add(ex);
        return errs;
    }

}
