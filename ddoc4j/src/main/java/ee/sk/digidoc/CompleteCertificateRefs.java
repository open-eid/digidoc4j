package ee.sk.digidoc;

import ee.sk.digidoc.CertID;
import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.Signature;
import ee.sk.digidoc.UnsignedProperties;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

/**
 * Models the ETSI CompleteCertificateRefs
 * element
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class CompleteCertificateRefs implements Serializable
{
    private static final long serialVersionUID = 1L;

    /** parent object - UnsignedProperties ref */
    private UnsignedProperties m_unsignedProps;

    /**
     * Creates new CompleteCertificateRefs
     * and initializes everything to null
     */
    public CompleteCertificateRefs() {
        m_unsignedProps = null;
    }

    /**
     * Creates new CompleteCertificateRefs.
     * Rerouted to set those values on responders certid.
     * @param certId OCSP responders cert id (in XML)
     * @param digAlg OCSP responders certs digest algorithm id/uri
     * @param digest OCSP responders certs digest
     * @param serial OCSP responders certs issuers serial number
     * @throws DigiDocException for validation errors
     */
    public CompleteCertificateRefs(String certId, String digAlg, byte[] digest, BigInteger serial)
            throws DigiDocException
    {
        CertID cid = new CertID(certId, digAlg, digest, serial, null, CertID.CERTID_TYPE_RESPONDER);
        addCertID(cid);
        m_unsignedProps = null;
    }

    /**
     * Creates new CompleteCertificateRefs by using
     * default values for id and responders cert
     * Rerouted to set those values on responders certid.
     * @param sig Signature object
     * @param respCert OCSP responders cert
     * @throws DigiDocException for validation errors
     */
    public CompleteCertificateRefs(Signature sig, X509Certificate respCert)
            throws DigiDocException
    {
        CertID cid = new CertID(sig, respCert, CertID.CERTID_TYPE_RESPONDER);
        sig.addCertID(cid);
    }

    /**
     * return the count of CertID objects
     * @return count of CertID objects
     */
    public int countCertIDs()
    {
        return m_unsignedProps.getSignature().countCertIDs();
    }

    /**
     * Adds a new CertID object
     * @param cid new object to be added
     */
    public void addCertID(CertID cid)
    {
        m_unsignedProps.getSignature().addCertID(cid);
    }

    /**
     * Retrieves CertID element with the desired index
     * @param idx CertID index
     * @return CertID element or null if not found
     */
    public CertID getCertID(int idx)
    {
        return m_unsignedProps.getSignature().getCertID(idx);
    }

    /**
     * Retrieves the last CertID element
     * @return CertID element or null if not found
     */
    public CertID getLastCertId()
    {
        return m_unsignedProps.getSignature().getLastCertId();
    }

    /**
     * Retrieves CertID element with the desired type
     * @param type CertID type
     * @return CertID element or null if not found
     */
    public CertID getCertIdOfType(int type)
    {
        return m_unsignedProps.getSignature().getCertIdOfType(type);
    }

    /**
     * Retrieves CertID element with the desired type.
     * If not found creates a new one with this type.
     * @param type CertID type
     * @return CertID element
     * @throws DigiDocException for validation errors
     */
    public CertID getOrCreateCertIdOfType(int type)
            throws DigiDocException
    {
        return m_unsignedProps.getSignature().getOrCreateCertIdOfType(type);
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
     * Accessor for certId attribute
     * Rerouted to get this attribute from CertID sublement.
     * @return value of certId attribute
     */
    public String getCertId() {
        CertID cid = getCertIdOfType(CertID.CERTID_TYPE_RESPONDER);
        if(cid != null)
            return cid.getId();
        else
            return null;
    }

    /**
     * Mutator for certId attribute.
     * Rerouted to set this attribute on CertID sublement.
     * @param str new value for certId attribute
     * @throws DigiDocException for validation errors
     */
    public void setCertId(String str)
            throws DigiDocException
    {
        CertID cid = getOrCreateCertIdOfType(CertID.CERTID_TYPE_RESPONDER);
        cid.setId(str);
    }

    /**
     * Accessor for certDigestAlgorithm attribute
     * Rerouted to get this attribute from CertID sublement.
     * @return value of certDigestAlgorithm attribute
     */
    public String getCertDigestAlgorithm() {
        CertID cid = getCertIdOfType(CertID.CERTID_TYPE_RESPONDER);
        if(cid != null)
            return cid.getDigestAlgorithm();
        else
            return null;
    }

    /**
     * Mutator for certDigestAlgorithm attribute.
     * Rerouted to set this attribute on CertID sublement.
     * @param str new value for certDigestAlgorithm attribute
     * @throws DigiDocException for validation errors
     */
    public void setCertDigestAlgorithm(String str)
            throws DigiDocException
    {
        CertID cid = getOrCreateCertIdOfType(CertID.CERTID_TYPE_RESPONDER);
        cid.setDigestAlgorithm(str);
    }

    /**
     * Accessor for certDigestValue attribute
     * Rerouted to get this attribute from CertID sublement.
     * @return value of certDigestValue attribute
     */
    public byte[] getCertDigestValue() {
        CertID cid = getCertIdOfType(CertID.CERTID_TYPE_RESPONDER);
        if(cid != null)
            return cid.getDigestValue();
        else
            return null;
    }

    /**
     * Mutator for certDigestValue attribute.
     * Rerouted to set this attribute on CertID sublement.
     * @param data new value for certDigestValue attribute
     * @throws DigiDocException for validation errors
     */
    public void setCertDigestValue(byte[] data)
            throws DigiDocException
    {
        CertID cid = getOrCreateCertIdOfType(CertID.CERTID_TYPE_RESPONDER);
        cid.setDigestValue(data);
    }

    /**
     * Accessor for certSerial attribute.
     * Rerouted to get this attribute from CertID sublement.
     * @return value of certSerial attribute
     */
    public BigInteger getCertSerial() {
        CertID cid = getCertIdOfType(CertID.CERTID_TYPE_RESPONDER);
        if(cid != null)
            return cid.getSerial();
        else
            return null;
    }

    public String getCertIssuer() {
        CertID cid = getCertIdOfType(CertID.CERTID_TYPE_RESPONDER);
        if(cid != null)
            return cid.getIssuer();
        else
            return null;
    }

    /**
     * Mutator for certSerial attribute.
     * Rerouted to set this attribute on CertID sublement.
     * @param str new value for certSerial attribute
     * @throws DigiDocException for validation errors
     */
    public void setCertSerial(BigInteger i)
            throws DigiDocException
    {
        CertID cid = getOrCreateCertIdOfType(CertID.CERTID_TYPE_RESPONDER);
        cid.setSerial(i);
    }

    /**
     * Helper method to validate the whole
     * CompleteCertificateRefs object
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();
        for(int i = 0; i < countCertIDs(); i++) {
            CertID cid = getCertID(i);
            if(cid != null) {
                ArrayList a = cid.validate();
                if(a.size() > 0)
                    errs.addAll(a);
            }
        }
        return errs;
    }

}
