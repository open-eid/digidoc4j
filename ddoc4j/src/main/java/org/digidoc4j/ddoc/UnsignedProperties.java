package org.digidoc4j.ddoc;

import org.apache.log4j.Logger;
import org.digidoc4j.ddoc.factory.NotaryFactory;
import org.digidoc4j.ddoc.utils.ConfigManager;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Vector;

/**
 * Models the unsigned properties of
 * a signature.
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class UnsignedProperties implements Serializable
{
    private static final long serialVersionUID = 1L;
    /** signature reference */
    private Signature m_signature;
    /** CompleteCertificateRefs object */
    private CompleteCertificateRefs m_certRefs;
    /** CompleteRevocationRefs object */
    private CompleteRevocationRefs m_revRefs;
    /** Notary object */
    private Vector m_notaries;
    private static Logger m_logger = Logger.getLogger(UnsignedProperties.class);
    /**
     * Creates new UsignedProperties
     * Initializes everything to null
     * @param sig signature reference
     */
    public UnsignedProperties(Signature sig) {
        m_signature = sig;
        m_certRefs = null;
        m_revRefs = null;
        m_notaries = null;
    }

    /**
     * Creates new UsignedProperties
     * @param sig signature reference
     * @param crefs responders cert digest & info
     * @param rrefs OCSP response digest & info
     */
    public UnsignedProperties(Signature sig, CompleteCertificateRefs crefs,
                              CompleteRevocationRefs rrefs)
            throws DigiDocException
    {
        m_signature = sig;
        setCompleteCertificateRefs(crefs);
        setCompleteRevocationRefs(rrefs);
    }

    /**
     * Accessor for completeCertificateRefs attribute
     * @return value of completeCertificateRefs attribute
     */
    public CompleteCertificateRefs getCompleteCertificateRefs() {
        return m_certRefs;
    }

    /**
     * Accessor for signature attribute
     * @return value of signature attribute
     */
    public Signature getSignature()
    {
        return m_signature;
    }

    /**
     * Mutator for completeCertificateRefs attribute
     * @param str new value for completeCertificateRefs attribute
     * @throws DigiDocException for validation errors
     */
    public void setCompleteCertificateRefs(CompleteCertificateRefs crefs)
            throws DigiDocException
    {
        //ArrayList errs = crefs.validate();
        //if(!errs.isEmpty())
        //    throw (DigiDocException)errs.get(0);
        m_certRefs = crefs;
    }

    /**
     * Accessor for completeRevocationRefs attribute
     * @return value of completeRevocationRefs attribute
     */
    public CompleteRevocationRefs getCompleteRevocationRefs() {
        return m_revRefs;
    }

    /**
     * Mutator for completeRevocationRefs attribute
     * @param str new value for completeRevocationRefs attribute
     * @throws DigiDocException for validation errors
     */
    public void setCompleteRevocationRefs(CompleteRevocationRefs refs)
            throws DigiDocException
    {
        //ArrayList errs = refs.validate();
        //if(!errs.isEmpty())
        //    throw (DigiDocException)errs.get(0);
        m_revRefs = refs;
    }

    /**
     * Accessor for respondersCertificate attribute
     * @return value of respondersCertificate attribute
     */
    public X509Certificate getRespondersCertificate() {
        X509Certificate cert = null;
        if(m_signature != null) {
            CertValue cval = m_signature.getCertValueOfType(CertValue.CERTVAL_TYPE_RESPONDER);
            if(cval != null)
                cert = cval.getCert();
        }
        return cert;
    }

    /**
     * Mutator for respondersCertificate attribute
     * @param cert new value for respondersCertificate attribute
     * @throws DigiDocException for validation errors
     */
    public void setRespondersCertificate(X509Certificate cert)
            throws DigiDocException
    {

        if(m_signature != null && cert != null) {
            CertValue cval = m_signature.getOrCreateCertValueOfType(CertValue.CERTVAL_TYPE_RESPONDER);
            cval.setId(m_signature.getId() + "-RESPONDER_CERT");
            cval.setCert(cert);
        }
    }

    /**
     * Helper method to validate a responders cert
     * @param cert input data
     * @return exception or null for ok
     */
    private DigiDocException validateRespondersCertificate(X509Certificate cert)
    {
        DigiDocException ex = null;
        return ex;
    }

    /**
     * Get the n-th Notary object
     * @param nIdx Notary index
     * @return Notary object
     */
    public Notary getNotaryById(int nIdx)
    {
        if(m_notaries != null && nIdx < m_notaries.size())
            return (Notary)m_notaries.elementAt(nIdx);
        else
            return null;
    }

    /**
     * Add a new Notary
     * @param not Notary object
     */
    public void addNotary(Notary not)
    {
        if(m_notaries == null)
            m_notaries = new Vector();
        m_notaries.add(not);
    }

    /**
     * Count the number of Notary objects
     * @return number of Notary objects
     */
    public int countNotaries() { return (m_notaries != null) ? m_notaries.size() : 0; }

    /**
     * Accessor for notary attribute
     * @return value of notary attribute
     */
    public Notary getNotary() {
        return getNotaryById(0);
    }

    /**
     * Accessor for notary attribute
     * @return value of notary attribute
     */
    public Notary getLastNotary() {
        return getNotaryById(countNotaries()-1);
    }

    /**
     * Mutator for notary attribute
     * @param str new value for notary attribute
     * @throws DigiDocException for validation errors
     */
    public void setNotary(Notary not)
            throws DigiDocException
    {
        addNotary(not);
    }


    /**
     * Verifies this confirmation
     * @param sdoc parent doc object
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList verify(SignedDoc sdoc)
    {
        ArrayList errs = new ArrayList();
        // verify notary certs serial number using CompleteCertificateRefs
        X509Certificate cert = getRespondersCertificate();
        if(m_logger.isDebugEnabled())
            m_logger.debug("Responders cert: " + cert.getSerialNumber() + " - " + cert.getSubjectDN().getName() +
                    " complete cert refs nr: " + m_certRefs.getCertSerial() + " - " + m_certRefs.getCertIssuer());
        if(cert == null) {
            errs.add(new DigiDocException(DigiDocException.ERR_RESPONDERS_CERT,
                    "No notarys certificate!", null));
            return errs;
        }
        if(cert != null && !cert.getSerialNumber().equals(m_certRefs.getCertSerial())) {
            errs.add(new DigiDocException(DigiDocException.ERR_RESPONDERS_CERT,
                    "Wrong notarys certificate: " + cert.getSerialNumber() + " ref: " + m_certRefs.getCertSerial(), null));
        }
        // verify notary certs digest using CompleteCertificateRefs
        try {
            byte[] digest = SignedDoc.digestOfType(cert.getEncoded(), SignedDoc.SHA1_DIGEST_TYPE);
            if(m_logger.isDebugEnabled())
                m_logger.debug("Not cert calc hash: " + Base64Util.encode(digest, 0) +
                        " cert-ref hash: " + Base64Util.encode(m_certRefs.getCertDigestValue(), 0));
            if(!SignedDoc.compareDigests(digest, m_certRefs.getCertDigestValue())) {
                errs.add(new DigiDocException(DigiDocException.ERR_RESPONDERS_CERT,
                        "Notary certificates digest doesn't match!", null));
                m_logger.error("Notary certificates digest doesn't match!");
                }
        } catch(DigiDocException ex) {
            errs.add(ex);
        } catch(Exception ex) {
            errs.add(new DigiDocException(DigiDocException.ERR_RESPONDERS_CERT,
                    "Error calculating notary certificate digest!", null));
        }
        // verify notarys digest using CompleteRevocationRefs
        try {
            for(int i = 0; i < countNotaries(); i++) {
                Notary not = getNotaryById(i);
                byte[] ocspData = not.getOcspResponseData();
                if(m_logger.isDebugEnabled())
                    m_logger.debug("OCSP value: " + not.getId() + " data: " + ((ocspData != null) ? ocspData.length : 0) + " bytes");
                if(ocspData == null || ocspData.length == 0) {
                    errs.add(new DigiDocException(DigiDocException.ERR_NOTARY_DIGEST, "OCSP value is empty!", null));
                    continue;
                }
                OcspRef orf = m_revRefs.getOcspRefByUri("#" + not.getId());
                if(m_logger.isDebugEnabled())
                    m_logger.debug("OCSP ref: " + ((orf != null) ? orf.getUri() : "NULL"));
                if(orf == null) {
                    errs.add(new DigiDocException(DigiDocException.ERR_NOTARY_DIGEST, "No OCSP ref for uri: #" + not.getId(), null));
                    continue;
                }
                byte[] digest1 = SignedDoc.digestOfType(ocspData, SignedDoc.SHA1_DIGEST_TYPE);
                byte[] digest2 = orf.getDigestValue();
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Check ocsp: " + not.getId() +
                            " calc hash: " + Base64Util.encode(digest1, 0) +
                            " refs-hash: " + Base64Util.encode(digest2, 0));
                if(!SignedDoc.compareDigests(digest1, digest2)) {
                    errs.add(new DigiDocException(DigiDocException.ERR_NOTARY_DIGEST,
                            "Notarys digest doesn't match!", null));
                    m_logger.error("Notarys digest doesn't match!");
                }
            }
        } catch(DigiDocException ex) {
            errs.add(ex);
        }
        // verify notary status
        try {
            NotaryFactory notFac = ConfigManager.instance().getNotaryFactory();
            for(int i = 0; i < countNotaries(); i++) {
                Notary not = getNotaryById(i);
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Verify notray: " + not.getId() + " ocsp: " +
                            ((not.getOcspResponseData() != null) ? not.getOcspResponseData().length : 0) +
                            " responder: " + not.getResponderId());
                notFac.parseAndVerifyResponse(m_signature, not);
            }
        } catch(DigiDocException ex) {
            errs.add(ex);
        }
        return errs;
    }


    /**
     * Helper method to validate the whole
     * UnsignedProperties object
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();
        DigiDocException ex = null;
        X509Certificate cert = getRespondersCertificate();
        if(cert == null)
            ex = validateRespondersCertificate(cert);
        if(ex != null)
            errs.add(ex);
        ArrayList e = null;
        if(m_certRefs != null) {
            e = m_certRefs.validate();
            if(!e.isEmpty())
                errs.addAll(e);
        }
        if(m_revRefs != null) {
            e = m_revRefs.validate();
            if(!e.isEmpty())
                errs.addAll(e);
        }
        // notary ???

        return errs;
    }


}
