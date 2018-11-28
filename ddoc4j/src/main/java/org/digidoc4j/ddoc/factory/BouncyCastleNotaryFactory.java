package org.digidoc4j.ddoc.factory;

import org.digidoc4j.ddoc.*;
import org.digidoc4j.ddoc.utils.ConfigManager;
import org.digidoc4j.ddoc.utils.ConvertUtils;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.digidoc4j.ddoc.Signature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.OutputStream;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class BouncyCastleNotaryFactory implements NotaryFactory
{
    private static final Logger m_logger = LoggerFactory.getLogger(BouncyCastleNotaryFactory.class);

    /**
     * Returns the OCSP responders certificate
     * @param responderCN responder-id's CN
     * @param specificCertNr specific cert number that we search.
     * If this parameter is null then the newest cert is seleced (if many exist)
     * @returns OCSP responders certificate
     */
    public X509Certificate[] getNotaryCerts(String responderCN, String specificCertNr)
    {
        try {
            TrustServiceFactory tslFac = ConfigManager.instance().getTslFactory();
            return tslFac.findOcspsByCNAndNr(responderCN, true, specificCertNr);
        } catch(Exception ex) {
            m_logger.error("Error searching responder cert for: " + responderCN + " - " + ex);
        }
        return null;
    }

    public boolean isSignatureValid(BasicOCSPResp resp, ContentVerifierProvider verifierProvider)
            throws Exception
    {
        try
        {

            ContentVerifier verifier = verifierProvider.get(resp.getSignatureAlgorithmID());
            OutputStream vOut = verifier.getOutputStream();
            vOut.write(resp.getTBSResponseData());
            vOut.close();
            ASN1Primitive obj = ASN1Primitive.fromByteArray(resp.getEncoded());
            BasicOCSPResponse bresp = BasicOCSPResponse.getInstance(obj);
            boolean bOk = verifier.verify(bresp.getSignature().getBytes());
            if(m_logger.isDebugEnabled())
                m_logger.debug("Verify ocsp sig: " + ConvertUtils.bin2hex(bresp.getSignature().getBytes()) + " RC: " + bOk);
            return bOk;
        }
        catch (Exception ex)
        {
            m_logger.error("ocsp exception: " + ex);
            m_logger.error("Trace; " + ConvertUtils.getTrace(ex));
            throw ex;
        }
    }

    /**
     * Verifies that the OCSP response is about our signers
     * cert and the response status is successfull
     * @param sig Signature object
     * @param basResp OCSP Basic response
     * @throws DigiDocException if the response is not successfull
     */
    private void checkCertStatus(Signature sig, BasicOCSPResp basResp)
            throws DigiDocException
    {
        checkCertStatus(sig.getKeyInfo().getSignersCertificate(), basResp, null);
    }


    /**
     * Verifies that the OCSP response is about our signers
     * cert and the response status is successfull
     * @param sig Signature object
     * @param basResp OCSP Basic response
     * @throws DigiDocException if the response is not successfull
     */
    private void checkCertStatus(X509Certificate cert, BasicOCSPResp basResp, X509Certificate caCert)
            throws DigiDocException
    {
        try {
            if(m_logger.isDebugEnabled())
                m_logger.debug("Checking response status, CERT: " + ((cert != null) ? cert.getSubjectDN().getName() : "NULL") +
                        " SEARCH: " + ((cert != null) ? SignedDoc.getCommonName(ConvertUtils.convX509Name(cert.getIssuerX500Principal())) : "NULL"));
            if(cert == null)
                throw new DigiDocException(DigiDocException.ERR_CERT_UNKNOWN,
                        "No certificate to check! Error reading certificate from file?", null);
            // check the response on our cert
            TrustServiceFactory tslFac = ConfigManager.instance().getTslFactory();
            if(caCert == null)
                caCert = tslFac.findCaForCert(cert, true, null);
            if(m_logger.isDebugEnabled()) {
                m_logger.debug("CA cert: " + ((caCert != null) ? caCert.getSubjectDN().getName() : "NULL"));
                m_logger.debug("RESP: " + basResp);
                m_logger.debug("CERT: " + cert.getSubjectDN().getName() +
                        " ISSUER: " + ConvertUtils.convX509Name(cert.getIssuerX500Principal()) +
                        " nr: " + ((caCert != null) ? ConvertUtils.bin2hex(caCert.getSerialNumber().toByteArray()) : "NULL"));
            }
            if(caCert == null)
                throw new DigiDocException(DigiDocException.ERR_CERT_UNKNOWN, "Unknown CA cert: " + cert.getIssuerDN().getName(), null);
            SingleResp[] sresp = basResp.getResponses();
            CertificateID rc = creatCertReq(cert, caCert);
            if(m_logger.isDebugEnabled())
                m_logger.debug("Search alg: " + rc.getHashAlgOID() + " cert ser: " + cert.getSerialNumber().toString() +
                        " serial: " + rc.getSerialNumber() + " issuer: " + Base64Util.encode(rc.getIssuerKeyHash()) +
                        " subject: " + Base64Util.encode(rc.getIssuerNameHash()));
            boolean ok = false;
            for(int i=0;i < sresp.length;i++) {
                CertificateID id = sresp[i].getCertID();
                if(id != null) {
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Got alg: " + id.getHashAlgOID() +
                                " serial: " + id.getSerialNumber() +
                                " issuer: " + Base64Util.encode(id.getIssuerKeyHash()) +
                                " subject: " + Base64Util.encode(id.getIssuerNameHash()));
                    if(rc.getHashAlgOID().equals(id.getHashAlgOID()) &&
                            rc.getSerialNumber().equals(id.getSerialNumber()) &&
                            SignedDoc.compareDigests(rc.getIssuerKeyHash(), id.getIssuerKeyHash()) &&
                            SignedDoc.compareDigests(rc.getIssuerNameHash(), id.getIssuerNameHash())) {
                        if(m_logger.isDebugEnabled())
                            m_logger.debug("Found it!");
                        ok = true;
                        Object status = sresp[i].getCertStatus();
                        if(status != null) {
                            if(m_logger.isDebugEnabled())
                                m_logger.debug("CertStatus: " + status.getClass().getName());
                            if(status instanceof RevokedStatus) {
                                m_logger.error("Certificate has been revoked!");
                                throw new DigiDocException(DigiDocException.ERR_CERT_REVOKED,
                                        "Certificate has been revoked!", null);
                            }
                            if(status instanceof UnknownStatus) {
                                m_logger.error("Certificate status is unknown!");
                                throw new DigiDocException(DigiDocException.ERR_CERT_UNKNOWN,
                                        "Certificate status is unknown!", null);
                            }

                        }
                        break;
                    }
                }
            }

            if(!ok) {
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Error checkCertStatus - not found ");
                throw new DigiDocException(DigiDocException.ERR_OCSP_RESP_STATUS,
                        "Bad OCSP response status!", null);
            }
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            m_logger.error("Error checkCertStatus: " + ex);
            ex.printStackTrace();
            throw new DigiDocException(DigiDocException.ERR_OCSP_RESP_STATUS,
                    "Error checking OCSP response status!", null);
        }
    }

    /**
     * Check the response and parse it's data
     * Used by UnsignedProperties.verify()
     * @param not initial Notary object that contains only the
     * raw bytes of an OCSP response
     * @returns Notary object with data parsed from OCSP response
     */
    public Notary parseAndVerifyResponse(Signature sig, Notary not)
            throws DigiDocException
    {
        try {;
            OCSPResp  resp = new OCSPResp(not.getOcspResponseData());
            // now read the info from the response
            BasicOCSPResp basResp = (BasicOCSPResp)resp.getResponseObject();
            // verify the response
            X509Certificate[] lNotCerts = null;
            try {
                String respondIDstr = responderIDtoString(basResp);

                if(m_logger.isDebugEnabled()) {
                    m_logger.debug("SIG: " + ((sig == null) ? "NULL" : sig.getId()));
                    m_logger.debug("UP: " + ((sig.getUnsignedProperties() == null) ? "NULL" : "OK: " + sig.getUnsignedProperties().getNotary().getId()));
                    m_logger.debug("RESP-CERT: " + ((sig.getUnsignedProperties().
                            getRespondersCertificate() == null) ? "NULL" : "OK"));
                    m_logger.debug("RESP-ID: " + respondIDstr);
                    CertID cid = sig.getCertID(CertID.CERTID_TYPE_RESPONDER);
                    if(cid != null)
                        m_logger.debug("CID: " + cid.getType() + " id: " + cid.getId() +
                                ", " + cid.getSerial() + " issuer: " + cid.getIssuer());
                    m_logger.debug("RESP: " + Base64Util.encode(resp.getEncoded()));
                }
                if(lNotCerts == null && sig != null) {
                    String respSrch = respondIDstr;
                    if((respSrch.indexOf("CN") != -1))
                        respSrch = ConvertUtils.getCommonName(respondIDstr);
                    if(respSrch.startsWith("byKey: "))
                        respSrch = respSrch.substring("byKey: ".length());
                    int n1 = respSrch.indexOf(',');
                    if(n1 > 0)
                        respSrch = respSrch.substring(0, n1);
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Search not cert by: " + respSrch);
                    // TODO: get multiple certs
                    lNotCerts = getNotaryCerts(respSrch, null /*ddocRespCertNr*/);
                }
                if(lNotCerts == null || lNotCerts.length == 0)
                    throw new DigiDocException(DigiDocException.ERR_OCSP_RECPONDER_NOT_TRUSTED,
                            "No certificate for responder: \'" + respondIDstr + "\' found in local certificate store!", null);
                boolean bOk = false;
                for(int j = 0; (lNotCerts != null) && (j < lNotCerts.length) && !bOk; j++) {
                    X509Certificate cert = lNotCerts[j];
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Verify using responders cert: " +
                                ((cert != null) ? ConvertUtils.getCommonName(cert.getSubjectDN().getName()) + " nr: " + cert.getSerialNumber().toString() : "NULL"));
                    if(cert != null) {
                        X509CertificateHolder ch = new X509CertificateHolder(cert.getEncoded());
                        bOk = isSignatureValid(basResp, new JcaContentVerifierProviderBuilder().setProvider("BC").build(ch));
                    } else bOk = false;
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("OCSP resp: " + ((basResp != null) ? responderIDtoString(basResp) : "NULL") +
                                " verify using: " + ((cert != null) ? ConvertUtils.getCommonName(cert.getSubjectDN().getName()) : "NULL") +
                                " verify: " + bOk);
                }
                if(bOk) {
                    CertValue cvOcsp = sig.getCertValueOfType(CertValue.CERTVAL_TYPE_RESPONDER);
                    if(cvOcsp != null) {
                        X509Certificate rCert = cvOcsp.getCert();
                        if(rCert != null) {
                            X509CertificateHolder ch = new X509CertificateHolder(rCert.getEncoded());
                            bOk = isSignatureValid(basResp, new JcaContentVerifierProviderBuilder().setProvider("BC").build(ch));
                            if(m_logger.isDebugEnabled())
                                m_logger.debug("OCSP resp: " + ((basResp != null) ? responderIDtoString(basResp) : "NULL") +
                                        " verify using cert in xml: " + ConvertUtils.getCommonName(rCert.getSubjectDN().getName()) +
                                        " verify: " + bOk);
                        }
                    }
                }
                if(!bOk)
                    throw new DigiDocException(DigiDocException.ERR_OCSP_VERIFY, "OCSP verification error!", null);
            } catch (Exception ex) {
                m_logger.error("Signature verification error: " + ex);
                ex.printStackTrace();
                DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_VERIFY);
            }
            try{
                String ocspResponderCommonName = ConvertUtils.getCommonName(responderIDtoString(basResp));
                List<String> allowedOcspProviders = ConfigManager.instance().getAllowedOcspProviders();
                if(!allowedOcspProviders.contains(ocspResponderCommonName)) {
                    throw new DigiDocException(DigiDocException.ERR_OCSP_RESPONDER_TM, "OCSP Responder does not meet TM requirements", null);
                }

            }catch (Exception ex) {
                DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_RESPONDER_TM);
            }

            // done't care about SingleResponses because we have
            // only one response and the whole response was successfull
            // but we should verify that the nonce hasn't changed
            // calculate the nonce
            if(m_logger.isDebugEnabled())
                m_logger.debug("Verif sig: " + sig.getId() + " format: " + sig.getSignedDoc().getFormat() + " nonce policy: " + sig.hasBdoc2NoncePolicy());
            boolean ok = true;
            if(sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_SK_XML) ||
                    sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML)) {
                byte[] nonce1 = SignedDoc.digestOfType(sig.getSignatureValue().getValue(), SignedDoc.SHA1_DIGEST_TYPE);
                byte[] nonce2 = getNonce(basResp, sig.getSignedDoc());
                if(nonce1 == null || nonce2 == null || nonce1.length != nonce2.length)
                    ok = false;
                for(int i = 0; (nonce1 != null) && (nonce2 != null) && (i < nonce1.length) && (i < nonce2.length); i++)
                    if(nonce1[i] != nonce2[i])
                        ok = false;
                // TODO: investigate further
                if(!ok && sig.getSignedDoc() != null) {
                    if(m_logger.isDebugEnabled()) {
                        m_logger.debug("SigVal\n---\n" + Base64Util.encode(sig.getSignatureValue().getValue()) +
                                "\n---\nOCSP\n---\n" + Base64Util.encode(not.getOcspResponseData()) + "\n---\n");
                        m_logger.debug("DDOC ver: " + sig.getSignedDoc().getVersion() +
                                " SIG: " + sig.getId() + " NOT: " + not.getId() +
                                " Real nonce: " + ((nonce2 != null) ? Base64Util.encode(nonce2, 0) : "NULL") + " noncelen: " + ((nonce2 != null) ? nonce2.length : 0)
                                + " SigVal hash: " + ((nonce1 != null) ? Base64Util.encode(nonce1, 0) : "NULL")
                                + " SigVal hash hex: " + ((nonce1 != null) ? ConvertUtils.bin2hex(nonce1) : "NULL")
                                + " svlen: " + ((nonce1 != null) ? nonce1.length : 0));
                    }
                    throw new DigiDocException(DigiDocException.ERR_OCSP_NONCE,
                            "OCSP response's nonce doesn't match the requests nonce!", null);
                }
            }
            if(m_logger.isDebugEnabled())
                m_logger.debug("Verify not: " + not.getId());
            checkCertStatus(sig, basResp);
            not.setProducedAt(basResp.getProducedAt());
            not.setResponderId(responderIDtoString(basResp));
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_PARSE);
        }
        return not;
    }


    /**
     * Get String represetation of ResponderID
     * @param basResp
     * @return stringified responder ID
     */
    private String responderIDtoString(BasicOCSPResp basResp) {
        if(basResp != null) {
            ResponderID respid = basResp.getResponderId().toASN1Primitive();
            Object o = ((DERTaggedObject)respid.toASN1Object()).getObject();
            if(o instanceof org.bouncycastle.asn1.DEROctetString) {
                org.bouncycastle.asn1.DEROctetString oc = (org.bouncycastle.asn1.DEROctetString)o;
                return "byKey: " + SignedDoc.bin2hex(oc.getOctets());
            } else {
                X509Name name = new X509Name((ASN1Sequence)o);
                return "byName: " + name.toString();
            }
        }
        else
            return null;
    }

    /**
     * Method to get NONCE array from responce
     * @param basResp
     * @return OCSP nonce value
     */
    private byte[] getNonce(BasicOCSPResp basResp, SignedDoc sdoc) {
        if(basResp != null) {
            try {
                byte[] nonce2 = null;
                Set extOids = basResp.getNonCriticalExtensionOIDs();
                boolean bAsn1=false;
                String sType = null;
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Nonce exts: " + extOids.size());
                if(extOids.size() >= 1) {
                    Extension ext = basResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
                    if(ext != null) {
                        if(m_logger.isDebugEnabled())
                            m_logger.debug("Ext: " + ext.getExtnId() + " val-len: " + ((ext.getExtnValue() != null) ? ext.getExtnValue().getOctets().length : 0));
                        if(ext.getExtnValue() != null && ext.getExtnValue().getOctets() != null && ext.getExtnValue().getOctets().length == 20) {
                            nonce2 = ext.getExtnValue().getOctets();
                            m_logger.debug("Raw nonce len: " + ((nonce2 != null) ? nonce2.length : 0));
                        } else {
                            ASN1Encodable extObj = ext.getParsedValue();
                            nonce2 = extObj.toASN1Primitive().getEncoded();
                        }
                    }
                }
                boolean bCheckOcspNonce = ConfigManager.instance().getBooleanProperty("CHECK_OCSP_NONCE", false);
                if(sdoc != null && sdoc.getFormat() != null && sdoc.getFormat().equals(SignedDoc.FORMAT_SK_XML)) bCheckOcspNonce = false;
                if(m_logger.isDebugEnabled() && nonce2 != null)
                    m_logger.debug("Nonce hex: " + ConvertUtils.bin2hex(nonce2) + " b64: " + Base64Util.encode(nonce2) + " len: " + nonce2.length + " asn1: " + bAsn1);
                if(sdoc != null && sdoc.getFormat() != null && sdoc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML) || sdoc == null) {
                    if(nonce2 != null && nonce2.length == 22) { //  nonce2[0] == V_ASN1_OCTET_STRING
                        byte[] b = new byte[20];
                        System.arraycopy(nonce2, nonce2.length - 20, b, 0, 20);
                        nonce2 = b;
                        bAsn1=true;
                        sType = "ASN1-NONCE";
                    }
                }
                if(m_logger.isDebugEnabled() && nonce2 != null)
                    m_logger.debug("Nonce hex: " + ConvertUtils.bin2hex(nonce2) + " b64: " + Base64Util.encode(nonce2) + " len: " + nonce2.length + " type: " + sType);
                else
                    m_logger.debug("No nonce");
                if(!bAsn1 && bCheckOcspNonce) {
                    throw new DigiDocException(DigiDocException.ERR_OCSP_NONCE,
                            "Invalid nonce: " + ((nonce2 != null) ? ConvertUtils.bin2hex(nonce2) + " length: " + nonce2.length : "NO-NONCE") + "!", null);
                }
                return nonce2;
            } catch(Exception ex) {
                m_logger.error("Error reading ocsp nonce: " + ex);
                ex.printStackTrace();
                return null;
            }
        }
        else
            return null;
    }

    /**
     * Method for creating CertificateID for OCSP request
     * @param signersCert
     * @param caCert
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws CertificateEncodingException
     */
    private CertificateID creatCertReq(X509Certificate signersCert, X509Certificate caCert)
            throws Exception
    {
        DigestCalculatorProvider dcp = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        X509CertificateHolder caCertHolder = new X509CertificateHolder(caCert.getEncoded());
        return new CertificateID(dcp.get(CertificateID.HASH_SHA1), caCertHolder, signersCert.getSerialNumber());
    }

    /**
     * initializes the implementation class
     */
    public void init()
            throws DigiDocException
    {
        FileInputStream fi = null;
        try {
            String proxyHost = ConfigManager.instance().
                    getProperty("DIGIDOC_PROXY_HOST");
            String proxyPort = ConfigManager.instance().
                    getProperty("DIGIDOC_PROXY_PORT");
            if(proxyHost != null && proxyPort != null) {
                System.setProperty("http.proxyHost", proxyHost);
                System.setProperty("http.proxyPort", proxyPort);
            }
            // only need this if we must sign the requests
            Provider prv = (Provider)Class.forName(ConfigManager.
                    instance().getProperty("DIGIDOC_SECURITY_PROVIDER")).newInstance();
            Security.addProvider(prv);
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_NOT_FAC_INIT);
        } finally {
            if(fi != null) {
                try {
                    fi.close();
                } catch(Exception ex2) {
                    m_logger.error("Error closing input stream: " + ex2);
                }
            }
        }
    }

}