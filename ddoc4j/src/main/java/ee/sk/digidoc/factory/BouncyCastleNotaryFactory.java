package ee.sk.digidoc.factory;

import ee.sk.digidoc.*;
import ee.sk.digidoc.Signature;
import ee.sk.utils.ConfigManager;
import ee.sk.utils.ConvertUtils;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.URL;
import java.net.URLConnection;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Random;
import java.util.Set;

public class BouncyCastleNotaryFactory implements NotaryFactory
{
    /** NONCE extendion oid */
    public static final String nonceOid = "1.3.6.1.5.5.7.48.1.2";
    /** cert used to sign to all OCSP requests */
    private X509Certificate m_signCert;
    /** key used to sign all OCSP requests */
    private PrivateKey m_signKey;
    private boolean m_bSignRequests;
    private Logger m_logger = null;
    private static final Random RANDOM_GENERATOR = new SecureRandom();

    /** Creates new BouncyCastleNotaryFactory */
    public BouncyCastleNotaryFactory() {
        m_signCert = null;
        m_signKey = null;
        m_bSignRequests = false;
        m_logger = LoggerFactory.getLogger(BouncyCastleNotaryFactory.class);
    }

    private byte[] createRandomBytes(int byteCount)
    {
        byte[] randomBytes = new byte[byteCount];
        RANDOM_GENERATOR.nextBytes(randomBytes);
        return randomBytes;
    }

    /**
     * Returns the n-th OCSP responders certificate if there are many
     * certificates registered for this responder.
     * @param responderCN responder-id's CN
     * @param idx certificate index starting with 0
     * @returns OCSP responders certificate or null if not found
     */
    /*public X509Certificate findNotaryCertByIndex(String responderCN, int idx)
    {
    	X509Certificate cert = null;

    	if(m_logger.isInfoEnabled())
    		m_logger.info("Find responder for: " + responderCN + " index: " + idx);
    	String certKey = null;
    	if(idx == 0)
    		certKey = responderCN;
    	else
    		certKey = responderCN + "-" + idx;
    	if(m_logger.isInfoEnabled())
        	m_logger.info("Searching responder: " + certKey);
    	cert = (X509Certificate)m_ocspCerts.get(certKey);
    	if(m_logger.isInfoEnabled() && cert != null && certKey != null)
    		m_logger.info("Selecting cert " + cert.getSerialNumber().toString() +
    				" key: " + certKey + " valid until: " + cert.getNotAfter().toString());
    	return cert;
    }*/

    /**
     * Returns the OCSP responders certificate
     * @param responderCN responder-id's CN
     * @param specificCertNr specific cert number that we search.
     * If this parameter is null then the newest cert is seleced (if many exist)
     * @returns OCSP responders certificate
     */
    public X509Certificate getNotaryCert(String responderCN, String specificCertNr)

    {
        try {
            TrustServiceFactory tslFac = ConfigManager.instance().getTslFactory();
            return tslFac.findOcspByCN(responderCN, true);
        } catch(Exception ex) {
            m_logger.error("Error searching responder cert for: " + responderCN + " - " + ex);
        }
        return null;
    }

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

    /**
     * Returns the OCSP responders CA certificate
     * @param responderCN responder-id's CN
     * @returns OCSP responders CA certificate
     */
    public X509Certificate getCACert(String responderCN)
    {
        try {
            TrustServiceFactory tslFac = ConfigManager.instance().getTslFactory();
            X509Certificate cert = tslFac.findOcspByCN(responderCN, true);
            if(cert != null)
                return tslFac.findCaForCert(cert, true, null);
        } catch(Exception ex) {
            m_logger.error("Error searching responder ca cert for: " + responderCN + " - " + ex);
        }
        return null;
    }


    /**
     * Get confirmation from AS Sertifitseerimiskeskus
     * by creating an OCSP request and parsing the returned
     * OCSP response
     * @param nonce signature nonce
     * @param signersCert signature owners cert
     * @param notId new id for Notary object
     * @param httpFrom HTTP_FROM header value (optional)
     * @returns Notary object
     * @deprecated use Notary getConfirmation(Signature sig, byte[] nonce, X509Certificate signersCert, X509Certificate caCert,
     *   X509Certificate notaryCert, String notId, String ocspUrl, String httpFrom, String format, String formatVer)
     */
    public Notary getConfirmation(byte[] nonce,
                                  X509Certificate signersCert, String notId, String httpFrom)
            throws DigiDocException
    {
        TrustServiceFactory tslFac = ConfigManager.instance().getTslFactory();
        X509Certificate caCert = tslFac.findCaForCert(signersCert, true, null);
        X509Certificate ocspCert = tslFac.findOcspByCN(ConvertUtils.getCommonName(ConvertUtils.convX509Name(signersCert.getIssuerX500Principal())), true);
        return getConfirmation(nonce, signersCert, caCert, ocspCert, notId, httpFrom);
    }

    /**
     * Get confirmation from AS Sertifitseerimiskeskus
     * by creating an OCSP request and parsing the returned
     * OCSP response. Used by DigiDocGenFactory.
     * @param sig Signature object
     * @param nonce signature nonce
     * @param signersCert signature owners cert
     * @param caCert CA cert for this signer
     * @param notaryCert notarys own cert
     * @param notId new id for Notary object
     * @param httpFrom HTTP_FROM header value (optional)
     * @returns Notary object
     */
    public Notary getConfirmation(Signature sig, byte[] nonce,
                                  X509Certificate signersCert, X509Certificate caCert,
                                  X509Certificate notaryCert, String notId, String ocspUrl,
                                  String httpFrom, String format, String formatVer)
            throws DigiDocException
    {
        Notary not = null;
        OCSPReq req = null;
        OCSPResp resp = null;
        try {
            if(m_logger.isDebugEnabled())
                m_logger.debug("getConfirmation, nonce " + Base64Util.encode(nonce, 0) +
                        " cert: " + ((signersCert != null) ? signersCert.getSerialNumber().toString() : "NULL") +
                        " CA: " + ((caCert != null) ? caCert.getSerialNumber().toString() : "NULL") +
                        " responder: " + ((notaryCert != null) ? notaryCert.getSerialNumber().toString() : "NULL") +
                        " notId: " + notId + " signRequest: " + m_bSignRequests +
                        " url: " + ocspUrl);
            if(m_logger.isDebugEnabled()) {
                m_logger.debug("Check cert: " + ((signersCert != null) ? signersCert.getSubjectDN().getName() : "NULL"));
                m_logger.debug("Check CA cert: " + ((caCert != null) ? caCert.getSubjectDN().getName() : "NULL"));
            }
            // create the request - sign the request if necessary
            req = createOCSPRequest(nonce, signersCert, caCert, m_bSignRequests, (sig != null && sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC)));
            //debugWriteFile("req.der", req.getEncoded());
            if(m_logger.isDebugEnabled())
                m_logger.debug("REQUEST:\n" + Base64Util.encode(req.getEncoded(), 0));
            // send it
            resp = sendRequestToUrl(req, ocspUrl, httpFrom, format, formatVer);
            //debugWriteFile("resp.der", resp.getEncoded());
            if(m_logger.isDebugEnabled())
                m_logger.debug("RESPONSE:\n" + ((resp != null) ? Base64Util.encode(resp.getEncoded(), 0) : "NULL"));
            // check response status
            if(resp != null)
                verifyRespStatus(resp);
            // check the result
            not = parseAndVerifyResponse(sig, notId, signersCert, resp, nonce, notaryCert, caCert);
            if(m_logger.isDebugEnabled())
                m_logger.debug("Confirmation OK!");
        } catch(DigiDocException ex) {
            m_logger.error("Error receiving OCSP confirmation: " + ex + " nonce: " + ConvertUtils.bin2hex(nonce) + " len: " + nonce.length);
            try {
                byte[] b = req.getEncoded();
                m_logger.error("OCSP req: " + ConvertUtils.bin2hex(b) + " len: " + b.length);
                b = resp.getEncoded();
                m_logger.error("OCSP req: " + ConvertUtils.bin2hex(b) + " len: " + b.length);
            } catch(Exception ex2) {
                m_logger.error("Error converting OCSP info: " + ex2);
            }
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_GET_CONF);
        }
        return not;
    }


    /**
     * Get confirmation from AS Sertifitseerimiskeskus
     * by creating an OCSP request and parsing the returned
     * OCSP response
     * @param nonce signature nonce
     * @param signersCert signature owners cert
     * @param caCert CA cert for this signer
     * @param notaryCert notarys own cert
     * @param notId new id for Notary object
     * @returns Notary object
     * @deprecated use Notary getConfirmation(Signature sig, byte[] nonce, X509Certificate signersCert, X509Certificate caCert,
     *   X509Certificate notaryCert, String notId, String ocspUrl, String httpFrom, String format, String formatVer)
     */
    public Notary getConfirmation(byte[] nonce,
                                  X509Certificate signersCert, X509Certificate caCert,
                                  X509Certificate notaryCert, String notId, String httpFrom) // TODO: remove param notaryCert
            throws DigiDocException
    {
        return getConfirmation(null, nonce,
                signersCert, caCert,
                notaryCert, notId, ConfigManager.instance().
                        getProperty("DIGIDOC_OCSP_RESPONDER_URL"), httpFrom, null, null);
    }



    /**
     * Get confirmation from AS Sertifitseerimiskeskus
     * by creating an OCSP request and parsing the returned
     * OCSP response
     * @param sig Signature object.
     * @param signersCert signature owners cert
     * @param caCert CA cert for this signer
     * @returns Notary object
     * @deprecated use Notary getConfirmation(Signature sig, byte[] nonce, X509Certificate signersCert, X509Certificate caCert,
     *   X509Certificate notaryCert, String notId, String ocspUrl, String httpFrom, String format, String formatVer)
     */
    public Notary getConfirmation(Signature sig,
                                  X509Certificate signersCert, X509Certificate caCert)
            throws DigiDocException
    {
        Notary not = null;
        if(sig == null) {
            throw new DigiDocException(DigiDocException.ERR_INPUT_VALUE, "Signature is NULL for ocsp request!", null);
        }
        try {
            String notId = sig.getId().replace('S', 'N');
            // calculate the nonce
            // test if it works with sha256
            byte[] nonce = SignedDoc.digestOfType(sig.getSignatureValue().getValue(),
                    sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC) ? SignedDoc.SHA256_DIGEST_TYPE : SignedDoc.SHA1_DIGEST_TYPE);
            X509Certificate notaryCert = null;
            if(sig.getUnsignedProperties() != null)
                notaryCert = sig.getUnsignedProperties().getRespondersCertificate();
            // check the result
            // TODO: select correct ocsp url
            not = getConfirmation(sig, nonce, signersCert, caCert, notaryCert, notId,
                    ConfigManager.instance().getProperty("DIGIDOC_OCSP_RESPONDER_URL"),
                    sig.getHttpFrom(), sig.getSignedDoc().getFormat(), sig.getSignedDoc().getVersion());
            // add cert to signature
            if(notaryCert == null && sig != null && sig.getUnsignedProperties() != null) {
                OCSPResp resp = new OCSPResp(not.getOcspResponseData());
                if(resp != null && resp.getResponseObject() != null) {
                    String respId = responderIDtoString((BasicOCSPResp)resp.getResponseObject());
                    TrustServiceFactory tslFac = ConfigManager.instance().getTslFactory();
                    notaryCert = tslFac.findOcspByCN(SignedDoc.getCommonName(respId), true); // must use local store here since ocsp certs are not in tsl
                    if(notaryCert != null)
                        sig.getUnsignedProperties().setRespondersCertificate(notaryCert);
                    ee.sk.digidoc.CertID cid = new ee.sk.digidoc.CertID(sig, notaryCert, ee.sk.digidoc.CertID.CERTID_TYPE_RESPONDER);
                    sig.addCertID(cid);
                    cid.setUri("#" + sig.getId() + "-RESPONDER_CERT");
                }
            }
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_GET_CONF);
        }
        return not;
    }

    /**
     * Get confirmation from AS Sertifitseerimiskeskus
     * by creating an OCSP request and parsing the returned
     * OCSP response. This getConfirmation() is used by DigiDocGenfactory.
     * @param sig Signature object.
     * @param signersCert signature owners cert
     * @param caCert CA cert for this signer
     * @param notaryCert OCSP responders cert
     * @param ocspUrl OCSP responders url
     * @returns Notary object
     */
    public Notary getConfirmation(Signature sig,
                                  X509Certificate signersCert, X509Certificate caCert,
                                  X509Certificate notaryCert, String ocspUrl)
            throws DigiDocException
    {

        Notary not = null;
        if(sig == null) {
            throw new DigiDocException(DigiDocException.ERR_INPUT_VALUE, "Signature is NULL for ocsp request!", null);
        }
        try {

            String notId = sig.getId().replace('S', 'N');
            // calculate the nonce
            // TODO: sha256?
            //byte[] nonce = SignedDoc.digest(sig.getSignatureValue().getValue());
            byte[] nonce = SignedDoc.digestOfType(sig.getSignatureValue().getValue(),
                    sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC) ? SignedDoc.SHA256_DIGEST_TYPE : SignedDoc.SHA1_DIGEST_TYPE);
            if(notaryCert == null && sig.getUnsignedProperties() != null)
                notaryCert = sig.getUnsignedProperties().getRespondersCertificate();
            // check the result

            not = getConfirmation(sig, nonce, signersCert, caCert, notaryCert, notId, ocspUrl,
                    sig.getHttpFrom(), sig.getSignedDoc().getFormat(), sig.getSignedDoc().getVersion());
            if(not != null && sig.getUnsignedProperties() != null)
                sig.getUnsignedProperties().setNotary(not);
            // add cert to signature
            if(notaryCert == null && sig != null && sig.getUnsignedProperties() != null && sig.getUnsignedProperties().getNotary() != null) {
                OCSPResp resp = new OCSPResp(sig.getUnsignedProperties().getNotary().getOcspResponseData());
                if(resp != null && resp.getResponseObject() != null && notaryCert == null) {
                    String respId = responderIDtoString((BasicOCSPResp)resp.getResponseObject());
                    TrustServiceFactory tslFac = ConfigManager.instance().getTslFactory();
                    notaryCert = tslFac.findOcspByCN(ConvertUtils.getCommonName(respId), true);
                    if(notaryCert != null) {
                        sig.getUnsignedProperties().setRespondersCertificate(notaryCert);
                        ee.sk.digidoc.CertID cid = new ee.sk.digidoc.CertID(sig, notaryCert, ee.sk.digidoc.CertID.CERTID_TYPE_RESPONDER);
                        sig.addCertID(cid);
                        cid.setUri("#" + sig.getId() + "-RESPONDER_CERT");
                    }
                }
            }
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_GET_CONF);
        }
        return not;
    }

    /**
     * Get confirmation from AS Sertifitseerimiskeskus
     * by creating an OCSP request and parsing the returned
     * OCSP response. CA and reponders certs are read
     * using paths in the config file or maybe from
     * a keystore etc.
     * @param sig Signature object
     * @param signersCert signature owners cert
     * @returns Notary object
     * @deprecated use Notary getConfirmation(Signature sig, byte[] nonce, X509Certificate signersCert, X509Certificate caCert,
     *   X509Certificate notaryCert, String notId, String ocspUrl, String httpFrom, String format, String formatVer)
     */
    public Notary getConfirmation(Signature sig, X509Certificate signersCert)
            throws DigiDocException
    {
        String notId = sig.getId().replace('S', 'N');
        //byte[] nonce = SignedDoc.digest(sig.getSignatureValue().getValue()); // sha256?
        byte[] nonce = SignedDoc.digestOfType(sig.getSignatureValue().getValue(),
                sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC) ? SignedDoc.SHA256_DIGEST_TYPE : SignedDoc.SHA1_DIGEST_TYPE);
        TrustServiceFactory tslFac = ConfigManager.instance().getTslFactory();
        X509Certificate caCert = tslFac.findCaForCert(signersCert, true, null);
        X509Certificate ocspCert = tslFac.findOcspByCN(ConvertUtils.getCommonName(ConvertUtils.convX509Name(signersCert.getIssuerX500Principal())), true);
        return getConfirmation(nonce, signersCert, caCert, ocspCert, notId, sig.getHttpFrom());
    }



    private String composeHttpFrom()
    {
        // set HTTP_FROM to some value
        String sFrom = null;
        try {
            NetworkInterface ni = null;
            Enumeration eNi = NetworkInterface.getNetworkInterfaces();
            if(eNi != null && eNi.hasMoreElements())
                ni = (NetworkInterface)eNi.nextElement();
            if(ni != null) {
                InetAddress ia = null;
                Enumeration eA = ni.getInetAddresses();
                if(eA != null && eA.hasMoreElements())
                    ia = (InetAddress)eA.nextElement();
                if(ia != null)
                    sFrom = ia.getHostAddress();
                if(m_logger.isDebugEnabled())
                    m_logger.debug("FROM: " + sFrom);
            }
        } catch(Exception ex2) {
            m_logger.error("Error finding ip-adr: " + ex2);
        }
        return sFrom;
    }

    /**
     * Verifies the certificate by creating an OCSP request
     * and sending it to SK server.
     * @param cert certificate to verify
     * @param httpFrom HTTP_FROM optional argument
     * @throws DigiDocException if the certificate is not valid
     * @return ocsp response
     * @deprecated not thorougly tested
     */
    public OCSPResp checkCertificate(X509Certificate cert)
            throws DigiDocException
    {
        return checkCertificate(cert, composeHttpFrom());
    }

    /**
     * Verifies the certificate by creating an OCSP request
     * and sending it to SK server.
     * @param cert certificate to verify
     * @param httpFrom HTTP_FROM optional argument
     * @throws DigiDocException if the certificate is not valid
     * @return ocsp response
     * @deprecated not thorougly tested
     */
    public OCSPResp checkCertificate(X509Certificate cert, String httpFrom)
            throws DigiDocException
    {
        OCSPResp resp = null;
        try {
            // create the request
            DigiDocFactory ddocFac = ConfigManager.instance().getDigiDocFactory();
            TrustServiceFactory tslFac = ConfigManager.instance().getTslFactory();
            X509Certificate caCert = tslFac.findCaForCert(cert, true, null);
            if(m_logger.isDebugEnabled()) {
                m_logger.debug("Find CA for: " + SignedDoc.getCommonName(ConvertUtils.convX509Name(cert.getIssuerX500Principal())));
                m_logger.debug("Check cert: " + cert.getSubjectDN().getName());
                m_logger.debug("Check CA cert: " + caCert.getSubjectDN().getName());
            }
            byte[] nonce1 = SignedDoc.digest(createRandomBytes(32)); // sha256?
            OCSPReq req = createOCSPRequest(nonce1, cert, caCert, m_bSignRequests, false);
            //debugWriteFile("req1.der", req.getEncoded());
            if(m_logger.isDebugEnabled()) {
                m_logger.debug("Sending ocsp request: " + req.getEncoded().length + " bytes");
                m_logger.debug("REQUEST:\n" + Base64Util.encode(req.getEncoded(), 0));
            }
            // send it
            String ocspUrl = tslFac.findOcspUrlForCert(cert, 0, true);
            resp = sendRequestToUrl(req, ocspUrl, httpFrom, null, null);
            //debugWriteFile("resp1.der", resp.getEncoded());
            if(m_logger.isDebugEnabled()) {
                m_logger.debug("Got ocsp response: " + ((resp != null) ? resp.getEncoded().length : 0) + " bytes");
                if(resp != null)
                    m_logger.debug("RESPONSE:\n" + Base64Util.encode(resp.getEncoded(), 0));
            }
            // check response status
            verifyRespStatus(resp);
            // now read the info from the response
            BasicOCSPResp basResp =
                    (BasicOCSPResp)resp.getResponseObject();

            byte[] nonce2 = getNonce(basResp, null);
            if(m_logger.isDebugEnabled())
                m_logger.debug("Nonce1: " + ((nonce1 != null) ? ConvertUtils.bin2hex(nonce1) + " len: " + nonce1.length : "NULL") +
                        " nonce2: " + ((nonce2 != null) ? ConvertUtils.bin2hex(nonce2) + " len: " + nonce2.length : "NULL"));
            if(!SignedDoc.compareDigests(nonce1, nonce2))
                throw new DigiDocException(DigiDocException.ERR_OCSP_UNSUCCESSFULL,
                        "Invalid nonce value! Possible replay attack!", null);
            // verify the response
            try {
                String respId = responderIDtoString(basResp);
                X509Certificate notaryCert = getNotaryCert(ConvertUtils.getCommonName(respId), null);
                boolean bOk = false;
                if(notaryCert != null) {
                    X509CertificateHolder ch = new X509CertificateHolder(notaryCert.getEncoded());
                    bOk = basResp.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(ch));
                } else
                    throw new DigiDocException(DigiDocException.ERR_OCSP_VERIFY,
                            "Responder cert not found for: " + respId, null);
                if(!bOk)
                    throw new DigiDocException(DigiDocException.ERR_OCSP_VERIFY,
                            "OCSP verification error!", null);
            } catch (Exception ex) {
                m_logger.error("OCSP Signature verification error!!!", ex);
                DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_VERIFY);
            }
            // check the response about this certificate
            checkCertStatus(cert, basResp, caCert);

        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_GET_CONF);
        }
        return resp;
    }


    /**
     * Verifies the certificate by creating an OCSP request
     * and sending it to ocsp server.
     * @param cert certificate to verify
     * @param caCert CA certificate
     * @param url OCSP responder url
     * @param bosNonce buffer to return generated nonce
     * @param sbRespId buffer to return responderId field
     * @param bosReq buffer to return ocsp request
     * @param httpFrom http_from atribute
     * @throws DigiDocException if the certificate is not valid
     * @deprecated not thorougly tested
     */
    public OCSPResp sendCertOcsp(X509Certificate cert, X509Certificate caCert, String url,
                                 ByteArrayOutputStream bosNonce, StringBuffer sbRespId,
                                 ByteArrayOutputStream bosReq, String httpFrom)
            throws DigiDocException
    {
        try {
            OCSPResp resp = null;
            // create the request
            if(m_logger.isDebugEnabled()) {
                m_logger.debug("Find CA for: " + SignedDoc.getCommonName(ConvertUtils.convX509Name(cert.getIssuerX500Principal())));
                m_logger.debug("Check cert: " + cert.getSubjectDN().getName());
                m_logger.debug("Check CA cert: " + caCert.getSubjectDN().getName());
            }
            byte[] nonce1 = SignedDoc.digest(createRandomBytes(32)); //sha256?
            //byte[] nonce1 = SignedDoc.digestOfType(strTime.getBytes(),
            //		sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC) ? SignedDoc.SHA256_DIGEST_TYPE : SignedDoc.SHA1_DIGEST_TYPE);

            bosNonce.write(nonce1);
            OCSPReq req = createOCSPRequest(nonce1, cert, caCert, false, false);
            //debugWriteFile("req1.der", req.getEncoded());
            if(m_logger.isDebugEnabled()) {
                m_logger.debug("Sending ocsp request: " + req.getEncoded().length + " bytes");
                m_logger.debug("REQUEST:\n" + Base64Util.encode(req.getEncoded(), 0));
            }
            if(req != null && bosReq != null)
                bosReq.write(req.getEncoded());
            // send it
            resp = sendRequestToUrl(req, url, httpFrom, null, null);
            if(resp != null) {
                BasicOCSPResp basResp =
                        (BasicOCSPResp)resp.getResponseObject();
                String sRespId = responderIDtoString(basResp);
                if(sRespId != null)
                    sbRespId.append(sRespId);
            }
            //debugWriteFile("resp1.der", resp.getEncoded());
            if(m_logger.isDebugEnabled()) {
                m_logger.debug("Got ocsp response: " + ((resp != null) ? resp.getEncoded().length : 0) + " bytes");
                if(resp != null)
                    m_logger.debug("RESPONSE:\n" + Base64Util.encode(resp.getEncoded(), 0));
            }

            return resp;
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_GET_CONF);
        }
        return null;
    }

    /**
     * Verifies OCSP response by given responder cert. Checks actual certificate status.
     * @param resp ocsp response
     * @param cert certificate to check
     * @param ocspCert OCSP responders cert
     * @param nonce1 initial nonce value
     * @return true if verified ok
     * @throws DigiDocException
     * @deprecated not thorougly tested
     */
    public boolean checkCertOcsp(OCSPResp resp, X509Certificate cert,
                                 X509Certificate ocspCert, byte[] nonce1, X509Certificate caCert)
            throws DigiDocException
    {
        try {
            // check response status
            verifyRespStatus(resp);
            // now read the info from the response
            BasicOCSPResp basResp =
                    (BasicOCSPResp)resp.getResponseObject();
            byte[] nonce2 = getNonce(basResp, null);
            if(!SignedDoc.compareDigests(nonce1, nonce2))
                throw new DigiDocException(DigiDocException.ERR_OCSP_UNSUCCESSFULL,
                        "Invalid nonce value! Possible replay attack!", null);
            // verify the response
            boolean bOk = false;
            try {
                //String respId = responderIDtoString(basResp);
                X509CertificateHolder ch = new X509CertificateHolder(ocspCert.getEncoded());
                bOk = basResp.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(ch));
            } catch (Exception ex) {
                m_logger.error("OCSP Signature verification error!!!", ex);
                DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_VERIFY);
            }
            // check the response about this certificate
            checkCertStatusWithCa(cert, basResp, caCert);
            return bOk;
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_GET_CONF);
        }
        return false;
    }


    /**
     * Verifies the certificate.
     * @param cert certificate to verify
     * @param bUseOcsp flag: use OCSP to verify cert. (obsolete, false,e.g CRL no longer supported)
     * @throws DigiDocException if the certificate is not valid
     * @deprecated not thorougly tested
     */
    public void checkCertificateOcspOrCrl(X509Certificate cert, boolean bUseOcsp)
            throws DigiDocException
    {
        try {
            // create the request
            TrustServiceFactory tslFac = ConfigManager.instance().getTslFactory();
            X509Certificate caCert = tslFac.findCaForCert(cert, true, null);
            if(m_logger.isDebugEnabled()) {
                m_logger.debug("Find CA for: " + SignedDoc.getCommonName(ConvertUtils.convX509Name(cert.getIssuerX500Principal())));
                m_logger.debug("Check cert: " + cert.getSubjectDN().getName());
                m_logger.debug("Check CA cert: " + caCert.getSubjectDN().getName());
            }
            byte[] nonce1 = SignedDoc.digest(createRandomBytes(32)); // sha256?
            OCSPReq req = createOCSPRequest(nonce1, cert, caCert, m_bSignRequests, false);
            //debugWriteFile("req1.der", req.getEncoded());
            if(m_logger.isDebugEnabled()) {
                m_logger.debug("Sending ocsp request: " + req.getEncoded().length + " bytes");
                m_logger.debug("REQUEST:\n" + Base64Util.encode(req.getEncoded(), 0));
            }
            // send it
            OCSPResp resp = sendRequest(req, null, null, null);
            //debugWriteFile("resp1.der", resp.getEncoded());
            if(m_logger.isDebugEnabled()) {
                m_logger.debug("Got ocsp response: " + resp.getEncoded().length + " bytes");
                m_logger.debug("RESPONSE:\n" + Base64Util.encode(resp.getEncoded(), 0));
            }
            // check response status
            verifyRespStatus(resp);
            // now read the info from the response
            BasicOCSPResp basResp =
                    (BasicOCSPResp)resp.getResponseObject();
            byte[] nonce2 = getNonce(basResp, null);
            if(!SignedDoc.compareDigests(nonce1, nonce2))
                throw new DigiDocException(DigiDocException.ERR_OCSP_UNSUCCESSFULL,
                        "Invalid nonce value! Possible replay attack!", null);
            // verify the response
            try {
                String respId = responderIDtoString(basResp);
                X509Certificate notaryCert = getNotaryCert(SignedDoc.getCommonName(respId), null);
                X509CertificateHolder ch = new X509CertificateHolder(notaryCert.getEncoded());
                boolean bOk = basResp.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(ch));
                if(!bOk) {
                    m_logger.error("OCSP Signature verification error!!!");
                    throw new DigiDocException(DigiDocException.ERR_OCSP_VERIFY, "OCSP Signature verification error!!!", null );
                }
            } catch (Exception ex) {
                m_logger.error("OCSP Signature verification error!!!", ex);
                DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_VERIFY);
            }
            // check the response about this certificate
            checkCertStatus(cert, basResp, caCert);
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_GET_CONF);
        }
    }

    /**
     * Check the response and parse it's data.
     * @param sig Signature object
     * @param resp OCSP response
     * @param nonce1 nonve value used for request
     * @param notaryCert notarys own cert
     * @returns Notary object
     */
    private Notary parseAndVerifyResponse(Signature sig, OCSPResp resp,
                                          byte[] nonce1/*, X509Certificate notaryCert*/)
            throws DigiDocException
    {
        String notId = sig.getId().replace('S', 'N');
        X509Certificate sigCert = sig.getKeyInfo().getSignersCertificate();
        return parseAndVerifyResponse(sig, notId, sigCert, resp, nonce1, null, null);
    }


    /**
     * Check the response and parse it's data
     * @param sig Signature object
     * @param notId new id for Notary object
     * @param signersCert signature owners certificate
     * @param resp OCSP response
     * @param nonce1 nonve value used for request
     * @returns Notary object
     */
    private Notary parseAndVerifyResponse(Signature sig, String notId,
                                          X509Certificate signersCert, OCSPResp resp, byte[] nonce1, X509Certificate notaryCert, X509Certificate caCert)
            throws DigiDocException
    {
        Notary not = null;
        // check the result
        if(resp == null) {
            throw new DigiDocException(DigiDocException.ERR_OCSP_UNSUCCESSFULL,
                    "OCSP response is null!", null);
        }
        if(resp.getStatus() != OCSPRespBuilder.SUCCESSFUL) {
            if (resp.getStatus() == OCSPRespBuilder.UNAUTHORIZED){
                throw new DigiDocException(DigiDocException.ERR_OCSP_UNAUTHORIZED,
                        "OCSP response unauthorized! ", null);
            } else {
                throw new DigiDocException(DigiDocException.ERR_OCSP_UNSUCCESSFULL,
                        "OCSP response unsuccessfull!", null);
            }
        }
        try {
            // now read the info from the response
            BasicOCSPResp basResp =
                    (BasicOCSPResp)resp.getResponseObject();
            // find real notary cert suitable for this response
            String respId = responderIDtoString(basResp);
            if(notaryCert == null) {
                String nCn = ConvertUtils.getCommonName(respId);
            	/*int n = nCn.indexOf(',');
            	if(n > 0)
            		nCn = nCn.substring(0, n); */ // fix CN search
                notaryCert = getNotaryCert(nCn, null);
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Find notary cert: " + nCn + " found: " + ((notaryCert != null) ? "OK" : "NULL"));
            }
            if(notaryCert == null) {
                throw new DigiDocException(DigiDocException.ERR_OCSP_VERIFY, "Notary cert not found for: " + respId, null);
            }
            // verify the response
            boolean bOk = false;
            try {
                X509CertificateHolder ch = new X509CertificateHolder(notaryCert.getEncoded());
                bOk = isSignatureValid(basResp, new JcaContentVerifierProviderBuilder().setProvider("BC").build(ch));
            } catch (Exception ex) {
                m_logger.error("OCSP Signature verification error!!!", ex);
                DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_VERIFY);
            }
            if(!bOk) {
                m_logger.error("OCSP Signature verification error!!!");
                throw new DigiDocException(DigiDocException.ERR_OCSP_VERIFY, "OCSP Signature verification error!!!", null);
            }
            if(m_logger.isDebugEnabled() && notaryCert != null)
                m_logger.debug("Using responder cert: " + notaryCert.getSerialNumber().toString());
            // done't care about SingleResponses because we have
            // only one response and the whole response was successfull
            // but we should verify that the nonce hasn't changed
            byte[] nonce2 = getNonce(basResp, (sig != null) ? sig.getSignedDoc() : null);
            boolean ok = true;
            if(nonce1 == null || nonce2 == null || nonce1.length != nonce2.length)
                ok = false;
            for(int i = 0; (nonce1 != null) && (nonce2 != null) && (i < nonce1.length); i++)
                if(nonce1[i] != nonce2[i])
                    ok = false;
            if(m_logger.isDebugEnabled() && notaryCert != null)
                m_logger.debug("NONCE ddoc: " + ((sig != null) ? sig.getSignedDoc().getFormat() : "NULL") + " ok: " + ok);
            if(!ok && sig != null) {
                m_logger.error("DDOC ver: " + sig.getSignedDoc().getVersion() + " SIG: " + sig.getId() +
                        " Real nonce: " + Base64Util.encode(nonce2, 0)
                        + " SigVal hash: " + Base64Util.encode(nonce1, 0)
                        + " SigVal hash hex: " + ConvertUtils.bin2hex(nonce1));
                throw new DigiDocException(DigiDocException.ERR_OCSP_NONCE,
                        "OCSP response's nonce doesn't match the requests nonce!", null);
            }
            // check the response on our cert
            checkCertStatus(signersCert, basResp, caCert);
            // create notary
            not = new Notary(notId, resp.getEncoded(), respId, basResp.getProducedAt());
            if(notaryCert != null)
                not.setCertNr(notaryCert.getSerialNumber().toString());
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_PARSE);
        }
        return not;
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
            //ertificateID certId = creatCertReq(signersCert, caCert);
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
     * Verifies that the OCSP response is about our signers
     * cert and the response status is successfull
     * @param sig Signature object
     * @param basResp OCSP Basic response
     * @throws DigiDocException if the response is not successfull
     */
    private void checkCertStatusWithCa(X509Certificate cert, BasicOCSPResp basResp, X509Certificate caCert)
            throws DigiDocException
    {
        try {
            if(m_logger.isDebugEnabled())
                m_logger.debug("Checking response status, CERT: " + cert.getSubjectDN().getName() +
                        " SEARCH: " + SignedDoc.getCommonName(ConvertUtils.convX509Name(cert.getIssuerX500Principal())));
            // check the response on our cert
            //DigiDocFactory ddocFac = ConfigManager.instance().getDigiDocFactory();
            //X509Certificate caCert = (X509Certificate)m_ocspCACerts.
            //	get(SignedDoc.getCommonName(ConvertUtils.convX509Name(cert.getIssuerX500Principal())));
            if(m_logger.isDebugEnabled()) {
                m_logger.debug("CA cert: " + ((caCert == null) ? "NULL" : "OK"));
                m_logger.debug("RESP: " + basResp);
                m_logger.debug("CERT: " + cert.getSubjectDN().getName() +
                        " ISSUER: " + ConvertUtils.convX509Name(cert.getIssuerX500Principal()));
                if(caCert != null)
                    m_logger.debug("CA CERT: " + caCert.getSubjectDN().getName());
            }
            SingleResp[] sresp = basResp.getResponses();
            CertificateID rc = null;
            if(cert != null && caCert != null)
                rc = creatCertReq(cert, caCert);
            //ertificateID certId = creatCertReq(signersCert, caCert);
            if(m_logger.isDebugEnabled() && rc != null)
                m_logger.debug("Search alg: " + rc.getHashAlgOID() +
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
                    if(rc != null && rc.getHashAlgOID().equals(id.getHashAlgOID()) &&
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
                                throw new DigiDocException(DigiDocException.ERR_OCSP_RESP_STATUS,
                                        "Certificate has been revoked!", null);
                            }
                            if(status instanceof UnknownStatus) {
                                m_logger.error("Certificate status is unknown!");
                                throw new DigiDocException(DigiDocException.ERR_OCSP_RESP_STATUS,
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
        try {
            // DEBUG
            //debugWriteFile("respin.resp", not.getOcspResponseData());
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
                    ee.sk.digidoc.CertID cid = sig.getCertID(ee.sk.digidoc.CertID.CERTID_TYPE_RESPONDER);
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
            // done't care about SingleResponses because we have
            // only one response and the whole response was successfull
            // but we should verify that the nonce hasn't changed
            // calculate the nonce
            if(m_logger.isDebugEnabled())
                m_logger.debug("Verif sig: " + sig.getId() + " format: " + sig.getSignedDoc().getFormat() + " nonce policy: " + sig.hasBdoc2NoncePolicy());
            boolean ok = true;
            if(sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_SK_XML) ||
                    sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML) ||
                    (sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC) && sig.hasBdoc2NoncePolicy())) {
                byte[] nonce1 = SignedDoc.digestOfType(sig.getSignatureValue().getValue(),
                        sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC) ? SignedDoc.SHA256_DIGEST_TYPE : SignedDoc.SHA1_DIGEST_TYPE);
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
                        //m_logger.debug("SIG:\n---\n" + sig.toString() + "\n--\n");
                    }
                    throw new DigiDocException(DigiDocException.ERR_OCSP_NONCE,
                            "OCSP response's nonce doesn't match the requests nonce!", null);
                }
            }
            // bdoc 2.0 has to define compliance to nonce policy
            // separate method is used to check all aspects of nonce policy
            /*if(sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC) && !sig.hasBdoc2NoncePolicy()) {
            	throw new DigiDocException(DigiDocException.ERR_OCSP_NONCE,
                        "BDOC 2.0 / ASIC-E signatures have to define compliance to nonce policy!", null);
            }*/
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

    private static final int V_ASN1_OCTET_STRING = 4;
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
                //if(extOids.size() == 0)
                //	extOids = basResp.getCriticalExtensionOIDs();
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
                if(sdoc != null && sdoc.getFormat() != null && sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC)) bCheckOcspNonce = true;
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
                if(sdoc != null && sdoc.getFormat() != null && sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC)) {
                    if(nonce2 != null) {
                        sType = ConvertUtils.findDigType(nonce2);
                        if(sType != null) {
                            byte[] b = ConvertUtils.removePrefix(nonce2);
                            nonce2 = b;
                        }
                        bAsn1 = (sType != null);
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
     * Helper method to verify response status
     * @param resp OCSP response
     * @throws DigiDocException if the response status is not ok
     */
    private void verifyRespStatus(OCSPResp resp)
            throws DigiDocException
    {
        if(resp == null || resp.getStatus() != OCSPRespBuilder.SUCCESSFUL)
            throw new DigiDocException(DigiDocException.ERR_OCSP_UNSUCCESSFULL,
                    "OCSP response unsuccessfull! ", null);
        int status = resp.getStatus();
        switch (status) {
            case OCSPRespBuilder.INTERNAL_ERROR: m_logger.error("An internal error occured in the OCSP Server!"); break;
            case OCSPRespBuilder.MALFORMED_REQUEST: m_logger.error("Your request did not fit the RFC 2560 syntax!"); break;
            case OCSPRespBuilder.SIG_REQUIRED: m_logger.error("Your request was not signed!"); break;
            case OCSPRespBuilder.TRY_LATER: m_logger.error("The server was too busy to answer you!"); break;
            case OCSPRespBuilder.UNAUTHORIZED: m_logger.error("The server could not authenticate you!"); break;
            case OCSPRespBuilder.SUCCESSFUL: break;
            default: m_logger.error("Unknown OCSPResponse status code! "+status);
        }
    }


    /**
     * Method for creating CertificateID for OCSP request
     * @param signersCert
     * @param caCert
     * @param provider
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws CertificateEncodingException
     */
    private CertificateID creatCertReq(X509Certificate signersCert, X509Certificate caCert)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            CertificateEncodingException, DigiDocException, Exception
    {
        DigestCalculatorProvider dcp = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        X509CertificateHolder caCertHolder = new X509CertificateHolder(caCert.getEncoded());
        return new CertificateID(dcp.get(CertificateID.HASH_SHA1), caCertHolder, signersCert.getSerialNumber());
    }



    /**
     * Creates a new OCSP request
     * @param nonce 128 byte RSA+SHA1 signatures digest
     * Use null if you want to verify only the certificate
     * and this is not related to any signature
     * @param signersCert signature owners cert
     * @param caCert CA cert for this signer
     * @param bSigned flag signed request or not
     * @param bBdoc used for BDOC signature
     */
    private OCSPReq createOCSPRequest(byte[] nonce, X509Certificate signersCert,
                                      X509Certificate caCert, boolean bSigned, boolean bBdoc)
            throws DigiDocException
    {
        OCSPReq req = null;
        OCSPReqBuilder ocspRequest = new OCSPReqBuilder();
        try {
            //Create certificate id, for OCSP request
            if(m_logger.isDebugEnabled())
                m_logger.debug("Request for: " + ((signersCert != null) ? ConvertUtils.getCommonName(ConvertUtils.convX509Name(signersCert.getSubjectX500Principal())) : "NULL") +
                        " CA: " + ((caCert != null) ? ConvertUtils.getCommonName(ConvertUtils.convX509Name(caCert.getSubjectX500Principal())) : "NULL"));
            if(signersCert == null)
                throw new DigiDocException(DigiDocException.ERR_OCSP_REQ_CREATE, "Missing signers cert for ocsp request", null);
            if(caCert == null)
                throw new DigiDocException(DigiDocException.ERR_OCSP_REQ_CREATE, "Missing CA cert for ocsp request", null);
            CertificateID certId = creatCertReq(signersCert, caCert);
            if(m_logger.isDebugEnabled())
                m_logger.debug("Request for: " + certId.getHashAlgOID() +
                        " serial: " + certId.getSerialNumber() +
                        " issuer: " + ConvertUtils.bin2hex(certId.getIssuerKeyHash()) +
                        " subject: " + ConvertUtils.bin2hex(certId.getIssuerNameHash()) +
                        " nonce: " + ConvertUtils.bin2hex(nonce) + " len: " + nonce.length);
            ocspRequest.addRequest(certId);
            //if(m_logger.isDebugEnabled())
            //	  m_logger.debug("Nonce in1: " + ConvertUtils.bin2hex(nonce) + " has-pref: " + ConvertUtils.findDigType(nonce) + " in-len: " + ((nonce != null) ? nonce.length : 0));
            if(nonce != null && ConvertUtils.findDigType(nonce) == null && bBdoc) {
                byte[] b = ConvertUtils.addDigestAsn1Prefix(nonce);
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Nonce in: " + ConvertUtils.bin2hex(nonce) + " in-len: " + nonce.length +
                            " with-asn1: " + ConvertUtils.bin2hex(b) + " out-len: " + ((b != null) ? b.length : 0) + " out-pref: " + ConvertUtils.findDigType(b));
                nonce = b;
            }
            if(nonce != null) {
                ExtensionsGenerator extGen = new ExtensionsGenerator();
                if(bBdoc)
                    extGen.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, nonce);
                else
                    extGen.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(nonce));
                ocspRequest.setRequestExtensions(extGen.generate());
            }
            GeneralName name = null;
            if(bSigned) {
                if(m_logger.isDebugEnabled())
                    m_logger.debug("SignCert: " + ((m_signCert != null) ? m_signCert.toString() : "NULL"));
                if(m_signCert == null)
                    throw new DigiDocException(DigiDocException.ERR_INVALID_CONFIG, "Invalid config file! Attempting to sign ocsp request but PKCS#12 token not configured!", null);
                name = new GeneralName(PrincipalUtil.getSubjectX509Principal(m_signCert));
            } else {
                if(signersCert == null)
                    throw new DigiDocException(DigiDocException.ERR_OCSP_SIGN, "Signature owners certificate is NULL!", null);
                name = new GeneralName(PrincipalUtil.getSubjectX509Principal(signersCert));
            }
            ocspRequest.setRequestorName(name);
            if(bSigned) {
                // lets generate signed request
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Signing ocsp request with: " + ((m_signCert != null) ? m_signCert.getSubjectX500Principal().getName() : "NULL"));
                X509CertificateHolder[] chain = new X509CertificateHolder[1];
                chain[0] = new X509CertificateHolder(m_signCert.getEncoded());
                req = ocspRequest.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(m_signKey), chain);
                if(!req.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(chain[0]))) {
                    m_logger.error("Verify failed");
                }
            } else { // unsigned request
                req = ocspRequest.build();
            }

        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_REQ_CREATE);
        }
        return req;
    }


    /**
     * Sends the OCSP request to Notary and
     * retrieves the response
     * @param req OCSP request
     * @param httpFrom HTTP_FROM value (optional)
     * @returns OCSP response
     */
    private OCSPResp sendRequest(OCSPReq req, String httpFrom, String format, String formatVer)
            throws DigiDocException
    {
        String responderUrl = ConfigManager.instance().
                getProperty("DIGIDOC_OCSP_RESPONDER_URL");
        return sendRequestToUrl(req, responderUrl, httpFrom, format, formatVer);
    }

    private String getUserInfo(String format, String formatVer)
    {
        StringBuffer sb = null;
        try {
            sb = new StringBuffer("LIB ");
            sb.append(SignedDoc.LIB_NAME);
            sb.append("/");
            sb.append(SignedDoc.LIB_VERSION);
            if(format != null && formatVer != null) {
                sb.append(" format: ");
                sb.append(format);
                sb.append("/");
                sb.append(formatVer);
            }
            sb.append(" Java: ");
            sb.append(System.getProperty("java.version"));
            sb.append("/");
            sb.append(System.getProperty("java.vendor"));
            sb.append(" OS: ");
            sb.append(System.getProperty("os.name"));
            sb.append("/");
            sb.append(System.getProperty("os.arch"));
            sb.append("/");
            sb.append(System.getProperty("os.version"));
            sb.append(" JVM: ");
            sb.append(System.getProperty("java.vm.name"));
            sb.append("/");
            sb.append(System.getProperty("java.vm.vendor"));
            sb.append("/");
            sb.append(System.getProperty("java.vm.version"));
        } catch(Throwable ex) {
            m_logger.error("Error reading java system properties: " + ex);
        }
        return ((sb != null) ? sb.toString() : null);
    }

    /**
     * Sends the OCSP request to Notary and
     * retrieves the response
     * @param req OCSP request
     * @param url OCSP responder url
     * @param httpFrom HTTP_FROM value (optional)
     * @returns OCSP response
     */
    private OCSPResp sendRequestToUrl(OCSPReq req, String url, String httpFrom, String format, String formatVer)
            throws DigiDocException
    {
        OCSPResp resp = null;
        try {
            byte[] breq = req.getEncoded();
            URL uUrl = new URL(url);
            if(m_logger.isDebugEnabled())
                m_logger.debug("Connecting to ocsp url: " + url);
            URLConnection con = uUrl.openConnection();
            int nTmout = con.getConnectTimeout();
            if(m_logger.isDebugEnabled())
                m_logger.debug("Default connection timeout: " + nTmout + " [ms]");
            int nConfTm = ConfigManager.instance().getIntProperty("OCSP_TIMEOUT", -1);
            if(nConfTm >= 0) {
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Setting connection and read timeout to: " + nConfTm + " [ms]");
                con.setConnectTimeout(nConfTm);
                con.setReadTimeout(nConfTm);
            }
            con.setAllowUserInteraction(false);
            con.setUseCaches(false);
            con.setDoOutput(true);
            con.setDoInput(true);
            // send the OCSP request
            con.setRequestProperty("Content-Type", "application/ocsp-request");
            String sUserInfo = getUserInfo(format, formatVer);
            if(sUserInfo != null) {
                if(m_logger.isDebugEnabled())
                    m_logger.debug("User-Agent: " + sUserInfo);
                con.setRequestProperty("User-Agent", sUserInfo);
            }
            if(httpFrom != null && httpFrom.trim().length() > 0) {
                if(m_logger.isDebugEnabled())
                    m_logger.debug("X-Forwarded-For: " + httpFrom);
                con.setRequestProperty("X-Forwarded-For", httpFrom);
            }
            OutputStream os = con.getOutputStream();
            os.write(breq);
            os.close();
            // read the response
            InputStream is = con.getInputStream();
            int cl = con.getContentLength();
            byte[] bresp = null;
            if(cl > 0) {
                int avail = 0;
                do {
                    avail = is.available();
                    byte[] data = new byte[avail];
                    int rc = is.read(data);
                    if(bresp == null) {
                        bresp = new byte[rc];
                        System.arraycopy(data, 0, bresp, 0, rc);
                    } else {
                        byte[] tmp = new byte[bresp.length + rc];
                        System.arraycopy(bresp, 0, tmp, 0, bresp.length);
                        System.arraycopy(data, 0, tmp, bresp.length, rc);
                        bresp = tmp;
                    }
                    cl -= rc;
                } while(cl > 0);
            }
            is.close();
            if(bresp != null) {
                resp = new OCSPResp(bresp);
            }
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_REQ_SEND);
        }
        return resp;
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
            String sigFlag = ConfigManager.
                    instance().getProperty("SIGN_OCSP_REQUESTS");
            m_bSignRequests = (sigFlag != null && sigFlag.equals("true"));
            // only need this if we must sign the requests
            Provider prv = (Provider)Class.forName(ConfigManager.
                    instance().getProperty("DIGIDOC_SECURITY_PROVIDER")).newInstance();
            //prv.list(System.out);
            Security.addProvider(prv);


            if(m_bSignRequests) {
                // load the cert & private key for OCSP signing
                String p12file = ConfigManager.instance().
                        getProperty("DIGIDOC_PKCS12_CONTAINER");
                String p12paswd = ConfigManager.instance().
                        getProperty("DIGIDOC_PKCS12_PASSWD");
                // PKCS#12 container has 2 certs
                // so use this serial to find the necessary one
                String p12serial = ConfigManager.instance().
                        getProperty("DIGIDOC_OCSP_SIGN_CERT_SERIAL");
                if(p12file != null && p12paswd != null) {
                    fi = new FileInputStream(p12file);
                    KeyStore store = KeyStore.getInstance("PKCS12", "BC");
                    store.load(fi, p12paswd.toCharArray());
                    java.util.Enumeration en = store.aliases();
                    // find the key alias
                    String      pName = null;
                    while(en.hasMoreElements()) {
                        String  n = (String)en.nextElement();
                        if (store.isKeyEntry(n)) {
                            pName = n;
                        }
                    }
                    m_signKey = (PrivateKey)store.getKey(pName, null);
                    java.security.cert.Certificate[] certs = store.getCertificateChain(pName);
                    for(int i = 0; (certs != null) && (i < certs.length); i++) {
                        java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate)certs[i];
                        if(m_logger.isInfoEnabled()) {
                            m_logger.info("Cert " + i + " subject: " + ConvertUtils.convX509Name(cert.getSubjectX500Principal()));
                            m_logger.info("Cert " + i + " issuer: " + ConvertUtils.convX509Name(cert.getIssuerX500Principal()));
                            m_logger.info("Cert " + i + " serial: " + cert.getSerialNumber());
                            m_logger.info("Cert " + i + " is-ca: " + ConvertUtils.isCACert(cert));
                        }
                        if(p12serial != null && cert != null && cert.getSerialNumber().equals(new BigInteger(p12serial)))
                            m_signCert = (X509Certificate)certs[i];
                    }
                }
            }



        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_NOT_FAC_INIT);
        } finally {
            if(fi != null) {
                try {
                    fi.close();
                    fi = null;
                } catch(Exception ex2) {
                    m_logger.error("Error closing input stream: " + ex2);
                }
            }
        }
    }



}