package org.digidoc4j.ddoc.factory;

import org.digidoc4j.ddoc.*;
import org.digidoc4j.ddoc.utils.ConfigManager;
import org.digidoc4j.ddoc.utils.ConvertUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.io.File;
import java.math.BigInteger;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Factory class to handle verification of signatures and container
 * @author Veiko Sinivee
 */
public class DigiDocVerifyFactory {
    private static final Logger m_logger = LoggerFactory.getLogger(DigiDocVerifyFactory.class);
    private static boolean m_prvInited = false;

    private static final String DIGIDOC_VERIFY_ALGORITHM = "RSA/NONE/PKCS1Padding";

    public static void initProvider() {
        try {
            if(!m_prvInited) {
                // only need this if we must sign the requests
                Provider prv = (Provider)Class.forName(ConfigManager.
                        instance().getProperty("DIGIDOC_SECURITY_PROVIDER")).newInstance();
                Security.addProvider(prv);
                m_prvInited = true;
            }
        } catch(Exception ex) {
            m_logger.error("Error initting provider: " + ex);
        }
    }

    /**
     * Helper method for comparing
     * digest values
     * @param dig1 first digest value
     * @param dig2 second digest value
     * @return true if they are equal
     */
    public static boolean compareDigests(byte[] dig1, byte[] dig2)
    {
        boolean ok = (dig1 != null) && (dig2 != null) &&
                (dig1.length == dig2.length);
        for(int i = 0; ok && (i < dig1.length); i++)
            if(dig1[i] != dig2[i])
                ok = false;
        return ok;
    }

    /**
     * Verifies the hash of one data-file
     * @param df DataFile object
     * @param ref Reference object
     * @param lerrs list of errors
     * @return true if ok
     */
    private static boolean verifyDataFileHash(DataFile df, Reference ref, List lerrs)
    {
        boolean bOk = true;
        if(df != null) {
            if(m_logger.isDebugEnabled())
                m_logger.debug("Check digest for DF: " + df.getId() + " ref: " + ((ref != null) ? ref.getUri() : "NULL"));
            String sDigType = null;
            if(ref != null)
                sDigType = ConfigManager.digAlg2Type(ref.getDigestAlgorithm());
            if(m_logger.isDebugEnabled())
                m_logger.debug("Check digest for DF: " + df.getId() + " type: " + sDigType);
            byte[] dfDig = null;
            try {
                if(sDigType != null)
                    dfDig = df.getDigestValueOfType(sDigType);
            } catch(DigiDocException ex) {
                lerrs.add(ex);
                bOk = false;
                m_logger.error("Error calculating hash for df: " + df.getId() + " - " + ex);
                ex.printStackTrace();
                if(ex.getNestedException() != null)
                    ex.getNestedException().printStackTrace();
            }
            if(ref != null) {
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Compare digest: " + ((dfDig != null) ? Base64Util.encode(dfDig, 0) : "NONE") +
                            " hex: " + ((dfDig != null) ? ConvertUtils.bin2hex(dfDig) : "NONE") +
                            " alt digest: " + ((df.getAltDigest() != null) ? Base64Util.encode(df.getAltDigest(), 0) : "NONE") +
                            " to: " + ((ref.getDigestValue() != null) ? Base64Util.encode(ref.getDigestValue()) : "NONE") +
                            " hex: " + ((ref.getDigestValue() != null) ? ConvertUtils.bin2hex(ref.getDigestValue()) : "NONE"));
                DigiDocException exd = null;
                if(!SignedDoc.compareDigests(ref.getDigestValue(), dfDig)) {
                    lerrs.add((exd = new DigiDocException(DigiDocException.ERR_DIGEST_COMPARE,
                            "Bad digest for DataFile: " + df.getId(), null)));
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("BAD DIGEST for DF: " + df.getId());
                    bOk = false;
                }
                if(!bOk && df.getAltDigest() != null) {
                    if(SignedDoc.compareDigests(ref.getDigestValue(), df.getAltDigest())) {
                        if(m_logger.isDebugEnabled()) {
                            m_logger.debug("DF: " + df.getId() + " alternate digest matches!");
                            m_logger.debug("GOOD ALT DIGEST for DF: " + df.getId());
                        }
                        if(exd != null)
                            lerrs.remove(exd);
                        ref.getSignedInfo().getSignature().setAltDigestMatch(true);
                        if(!ref.getSignedInfo().getSignature().getSignedDoc().getFormat().equals(SignedDoc.FORMAT_SK_XML))
                            lerrs.add((new DigiDocException(DigiDocException.ERR_DF_INV_HASH_GOOD_ALT_HASH,
                                    "Bad digest for DataFile: " + df.getId() + " alternate digest matches!", null)));
                        bOk = false;
                    }
                }
                else if(m_logger.isDebugEnabled())
                    m_logger.debug("GOOD DIGEST");
            } else {
                if(m_logger.isDebugEnabled())
                    m_logger.debug("No Reference");
                lerrs.add(new DigiDocException(
                        DigiDocException.ERR_DATA_FILE_NOT_SIGNED,
                        "No Reference element for DataFile: " + df.getId(), null));
                bOk = false;
            }
        } else {
            if(m_logger.isDebugEnabled())
                m_logger.debug("Invalid data-file");
            bOk = false;
        }
        return bOk;
    }

    /**
     * Verifies SignedProperties digest
     * @param sig Signature object
     * @param lerrs list of errors
     * @return true if ok
     */
    private static boolean verifySignedPropretiesHash(Signature sig, List lerrs)
    {
        boolean bOk = true;
        if(m_logger.isDebugEnabled())
            m_logger.debug("Verifying signed-props of: " + sig.getId());
        SignedProperties sp = sig.getSignedProperties();
        if(sp != null) {
            Reference ref2 = sig.getSignedInfo().getReferenceForSignedProperties(sp);
            if(ref2 != null) {
                byte[] spDig = null;
                try {
                    spDig = sp.calculateDigest();
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("SignedProp real digest: " + Base64Util.encode(spDig, 0));
                } catch(DigiDocException ex) {
                    lerrs.add(ex);
                    bOk = false;
                }
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Compare it to: " + Base64Util.encode(ref2.getDigestValue(), 0));
                if(!SignedDoc.compareDigests(ref2.getDigestValue(), spDig)) {
                    lerrs.add(new DigiDocException(DigiDocException.ERR_DIGEST_COMPARE,
                            "Bad digest for SignedProperties: " + sp.getId(), null));
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("BAD DIGEST for sig-prop");
                    bOk = false;
                }
                else if(m_logger.isDebugEnabled())
                    m_logger.debug("GOOD DIGEST");
            } else {
                if(m_logger.isDebugEnabled())
                    m_logger.debug("No Reference element for SignedProperties: " + sp.getId());
                lerrs.add(new DigiDocException(DigiDocException.ERR_SIG_PROP_NOT_SIGNED,
                        "No Reference element for SignedProperties: " + sp.getId(), null));
                bOk = false;
            }

        } else {
            if(m_logger.isDebugEnabled())
                m_logger.debug("No Reference element for SignedProperties of sig: " + sig.getId());
            lerrs.add(new DigiDocException(DigiDocException.ERR_SIG_PROP_NOT_SIGNED,
                    "No Reference element for SignedProperties sig: " + sig.getId(), null));
            bOk = false;
        }
        return bOk;
    }



    /**
     * Verifies the siganture
     * @param digest input data digest
     * @param signature signature value
     * @param cert certificate to be used on verify
     * @param bSoftCert use Sun verificateion api instead
     * @return true if signature verifies
     */
    public static boolean verify(byte[] digest, byte[] signature, X509Certificate cert, boolean bSoftCert, String sigMethod)
            throws DigiDocException
    {
        boolean rc = false;
        try {
            if(cert == null)
                throw new DigiDocException(DigiDocException.ERR_VERIFY, "Invalid or missing signers cert!", null);
            if(bSoftCert) {
                String sigType = ConfigManager.instance().sigMeth2SigType(sigMethod, true);
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Verify xml:\n---\n" + new String(digest) + "\n---\n len: " +
                            digest.length + " method: " + sigMethod + " sig-type: " + sigType + "\n---\n" +
                            ConvertUtils.bin2hex(signature) + " sig-len: " + signature.length);
                if(sigType == null)
                    throw new DigiDocException(DigiDocException.ERR_VERIFY, "Signature method: " + sigMethod + " not provided!", null);
                java.security.Signature sig = java.security.Signature.getInstance(sigType, ConfigManager.addProvider());
                sig.initVerify(cert.getPublicKey());
                sig.update(digest);
                rc = sig.verify(signature);
            } else {
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Verify sig: " + signature.length + " bytes, alg: " + DIGIDOC_VERIFY_ALGORITHM + " sig-alg: " + sigMethod);
                Cipher cryptoEngine = Cipher.getInstance(DIGIDOC_VERIFY_ALGORITHM, "BC");
                cryptoEngine.init(Cipher.DECRYPT_MODE, cert);
                byte[] decdig;
                try {
                    decdig = cryptoEngine.doFinal(signature);
                } catch(java.lang.ArrayIndexOutOfBoundsException ex2) {
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Invalid signature value. Signers cert and signature value don't match! - " + ex2);
                    throw new DigiDocException(DigiDocException.ERR_VERIFY, "Invalid signature value! Signers cert and signature value don't match!", ex2);
                }
                String digType2 = ConfigManager.sigMeth2Type(sigMethod);
                String digType1 = ConvertUtils.findDigType(decdig);
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Decrypted digest: \'" + SignedDoc.bin2hex(decdig) + "\' len: " + decdig.length + " has-pref: " + digType1 +
                            " must-have: " + digType2 + " alg: " + sigMethod);
                if(digType1 != null && digType1.equals(SignedDoc.SHA1_DIGEST_TYPE_BAD)) {
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Invalid signature asn.1 prefix with 0x00 byte");
                    throw new DigiDocException(DigiDocException.ERR_SIGVAL_00, "Invalid signature asn.1 prefix with 0x00 byte", null);
                }
                if((digType1 == null) ||
                        (digType2 != null && digType1 != null && !digType2.equals(digType1))) {
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Signature asn.1 prefix: " + digType1 + " does not match: " + digType2);
                    throw new DigiDocException(DigiDocException.ERR_SIGVAL_ASN1, "Signature asn.1 prefix: " + digType1 + " does not match: " + digType2, null);
                }
                byte[] cdigest = ConvertUtils.removePrefix(decdig);
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Signed digest: \'" + ((cdigest != null) ? SignedDoc.bin2hex(cdigest) : "NULL") + "\' calc-digest: \'" + SignedDoc.bin2hex(digest) + "\'");
                if(decdig != null && cdigest != null &&
                        decdig.length == cdigest.length) {
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Signature value decrypted len: " + decdig.length + " missing ASN.1 structure prefix");
                    throw new DigiDocException(DigiDocException.ERR_VERIFY, "Invalid signature value! Signature value decrypted len: " + decdig.length + " missing ASN.1 structure prefix", null);
                }
                rc = compareDigests(digest, cdigest);
            }
            if(m_logger.isDebugEnabled())
                m_logger.debug("Result: " + rc);
            if(!rc)
                throw new DigiDocException(DigiDocException.ERR_VERIFY, "Invalid signature value!", null);
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_VERIFY);
        }
        return rc;
    }

    public static boolean verifySignatureValue(SignedDoc sdoc, Signature sig, List lerrs)
    {
        boolean bOk = true;
        if(sdoc == null) {
            m_logger.error("SignedDoc is null");
            return false;
        }
        if(sig == null) {
            m_logger.error("Signature is null");
            return false;
        }
        if(m_logger.isDebugEnabled())
            m_logger.debug("Verifying signature value of: " + sig.getId());
        // verify signature value
        try {
            byte[] dig = sig.getSignedInfo().calculateDigest();
            if(m_logger.isDebugEnabled())
                m_logger.debug("SignedInfo real digest: " + Base64Util.encode(dig, 0) + " hex: " + SignedDoc.bin2hex(dig) +
                        " sig: " + ConvertUtils.bin2hex(sig.getSignatureValue().getValue()) +
                        " len: " + sig.getSignatureValue().getValue().length);
            if(sig.getSignatureValue() != null && sig.getSignatureValue().getValue() != null && dig != null) {
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Verify sig: " + ConvertUtils.bin2hex(sig.getSignatureValue().getValue()) +
                            " len: " + sig.getSignatureValue().getValue().length + " hlen: " + ConvertUtils.bin2hex(sig.getSignatureValue().getValue()).length());
                bOk = verify(dig, sig.getSignatureValue().getValue(), sig.getKeyInfo().getSignersCertificate(), false, sig.getSignedInfo().getSignatureMethod());
                if(m_logger.isDebugEnabled())
                    m_logger.debug("GOOD DIGEST");
            } else {
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Missing signature value!");
                lerrs.add(new DigiDocException(DigiDocException.ERR_SIGNATURE_VALUE_VALUE, "Missing signature value!", null));
                bOk = false;
            }
        } catch(DigiDocException ex) {
            lerrs.add(ex);
            if(m_logger.isDebugEnabled()) {
                m_logger.debug("BAD DIGEST for sig-inf: " + sig.getId() + " - " + ex.toString());
                m_logger.debug("TRACE: " + ConvertUtils.getTrace(ex));
                //ex.printStackTrace();
                m_logger.debug("sig-val-len: " + ((sig.getSignatureValue() != null && sig.getSignatureValue().getValue() != null) ? sig.getSignatureValue().getValue().length : 0));
                m_logger.debug("signer: " + ((sig.getKeyInfo() != null && sig.getKeyInfo().getSignersCertificate() != null) ? sig.getKeyInfo().getSignersCertificate().getSubjectDN().getName() : "NULL"));
            }
            bOk = false;
        }
        return bOk;
    }

    /**
     * Verifies that the signers cert
     * has been signed by at least one
     * of the known root certs
     * @param cert certificate to check
     */
    public static boolean verifyCertificate(X509Certificate cert, X509Certificate caCert)
            throws DigiDocException {
        boolean rc = false;
        try {
            if (caCert != null) {
                cert.verify(caCert.getPublicKey());
                rc = true;
            }
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_UNKNOWN_CA_CERT);
        }
        return rc;
    }

    /**
     * Verifies signers cerificate by a trusted CA cert
     * @param sig Signature object
     * @param lerrs list for errors
     * @return
     */
    public static boolean verifySignersCerificate(Signature sig, List lerrs)
    {
        boolean bOk = true;
        try {
            if(m_logger.isDebugEnabled())
                m_logger.debug("Verifying CA of signature: " + sig.getId() + " signed-at: " + ConvertUtils.date2string(sig.getSignedProperties().getSigningTime(), sig.getSignedDoc()) + " produced: " + ConvertUtils.date2string(sig.getSignatureProducedAtTime(), sig.getSignedDoc()));
            TrustServiceFactory tslFac = ConfigManager.instance().getTslFactory();
            if(sig.getKeyInfo().getSignersCertificate() == null) {
                lerrs.add(new DigiDocException(DigiDocException.ERR_SIGNERS_CERT, "Signers cert missing!", null));
                return false;
            }
            X509Certificate caCert = tslFac.findCaForCert(sig.getKeyInfo().getSignersCertificate(), true, sig.getSignatureProducedAtTime());
            X509Certificate cert = sig.getKeyInfo().getSignersCertificate();
            if(m_logger.isDebugEnabled())
                m_logger.debug("Check signer: " + cert.getSubjectDN().getName() +
                        " issued by: " + cert.getIssuerDN().getName() +
                        " SUB from: " + ConvertUtils.date2string(cert.getNotBefore(), sig.getSignedDoc()) +
                        " to: " + ConvertUtils.date2string(cert.getNotAfter(), sig.getSignedDoc()) +
                        " by CA: " + ((caCert != null) ? caCert.getSubjectDN().getName() : "NOT FOUND") +
                        " CA from: " + ((caCert != null) ? ConvertUtils.date2string(caCert.getNotBefore(), sig.getSignedDoc()) : "?") +
                        " to: " + ((caCert != null) ? ConvertUtils.date2string(caCert.getNotAfter(), sig.getSignedDoc()) : "?") +
                        " ca-ahel: " + (DigiDocGenFactory.isTestCard(cert) ? "TEST" : "LIVE"));
            if(caCert != null) {
                bOk = verifyCertificate(cert, caCert);
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Signer: " + ConvertUtils.getCommonName(sig.getKeyInfo().getSignersCertificate().getSubjectDN().getName()) +
                            " is issued by trusted CA: " + ConvertUtils.getCommonName(caCert.getSubjectDN().getName()));
            } else {
                if(m_logger.isDebugEnabled())
                    m_logger.debug("CA not found for: " + ConvertUtils.getCommonName(cert.getSubjectDN().getName()));
                lerrs.add(new DigiDocException(DigiDocException.ERR_SIGNERS_CERT, "Signers cert not trusted, missing CA cert!", null));
                bOk = false;
            }
            if(!ConfigManager.isSignatureKey(cert)) {
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Signers cert does not have non-repudiation bit set!");
                lerrs.add(new DigiDocException(DigiDocException.ERR_SIGNERS_CERT_NONREPUD, "Signers cert does not have non-repudiation bit set!", null));
                bOk = false;
            }

            CertID cid = sig.getCertIdOfType(CertID.CERTID_TYPE_SIGNER);
            if(cert != null && cid != null) {
                // verify DN using RDN
                boolean bMatch = true;
                List aCertRdns = parseDN(ConvertUtils.convX509Name(cert.getIssuerX500Principal()));
                List aCertIdRdns = parseDN(cid.getIssuer());
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Signed: " + cid.getIssuer() + " cert: " + ConvertUtils.convX509Name(cert.getIssuerX500Principal()) +
                            " cert rdn-s: " + aCertRdns.size() + " signed rdn-s: " + aCertIdRdns.size());
                // don't have to match all RDN entries in cert. Just the signed ones agains the cert. Not opposite
                for(int i = 0; i < aCertIdRdns.size(); i++) {
                    Rdn r1 = (Rdn)aCertIdRdns.get(i);
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Signed RDN: " + r1.getId() + "/" +  r1.getValue());
                    boolean bF = false;
                    for(int j = 0; j < aCertRdns.size(); j++) {
                        Rdn r2 = (Rdn)aCertRdns.get(j);
                        if(r1.getId() != null && r2.getId() != null && r1.getId().equalsIgnoreCase(r2.getId()) &&
                                r1.getValue() != null && r2.getValue() != null && r1.getValue().equalsIgnoreCase(r2.getValue())) {
                            bF = true;
                        }
                    }
                    if(!bF) {
                        if(m_logger.isDebugEnabled())
                            m_logger.debug("Different for signed: " + r1.getId() + "/" + r1.getValue());
                    }
                    if(!bF && r1.getId() != null &&
                            (r1.getId().equals("CN") ||
                                    r1.getId().equals("LT") ||
                                    r1.getId().equals("ST") ||
                                    r1.getId().equals("O") ||
                                    r1.getId().equals("OU") ||
                                    r1.getId().equals("C") ||
                                    r1.getId().equals("STREET") ||
                                    r1.getId().equals("DC") ||
                                    r1.getId().equals("UID")) ) {
                        m_logger.error("No match for signed: " + r1.getId() + "/" + r1.getValue());
                        bMatch = false;
                    }
                }
                if(!bMatch) {
                    m_logger.error("Signers cert issuer DN: " + ConvertUtils.convX509Name(cert.getIssuerX500Principal()) +
                            " and signed Issuername: " + cid.getIssuer() + " don't match");
                    lerrs.add(new DigiDocException(DigiDocException.ERR_VERIFY, "Signing certificate issuer information does not match", null));
                }
                // verify cer issuer serial
                if(cid.getSerial() != null) {
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Signed IssuerSerial: " + cid.getSerial().toString() + " cert serial: " + cert.getSerialNumber().toString());
                    if(!cid.getSerial().equals(cert.getSerialNumber())) {
                        m_logger.error("Signers cert issuer serial: " + cert.getSerialNumber().toString() +
                                " and signed IssuerSerial: " + cid.getSerial().toString() + " don't match");
                        lerrs.add(new DigiDocException(DigiDocException.ERR_VERIFY, "Signing certificate issuer information does not match", null));
                    }
                }
            }
        } catch(DigiDocException ex) {
            if(m_logger.isDebugEnabled())
                m_logger.debug("Signers certificate not trusted for: " + sig.getId());
            lerrs.add(ex);
            bOk = false;
        }
        return bOk;
    }

    /**
     * Verifies signing time of signature (as stored in signed properties)
     * @param sig Signature object
     * @param lerrs list of errors
     * @return true if ok
     */
    public static boolean verifySigningTime(Signature sig, List lerrs)
    {
        boolean bOk = true;
        if(m_logger.isDebugEnabled())
            m_logger.debug("Verifying signing time signature: " + sig.getId());
        try {
            Date dProdAt = null;
            if(sig != null && sig.getUnsignedProperties() != null && sig.getUnsignedProperties().getNotary() != null)
                dProdAt = sig.getUnsignedProperties().getNotary().getProducedAt();
            if(dProdAt != null)
                sig.getKeyInfo().getSignersCertificate().checkValidity(dProdAt);
            if(m_logger.isDebugEnabled())
                m_logger.debug("Signers cert: " + ConvertUtils.getCommonName(sig.getKeyInfo().getSignersCertificate().getSubjectDN().getName()) +
                        " was valid on: " + ConvertUtils.date2string(dProdAt, sig.getSignedDoc()));
        } catch(Exception ex) {
            m_logger.error("Signers certificate has expired for: " + sig.getId());
            lerrs.add(new DigiDocException(DigiDocException.ERR_CERT_EXPIRED,
                    "Signers certificate has expired!", null));
            bOk = false;
        }
        return bOk;
    }

    /**
     * Verifies OCSP confirmation for signature
     * @param sig Signature object
     * @param lerrs list of errors
     * @return true if ok
     */
    public static boolean verifySignatureOCSP(Signature sig, List lerrs)
    {
        boolean bOk = true;
        if(m_logger.isDebugEnabled())
            m_logger.debug("Verifying OCSP for signature: " + sig.getId());
        try {
            if(sig.getUnsignedProperties() != null && sig.getUnsignedProperties().countNotaries() > 0) {
                CertValue cvOcsp = sig.getCertValueOfType(CertValue.CERTVAL_TYPE_RESPONDER);
                CertID cidOcsp = sig.getCertIdOfType(CertID.CERTID_TYPE_RESPONDER);
                X509Certificate rCert = null;
                String sIssuer = null;
                BigInteger sSerial = null;
                if(cvOcsp != null)
                    rCert = cvOcsp.getCert();
                if(cidOcsp != null) {
                    sIssuer = cidOcsp.getIssuer();
                    sSerial = cidOcsp.getSerial();
                }
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Responders cert: " + ((rCert != null) ? rCert.getSerialNumber().toString() : "NULL") + " - " +
                            ((rCert != null) ? rCert.getSubjectDN().getName() : "NULL") +
                            " complete cert refs nr: " + sSerial + " - " + sIssuer +
                            " ca-ahel: " + ((rCert != null) ? (DigiDocGenFactory.isTestCard(rCert) ? "TEST" : "LIVE") : "?"));
                // signer/ocsp live/test verification moved to utility
                if(rCert != null && !rCert.getSerialNumber().equals(sSerial)) {
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Wrong notarys certificate: " + rCert.getSerialNumber() + " ref: " + sSerial);
                    lerrs.add(new DigiDocException(DigiDocException.ERR_RESPONDERS_CERT,
                            "Wrong notarys certificate: " + rCert.getSerialNumber() + " ref: " + sSerial, null));
                    bOk = false;
                }
                // verify notary certs digest using CompleteCertificateRefs
                try {
                    byte[] digest = SignedDoc.digestOfType(rCert.getEncoded(), SignedDoc.SHA1_DIGEST_TYPE);
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Not cert calc hash: " + Base64Util.encode(digest, 0) +
                                " cert-ref hash: " + Base64Util.encode(sig.getUnsignedProperties().getCompleteCertificateRefs().getCertDigestValue(), 0));
                    if(!compareDigests(digest, sig.getUnsignedProperties().getCompleteCertificateRefs().getCertDigestValue())) {
                        lerrs.add(new DigiDocException(DigiDocException.ERR_RESPONDERS_CERT,
                                "Notary certificates digest doesn't match!", null));
                        if(m_logger.isDebugEnabled())
                            m_logger.debug("Notary certificates digest doesn't match!");
                        bOk = false;
                    }
                } catch(DigiDocException ex) {
                    lerrs.add(ex);
                    bOk = false;
                } catch(Exception ex) {
                    bOk = false;
                    lerrs.add(new DigiDocException(DigiDocException.ERR_RESPONDERS_CERT,
                            "Error calculating notary certificate digest!", null));
                }
                // we support only 1 ocsp per signature
                if(sig.getUnsignedProperties().countNotaries() > 1) {
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Currently supports only one OCSP");
                    lerrs.add(new DigiDocException(DigiDocException.ERR_OCSP_VERIFY,
                            "Currently supports only one OCSP", null));
                    bOk = false;
                }

                // verify notarys digest using CompleteRevocationRefs
                try {
                    for(int i = 0; i < sig.getUnsignedProperties().countNotaries(); i++) {
                        if(m_logger.isDebugEnabled())
                            m_logger.debug("Signature: " + sig.getId() + " not: " + i + " notaries: " + sig.getUnsignedProperties().countNotaries());
                        Notary not = sig.getUnsignedProperties().getNotaryById(i);

                        byte[] ocspData = not.getOcspResponseData();
                        if(m_logger.isDebugEnabled())
                               m_logger.debug("OCSP value: " + not.getId() + " data: " + ((ocspData != null) ? ocspData.length : 0) + " bytes");
                        if(ocspData == null || ocspData.length == 0) {
                            lerrs.add(new DigiDocException(DigiDocException.ERR_NOTARY_DIGEST, "OCSP value is empty!", null));
                            bOk = false;
                            continue;
                        }
                        OcspRef orf = sig.getUnsignedProperties().getCompleteRevocationRefs().getOcspRefByUri("#" + not.getId());
                        if(m_logger.isDebugEnabled())
                            m_logger.debug("OCSP ref: " + ((orf != null) ? orf.getUri() : "NULL"));
                        if(orf == null) {
                            lerrs.add(new DigiDocException(DigiDocException.ERR_NOTARY_DIGEST, "No OCSP ref for uri: #" + not.getId(), null));
                            bOk = false;
                            continue;
                        }
                        if(m_logger.isDebugEnabled())
                            m_logger.debug("OCSP data len: " + ocspData.length);
                        byte[] digest1 = SignedDoc.digestOfType(ocspData, SignedDoc.SHA1_DIGEST_TYPE);
                        byte[] digest2 = orf.getDigestValue();
                        if(m_logger.isDebugEnabled())
                            m_logger.debug("Check ocsp: " + not.getId() +
                                    " calc hash: " + Base64Util.encode(digest1, 0) +
                                    " refs-hash: " + Base64Util.encode(digest2, 0));
                        if(!sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_SK_XML) &&
                                !compareDigests(digest1, digest2)) {
                            lerrs.add(new DigiDocException(DigiDocException.ERR_NOTARY_DIGEST,
                                    "Notarys digest doesn't match!", null));
                            if(m_logger.isDebugEnabled())
                                m_logger.debug("Notarys digest doesn't match!");
                            bOk = false;
                        }
                        if(m_logger.isDebugEnabled())
                            m_logger.debug("Check ocsp: " + not.getId() + " prodAt: " +
                                    ((not.getProducedAt() != null) ? ConvertUtils.date2string(not.getProducedAt(), sig.getSignedDoc()) : "NULL") +
                                    " orf prodAt: " + ((orf.getProducedAt() != null) ? ConvertUtils.date2string(orf.getProducedAt(), sig.getSignedDoc()) : "NULL"));
                        if(not.getProducedAt() != null && orf.getProducedAt() != null &&
                                !ConvertUtils.date2string(not.getProducedAt(), sig.getSignedDoc()).
                                        equals(ConvertUtils.date2string(orf.getProducedAt(), sig.getSignedDoc()))) {
                            if(m_logger.isDebugEnabled())
                                m_logger.debug("Notary: " + not.getId() + " producedAt: " +
                                        ((not.getProducedAt() != null) ? ConvertUtils.date2string(not.getProducedAt(), sig.getSignedDoc()) : "NULL") +
                                        " does not match OcpsRef-s producedAt: " + ((orf.getProducedAt() != null) ? ConvertUtils.date2string(orf.getProducedAt(), sig.getSignedDoc()) : "NULL"));
                            lerrs.add(new DigiDocException(DigiDocException.ERR_OCSP_VERIFY, "Notary: " + not.getId() + " producedAt: " +
                                    ((not.getProducedAt() != null) ? ConvertUtils.date2string(not.getProducedAt(), sig.getSignedDoc()) : "NULL") +
                                    " does not match OcpsRef-s producedAt: " + ((orf.getProducedAt() != null) ? ConvertUtils.date2string(orf.getProducedAt(), sig.getSignedDoc()) : "NULL"), null));
                        }
                    }
                    } catch(DigiDocException ex) {
                        lerrs.add(ex);
                        bOk = false;
                    }
                try {
                    NotaryFactory notFac = ConfigManager.instance().getNotaryFactory();
                    for(int i = 0; i < sig.getUnsignedProperties().countNotaries(); i++) {
                        Notary not = sig.getUnsignedProperties().getNotaryById(i);
                        if(m_logger.isDebugEnabled())
                            m_logger.debug("Verify notary: " + not.getId() + " ocsp: " +
                                    ((not.getOcspResponseData() != null) ? not.getOcspResponseData().length : 0) +
                                    " responder: " + not.getResponderId());
                        notFac.parseAndVerifyResponse(sig, not);
                    }
                } catch(DigiDocException ex) {
                    lerrs.add(ex);
                    bOk = false;
                }

            } else {
                bOk = false;
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Signature has no OCSP confirmation!");
                lerrs.add(new DigiDocException(DigiDocException.ERR_NO_CONFIRMATION,
                        "Signature has no OCSP confirmation!", null));
            }
        } catch(Exception ex) {
            if(m_logger.isDebugEnabled())
                m_logger.debug("Failed to verify OCSP for: " + sig.getId());
            lerrs.add(new DigiDocException(DigiDocException.ERR_CERT_EXPIRED,
                    "Failed to verify OCSP for: " + sig.getId(), null));
            bOk = false;
        }
        return bOk;
    }

    /**
     * Verifies signature
     * @param sdoc SignedDoc object
     * @param sig Signature object
     * @param lerrs list of errors
     * @return true if ok
     */
    public static boolean verifySignature(SignedDoc sdoc, Signature sig, List lerrs)
    {
        boolean bOk = true, b = false;
        initProvider();
        if(m_logger.isDebugEnabled())
            m_logger.debug("Verifying signature: " + sig.getId() + " profile: " + sig.getProfile());
        // verify DataFile hashes
        for(int i = 0; i < sdoc.countDataFiles(); i++) {
            DataFile df = sdoc.getDataFile(i);
            if(m_logger.isDebugEnabled())
                m_logger.debug("Verifying DF: " + df.getId() + " file: " + df.getFileName());
            Reference ref = sig.getSignedInfo().getReferenceForDataFile(df);
            if(ref != null) {
                b = verifyDataFileHash(df, ref, lerrs);
            } else {
                b = false;
                lerrs.add(new DigiDocException(DigiDocException.ERR_VERIFY, "Missing Reference for file: " + df.getFileName(), null));
            }
            if(!b) bOk = false;
        }
        // check DF/Ref
        for(int i = 0; i < sdoc.countSignatures(); i++) {
            Signature sig1 = sdoc.getSignature(i);
            for(int j = 0; j < sig.getSignedInfo().countReferences(); j++) {
                Reference ref1 = sig.getSignedInfo().getReference(j);
                if(ref1.getType() != null)
                    continue;
                if((sdoc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML) ||
                        sdoc.getFormat().equals(SignedDoc.FORMAT_SK_XML)) && // ddoc 1.0 formaadis erijuhtumid
                        (ref1.getUri().indexOf("-MIME") != -1 || ref1.getUri().indexOf("-SignedProperties") != -1)) continue;
                boolean bFound = false;
                for(int l = 0; l < sdoc.countDataFiles(); l++) {
                    DataFile df = sdoc.getDataFile(l);
                    String sFile = df.getFileName();
                    if(sFile != null && sFile.indexOf('/') != -1 || sFile.indexOf('\\') != -1) {
                        File fT = new File(sFile);
                        sFile = fT.getName();
                    }
                    if(ref1.getUri() != null) {
                        if((sdoc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML) ||
                                sdoc.getFormat().equals(SignedDoc.FORMAT_SK_XML)) &&
                                ref1.getUri().startsWith("#") &&
                                df.getId().equals(ref1.getUri().substring(1)))
                            bFound = true;
                    }
                }
                if(!bFound) {
                    if(m_logger.isInfoEnabled())
                        m_logger.info("Missing DataFile for signature: " + sig.getId() + " reference " +ref1.getUri());
                    lerrs.add(new DigiDocException(DigiDocException.ERR_VERIFY, "Missing DataFile for signature: " + sig.getId() + " reference " +ref1.getUri(), null));
                }
            }
        }
        // verify <SignedProperties>
        if(!sdoc.getFormat().equals(SignedDoc.FORMAT_SK_XML))
            b = verifySignedPropretiesHash(sig, lerrs);
        if(!b) bOk = false;
        // verify signature value
        b = verifySignatureValue(sdoc, sig, lerrs);
        if(!b) bOk = false;
        // verify signers cert...
        // check the certs validity dates
        b = verifySigningTime(sig, lerrs);
        if(!b) bOk = false;
        // check certificates CA
        b = verifySignersCerificate(sig, lerrs);
        if(!b) bOk = false;
        // verify OCSP
        if(sdoc.getFormat().equals(SignedDoc.FORMAT_SK_XML) ||
                sdoc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML) ||
                (sig.getProfile() != null &&
                        (sig.getProfile().equals(SignedDoc.PROFILE_TM)))) {
            b = verifySignatureOCSP(sig, lerrs);
            if(!b) bOk = false;
        }
        return bOk;
    }

    /**
     * Helper method to parse DN
     * @param dn certificate DN
     * @param chSep separator used
     * @return list of RDN entries
     */
    private static List findRdns(String dn, char chSep)
    {
        List lrdn = new ArrayList();
        StringBuffer sbId = new StringBuffer();
        StringBuffer sbVal = new StringBuffer();
        boolean bId = true; // parsing stage - id or value
        for(int i = 0; (dn != null) && (i < dn.length()); i++) {
            char ch = dn.charAt(i);
            // RDN end found
            if(( (ch == chSep) &&
                    (i == 0 || dn.charAt(i-1) != '\\')) || (i == dn.length()-1)) {
                if(i == dn.length()-1 && !bId)
                    sbVal.append(ch);
                if(sbId.length() > 0 && sbVal.length() > 0)
                    lrdn.add(new Rdn(sbId.toString().trim(), null, sbVal.toString().trim()));
                sbId = new StringBuffer();
                sbVal = new StringBuffer();
                bId = true;
            } else if(ch == '=' && (i == 0 || dn.charAt(i-1) != '\\')) {
                bId = false;
            } else { // handle content
                if(bId)
                    sbId.append(ch);
                else
                    sbVal.append(ch);
            }
        }
        return lrdn;
    }

    /**
     * Parses a DN normalized by rules of RFC2253 and returns a set of
     * Rdn objects containing RDN-s and values found in this DN
     * @param dn normalized DN string
     * @return array of Rdn objects
     */
    public static List parseDN(String dn)
    {
        // try first according to RFC2253
        List al = findRdns( dn, ',');
        if(al.size() < 3) // if not successfull try RFC1770
            al = findRdns( dn, '/');
        return al;
    }



}
