package org.digidoc4j.ddoc.utils;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.digidoc4j.ddoc.Base64Util;
import org.digidoc4j.ddoc.DigiDocException;
import org.digidoc4j.ddoc.SignedDoc;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

public final class BouncyCastleNotaryUtil {
    private static final Logger m_logger = LoggerFactory.getLogger(BouncyCastleNotaryUtil.class);

    private BouncyCastleNotaryUtil() {
        //utility class
    }

    /**
     * Method to get NONCE array from responce
     *
     * @param basResp basic OCSP response
     * @return OCSP nonce value
     */
    public static byte[] getNonce(BasicOCSPResp basResp, SignedDoc sdoc) {
        if (basResp != null) {
            try {
                byte[] nonce2 = null;
                Set extOids = basResp.getNonCriticalExtensionOIDs();
                boolean bAsn1 = false;
                String sType = null;

                if (m_logger.isDebugEnabled())
                    m_logger.debug("Nonce exts: " + extOids.size());

                if (extOids.size() >= 1) {
                    Extension ext = basResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
                    if (ext != null) {
                        if (m_logger.isDebugEnabled())
                            m_logger.debug("Ext: " + ext.getExtnId() + " val-len: " + ((ext.getExtnValue() != null) ? ext.getExtnValue().getOctets().length : 0));
                        if (ext.getExtnValue() != null && ext.getExtnValue().getOctets() != null && ext.getExtnValue().getOctets().length == 20) {
                            nonce2 = ext.getExtnValue().getOctets();
                            m_logger.debug("Raw nonce len: " + ((nonce2 != null) ? nonce2.length : 0));
                        } else {
                            ASN1Encodable extObj = ext.getParsedValue();
                            nonce2 = extObj.toASN1Primitive().getEncoded();
                        }
                    }
                }

                boolean bCheckOcspNonce = ConfigManager.instance().getBooleanProperty("CHECK_OCSP_NONCE", false);

                if (sdoc != null && sdoc.getFormat() != null && sdoc.getFormat().equals(SignedDoc.FORMAT_SK_XML))
                    bCheckOcspNonce = false;

                if (m_logger.isDebugEnabled() && nonce2 != null)
                    m_logger.debug("Nonce hex: " + ConvertUtils.bin2hex(nonce2) + " b64: " + Base64Util.encode(nonce2) + " len: " + nonce2.length + " asn1: " + bAsn1);

                if (sdoc == null || sdoc.getFormat() != null && sdoc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML)) {
                    if (nonce2 != null && nonce2.length == 22) { //  nonce2[0] == V_ASN1_OCTET_STRING
                        byte[] b = new byte[20];
                        System.arraycopy(nonce2, nonce2.length - 20, b, 0, 20);
                        nonce2 = b;
                        bAsn1 = true;
                        sType = "ASN1-NONCE";
                    }
                }

                if (m_logger.isDebugEnabled() && nonce2 != null)
                    m_logger.debug("Nonce hex: " + ConvertUtils.bin2hex(nonce2) + " b64: " + Base64Util.encode(nonce2) + " len: " + nonce2.length + " type: " + sType);
                else
                    m_logger.debug("No nonce");

                if (!bAsn1 && bCheckOcspNonce) {
                    throw new DigiDocException(DigiDocException.ERR_OCSP_NONCE,
                            "Invalid nonce: " + ((nonce2 != null) ? ConvertUtils.bin2hex(nonce2) + " length: " + nonce2.length : "NO-NONCE") + "!", null);
                }
                return nonce2;
            } catch (Exception ex) {
                m_logger.error("Error reading ocsp nonce: " + ex);
                ex.printStackTrace();
                return null;
            }
        } else
            return null;
    }

    /**
     * Method that checks if Signed Doc is applicable for OCSP nonce related activities
     *
     * @param signedDoc Signed Doc
     * @return true if applicable, false otherwise
     */
    public static boolean isApplicableFormatForOcspNonce(SignedDoc signedDoc) {
        if (signedDoc == null) {
            m_logger.warn("Signed Doc is null, unable to determine if applicable for OCSP nonce");
            return false;
        }
        return SignedDoc.FORMAT_SK_XML.equals(signedDoc.getFormat()) || SignedDoc.FORMAT_DIGIDOC_XML.equals(signedDoc.getFormat());
    }
}
