package org.digidoc4j.ddoc.factory;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.*;
import org.digidoc4j.ddoc.utils.ConvertUtils;

import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;

/**
 * Factory class to handle generating signature elements according to
 * required signature type and version or in case of bdoc the profile
 * @author Veiko Sinivee
 */
public class DigiDocGenFactory {
    //private SignedDoc m_sdoc;
    private static Logger m_logger = Logger.getLogger(DigiDocGenFactory.class);
    private static final String DIGI_OID_LIVE_TEST = "1.3.6.1.4.1.10015.1.2";
    private static final String DIGI_OID_TEST_TEST = "1.3.6.1.4.1.10015.3.2";

    public static final String[] TEST_OIDS_PREFS = {
            "1.3.6.1.4.1.10015.3.7", "1.3.6.1.4.1.10015.7", // tempel test
            "1.3.6.1.4.1.10015.3.3", "1.3.6.1.4.1.10015.3.11", // mid test
            "1.3.6.1.4.1.10015.3.2", // digi-id test
            "1.3.6.1.4.1.10015.3.1" // est-eid test

    };

    private static boolean certHasPolicy(X509Certificate cert, String sOid)
    {
        try {
            if(m_logger.isDebugEnabled())
                m_logger.debug("Read cert policies: " + cert.getSerialNumber().toString());
            ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
            ASN1InputStream aIn = new ASN1InputStream(bIn);
            ASN1Sequence seq = (ASN1Sequence)aIn.readObject();
            X509CertificateStructure obj = new X509CertificateStructure(seq);
            TBSCertificateStructure tbsCert = obj.getTBSCertificate();
            if (tbsCert.getVersion() == 3) {
                X509Extensions ext = tbsCert.getExtensions();
                if (ext != null) {
                    Enumeration en = ext.oids();
                    while (en.hasMoreElements()) {
                        Object o = en.nextElement();
                        if(o instanceof ASN1ObjectIdentifier) {
                            ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)o;
                            X509Extension extVal = ext.getExtension(oid);
                            ASN1OctetString oct = extVal.getValue();
                            ASN1InputStream extIn = new ASN1InputStream(new ByteArrayInputStream(oct.getOctets()));
                            //if (oid.equals(X509Extensions.CertificatePolicies)) { // bc 146 ja jdk 1.6 puhul - X509Extension.certificatePolicies
                            if(oid.equals(X509Extension.certificatePolicies)) { // bc 146 ja jdk 1.6 puhul - X509Extension.certificatePolicies
                                ASN1Sequence cp = (ASN1Sequence)extIn.readObject();
                                for (int i = 0; i != cp.size(); i++) {
                                    PolicyInformation pol = PolicyInformation.getInstance(cp.getObjectAt(i));
                                    //DERObjectIdentifier dOid = null;
                                    if(pol != null) {
                                        String sId = pol.getPolicyIdentifier().getId();
                                        if(sId != null) {
                                            if(m_logger.isDebugEnabled())
                                                m_logger.debug("Policy: " + sId);
                                            if(sId.startsWith(sOid))
                                                return true;
                                        }
                                    }
                                }
                            }
                        } // instanceof
                    }
                }

            }
        } catch(Exception ex) {
            m_logger.error("Error reading cert policies: " + ex);
        }
        return false;
    }

    public static boolean isPre2011IdCard(X509Certificate cert) {
        return ((cert != null) && (cert.getPublicKey() instanceof RSAPublicKey) &&
                (((RSAPublicKey)cert.getPublicKey()).getModulus().bitLength() == 1024) &&
                //cert.getPublicKey().getEncoded().length <= PRE2011_KEYLEN);
                !certHasPolicy(cert, DIGI_OID_LIVE_TEST) && !certHasPolicy(cert, DIGI_OID_TEST_TEST));
    }

    public static boolean isTestCard(X509Certificate cert) {
        if(cert != null) {
            String cn = ConvertUtils.getCommonName(cert.getSubjectDN().getName());
            //if(cn != null && cn.indexOf("TEST") != -1)
            //	return true;
            for(int i = 0; i < TEST_OIDS_PREFS.length; i++) {
                String sOid = TEST_OIDS_PREFS[i];
                if(i == 1) {
                    if(certHasPolicy(cert, sOid) && cn != null && cn.indexOf("TEST") != -1)
                        return true;
                } else {
                    if(certHasPolicy(cert, sOid))
                        return true;
                }
            }
        }
        return false;
    }

}
