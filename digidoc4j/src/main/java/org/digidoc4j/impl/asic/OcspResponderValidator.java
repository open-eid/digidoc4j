package org.digidoc4j.impl.asic;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.digidoc4j.Configuration;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.CertificateNotFoundException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.asic.xades.XadesSignature;

import java.security.cert.CertificateEncodingException;

/**
 * Validator of OCSP responder for TM
 */
public class OcspResponderValidator {

    private XadesSignature signature;
    private Configuration configuration;

    /**
     * Constructor of the validator
     *
     * @param signature Xades signature object
     */
    public OcspResponderValidator(XadesSignature signature, Configuration configuration) {
        this.signature = signature;
        this.configuration = configuration;
    }

    /**
     * Method for asking if OCSP responder is valid or not.
     *
     * @return True if OCSP response is valid, false otherwise.
     */
    public boolean isValid() {
        if (SignatureProfile.LT_TM != signature.getProfile()) {
            return true;
        }
        try {
            return isOcspResponserCommonNameValid(signature.getOCSPCertificate());
        } catch (CertificateNotFoundException e) {
            return false;
        }

    }

    private boolean isOcspResponserCommonNameValid(X509Cert ocspCertificate) {
        try {
            X500Name x500name = new JcaX509CertificateHolder(ocspCertificate.getX509Certificate()).getSubject();
            RDN dn = x500name.getRDNs(BCStyle.CN)[0];
            String commonName =  IETFUtils.valueToString(dn.getFirst().getValue());
            return configuration.getAllowedOcspRespondersForTM().contains(commonName);
        } catch (CertificateEncodingException e) {
            throw new DigiDoc4JException("OCSP certificate encoding failed ", e);
        }
    }

}
