package org.digidoc4j.utils;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Collections;

import org.digidoc4j.Configuration;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.EncryptionAlgorithm;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.SignedInfo;
import org.digidoc4j.impl.BDocContainer;

import ee.sk.utils.ConvertUtils;

public abstract class AbstractSigningTests {
    protected SignatureParameters createSignatureParameters() {
        SignatureParameters signatureParameters = new SignatureParameters();
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setSignatureId("S0");
        signatureParameters.setProductionPlace(new org.digidoc4j.SignatureProductionPlace("", "", "", ""));
        signatureParameters.setRoles(Collections.<String> emptyList());
        signatureParameters.setEncryptionAlgorithm(EncryptionAlgorithm.RSA);
        return signatureParameters;
    }

    protected Configuration createDigiDoc4JConfiguration() {
        Configuration result = new ConfigurationWithIpBasedAccess();
        result.setOcspSource("http://www.openxades.org/cgi-bin/ocsp.cgi");
        result.setTSL(new CertificatesForTests().getTslCertificateSource());
        return result;
    }

    public static byte[] signWithRsa(PrivateKey privateKey, byte[] hashToSign) {
        try {
            return signWithRsaWithoutPrefix(ConvertUtils.addDigestAsn1Prefix(hashToSign), privateKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] signWithRsaWithoutPrefix(byte[] hashWithPrefix, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException,
            IOException, SignatureException {
        java.security.Signature newSignature = java.security.Signature.getInstance("RSA");
        newSignature.initSign(privateKey);
        newSignature.update(hashWithPrefix);
        return newSignature.sign();
    }

    protected byte[] prepareSigning(BDocContainer container, X509Certificate signingCertificate, SignatureParameters signatureParameters) {
        container.setSignatureParameters(signatureParameters);
        SignedInfo signedInfo = container.prepareSigning(signingCertificate);
        return signedInfo.getDigest();
    }

    private static class ConfigurationWithIpBasedAccess extends Configuration {
        public ConfigurationWithIpBasedAccess() {
            super(Mode.PROD);

            getJDigiDocConfiguration().put("SIGN_OCSP_REQUESTS", Boolean.toString(false));
        }

        @Override
        public boolean hasToBeOCSPRequestSigned() {
            return false;
        }
    }
}
