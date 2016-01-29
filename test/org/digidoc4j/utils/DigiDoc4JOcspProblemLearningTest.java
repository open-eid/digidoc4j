package org.digidoc4j.utils;

import static org.digidoc4j.ContainerBuilder.BDOC_CONTAINER_TYPE;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Collections;

import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.EncryptionAlgorithm;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.SignedInfo;
import org.junit.Ignore;
import org.junit.Test;

import ee.sk.utils.ConvertUtils;

public class DigiDoc4JOcspProblemLearningTest {
    final X509Certificate SIGN_CERT = Certificates.getCertFromPEMFormat("-----BEGIN CERTIFICATE-----\r\n"
            + "MIIEqDCCA5CgAwIBAgIQXZSW5EBkctNPfCkprF2XsTANBgkqhkiG9w0BAQUFADBs\r\n" + "MQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1\r\n"
            + "czEfMB0GA1UEAwwWVEVTVCBvZiBFU1RFSUQtU0sgMjAxMTEYMBYGCSqGSIb3DQEJ\r\n" + "ARYJcGtpQHNrLmVlMB4XDTEyMDQwNDEwNTc0NFoXDTE1MDQwNDIwNTk1OVowga4x\r\n"
            + "CzAJBgNVBAYTAkVFMRswGQYDVQQKDBJFU1RFSUQgKE1PQklJTC1JRCkxGjAYBgNV\r\n" + "BAsMEWRpZ2l0YWwgc2lnbmF0dXJlMSgwJgYDVQQDDB9URVNUTlVNQkVSLFNFSVRT\r\n"
            + "TUVTLDE0MjEyMTI4MDI1MRMwEQYDVQQEDApURVNUTlVNQkVSMREwDwYDVQQqDAhT\r\n" + "RUlUU01FUzEUMBIGA1UEBRMLMTQyMTIxMjgwMjUwgZ8wDQYJKoZIhvcNAQEBBQAD\r\n"
            + "gY0AMIGJAoGBAMFo0cOULrm6HHJdMsyYVq6bBmCU4rjg8eonNnbWNq9Y0AAiyIQv\r\n" + "J3xDULnfwJD0C3QI8Y5RHYnZlt4U4Yt4CI6JenMySV1hElOtGYP1EuFPf643V11t\r\n"
            + "/mUDgY6aZaAuPLNvVYbeVHv0rkunKQ+ORABjhANCvHaErqC24i9kv3mVAgMBAAGj\r\n" + "ggGFMIIBgTAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIGQDCBmQYDVR0gBIGRMIGO\r\n"
            + "MIGLBgorBgEEAc4fAwEBMH0wWAYIKwYBBQUHAgIwTB5KAEEAaQBuAHUAbAB0ACAA\r\n" + "dABlAHMAdABpAG0AaQBzAGUAawBzAC4AIABPAG4AbAB5ACAAZgBvAHIAIAB0AGUA\r\n"
            + "cwB0AGkAbgBnAC4wIQYIKwYBBQUHAgEWFWh0dHA6Ly93d3cuc2suZWUvY3BzLzAn\r\n" + "BgNVHREEIDAegRxzZWl0c21lcy50ZXN0bnVtYmVyQGVlc3RpLmVlMB0GA1UdDgQW\r\n"
            + "BBSBiUUnibDAPTHAuhRAwSvWzPfoEjAYBggrBgEFBQcBAwQMMAowCAYGBACORgEB\r\n" + "MB8GA1UdIwQYMBaAFEG2/sWxsbRTE4z6+mLQNG1tIjQKMEUGA1UdHwQ+MDwwOqA4\r\n"
            + "oDaGNGh0dHA6Ly93d3cuc2suZWUvcmVwb3NpdG9yeS9jcmxzL3Rlc3RfZXN0ZWlk\r\n" + "MjAxMS5jcmwwDQYJKoZIhvcNAQEFBQADggEBAKPzonf5auRAC8kX6zQTX0yYeQvv\r\n"
            + "l2bZdbMmDAp07g3CxEaC6bk8DEx9pOJR2Wtm7J9wQke6+HpLEGgNVTAllm+oE4sU\r\n" + "VsaIqFmrcqilWqeWIpj5uR/yU4GDDD9jAGFZtOLaFgaGCwE5++q/LZhosyyAGgvD\r\n"
            + "yl+yGm5IxTRQ9uflppNZ7k2LoFkoDJhgqHqMZQjwN1kJQ/VBReCRMGUVj5wkBLTJ\r\n" + "o9GcMiugyKQib9I6vV9TdemUXKgL+MYp2S8LeIBt0eUXvpp8n/3HIKJIyJpdVvK1\r\n"
            + "wX5bWYM2o6dT7FAftrkVnShTsEACuRBYSi/4a4hTsSeQTa2Oz1GoNZ7ADXI=\r\n" + "-----END CERTIFICATE-----");

    final PrivateKey PRIVATE_KEY_FOR_SIGN_CERT = parsePrivateKey("-----BEGIN RSA PRIVATE KEY-----\r\n"
            + "MIICXQIBAAKBgQDBaNHDlC65uhxyXTLMmFaumwZglOK44PHqJzZ21javWNAAIsiE\r\n" + "Lyd8Q1C538CQ9At0CPGOUR2J2ZbeFOGLeAiOiXpzMkldYRJTrRmD9RLhT3+uN1dd\r\n"
            + "bf5lA4GOmmWgLjyzb1WG3lR79K5LpykPjkQAY4QDQrx2hK6gtuIvZL95lQIDAQAB\r\n" + "AoGBAK4JABgZUyJU0hwmuPtZaUacwNRPpOPvpj+pIV01zOdj52b35a7sL3+loxJe\r\n"
            + "wQyuTVAQbCw/2XCdlyAncfzp+eeUehVACSJ0TTsCeNSDwRzwl5i1qubmk8kf1oFJ\r\n" + "GxRvkQJtYoPdcGXIwlohwP1u5RxQhCO4NCiJtZ+IxunCMFeBAkEA/9LMk9waSa0i\r\n"
            + "xiPqgfvfLjg+cqCQr3PJXmhpRxhUUrzf9b/NmvnK/o41IUGuneSjRXnOJqyG9RND\r\n" + "Q+kAwwGaOQJBAMGK/hKv3DhEW72rBlIFfB+Ow1G/YA42xmodHgi9FIYPsmunmnWR\r\n"
            + "/+Bm9LtfNlzM/LjFIbrOWRwS3CCw+I4Tij0CQHWNxSoQkxfV8kvAR0txlO2lNLTx\r\n" + "qWqmNxsluXLM8DqQxg0kFPOo4ymz6SAeEYJGhOww+5Tz5JQLRPaYxBvXyakCQDVP\r\n"
            + "l9SF5F8LVUnVRhRptlrq9BocYNUJeXXZN2Co1HJo+Hh23jDsWlLxiQ/jlhHR1PsA\r\n" + "Md5G4Hy/JStME+rurvECQQDafAxtKwDOtZWw1IrkxsetfecBZfad1Q0EM48xCcaI\r\n"
            + "TIgu2Su5JCXBtrJ7dQyBSh8lilAGuvCiwqyJ8cxJg4LF\r\n" + "-----END RSA PRIVATE KEY-----\r\n");

    @Test
	@Ignore
    public void signingTwiceCausesAProblemWithOCSP() {
        sign();
        sign();
    }

    protected void sign() {
        Container container = ContainerBuilder.
            aContainer(BDOC_CONTAINER_TYPE).
            withConfiguration(createDigiDoc4JConfiguration()).
            withDataFile(new ByteArrayInputStream("file contents".getBytes()), "file.txt", "application/octet-stream").
            build();
        byte[] hashToSign = prepareSigning(container, SIGN_CERT, createSignatureParameters());
        byte[] signatureValue = signWithRsa(PRIVATE_KEY_FOR_SIGN_CERT, hashToSign);
        container.signRaw(signatureValue);
    }

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
        result.setOcspSource(Configuration.TEST_OCSP_URL);
        result.setTSL(new Certificates().getTslCertificateSource());
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

    protected byte[] prepareSigning(Container container, X509Certificate signingCertificate, SignatureParameters signatureParameters) {
        container.setSignatureParameters(signatureParameters);
        SignedInfo signedInfo = container.prepareSigning(signingCertificate);
        return signedInfo.getDigest();
    }

    public static PrivateKey parsePrivateKey(Reader privateKey) {
        try (PEMParser pemParser = new PEMParser(privateKey)) {
            PEMKeyPair keyPair = (PEMKeyPair) pemParser.readObject();
            return new JcaPEMKeyConverter().getKeyPair(keyPair).getPrivate();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static PrivateKey parsePrivateKey(String privateKey) {
        return parsePrivateKey(new StringReader(privateKey));
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
