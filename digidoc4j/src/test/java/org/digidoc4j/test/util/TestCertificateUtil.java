package org.digidoc4j.test.util;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;

public final class TestCertificateUtil {

    public static JcaX509v3CertificateBuilder createX509v3CertificateBuilder(
            X500Name issuer, BigInteger serial, Instant notBefore, Instant notAfter, X500Name subject, PublicKey publicKey
    ) {
        Objects.requireNonNull(notAfter, "NotAfter not provided");
        Objects.requireNonNull(subject, "Subject not provided");
        Objects.requireNonNull(publicKey, "Public key not provided");
        return new JcaX509v3CertificateBuilder(
                (issuer != null) ? issuer : subject,
                (serial != null) ? serial : generateSerial(64),
                Date.from(notBefore != null ? notBefore : Instant.now()),
                Date.from(notAfter),
                subject,
                publicKey
        );
    }

    public static ContentSigner createCertificateSigner(PrivateKey privateKey, String signatureAlgorithm) {
        try {
            return new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(privateKey);
        } catch (OperatorCreationException e) {
            throw new IllegalStateException("Failed to create certificate signer", e);
        }
    }

    public static X509Certificate toX509Certificate(X509CertificateHolder x509CertificateHolder) {
        try {
            return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);
        } catch (CertificateException e) {
            throw new IllegalStateException("Failed to convert certificate", e);
        }
    }

    public static BigInteger generateSerial(int size) {
        byte[] serialBytes = new byte[size];
        ThreadLocalRandom.current().nextBytes(serialBytes);
        return new BigInteger(1, serialBytes);
    }

    private TestCertificateUtil() {}

}
