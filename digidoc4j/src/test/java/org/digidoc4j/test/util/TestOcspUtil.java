package org.digidoc4j.test.util;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.security.PrivateKey;
import java.time.Instant;
import java.util.Date;

public final class TestOcspUtil {

  public static BasicOCSPRespBuilder createBasicOCSPRespBuilder(X500Name responderSubjectDn) {
    return new BasicOCSPRespBuilder(new RespID(responderSubjectDn));
  }

  public static BasicOCSPRespBuilder createBasicOCSPRespBuilder(X509CertificateHolder responderCertificate) {
    return createBasicOCSPRespBuilder(responderCertificate.getSubject());
  }

  public static ContentSigner createOcspSigner(PrivateKey privateKey, String signatureAlgorithm) {
    try {
      return new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(privateKey);
    } catch (OperatorCreationException e) {
      throw new IllegalStateException("Failed to create OCSP signer", e);
    }
  }

  public static BasicOCSPResp buildBasicOCSPResp(BasicOCSPRespBuilder builder, ContentSigner ocspSigner, Instant time, X509CertificateHolder[] certificateChain) {
    try {
      return builder.build(ocspSigner, certificateChain, Date.from(time));
    } catch (OCSPException e) {
      throw new IllegalStateException("Failed to build basic OCSP response", e);
    }
  }

  public static BasicOCSPResp buildBasicOCSPResp(BasicOCSPRespBuilder builder, ContentSigner ocspSigner, X509CertificateHolder... certificateChain) {
    return buildBasicOCSPResp(builder, ocspSigner, Instant.now(), certificateChain);
  }

  public static OCSPResp buildSuccessfulOCSPResp(BasicOCSPResp basicOCSPResp) {
    try {
      return new OCSPRespBuilder().build(OCSPResp.SUCCESSFUL, basicOCSPResp);
    } catch (OCSPException e) {
      throw new IllegalStateException("Failed to build OCSP response", e);
    }
  }

  private TestOcspUtil() {}

}
