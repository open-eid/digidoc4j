/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.test;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.test.util.TestCertificateUtil;

import java.io.IOException;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Objects;

public class TestSignatureToken implements SignatureToken {

  private final PrivateKey privateKey;
  private final X509Certificate x509Certificate;

  public TestSignatureToken(PrivateKey privateKey, X509Certificate x509Certificate) {
    this.privateKey = Objects.requireNonNull(privateKey, "Private key cannot be null");
    this.x509Certificate = Objects.requireNonNull(x509Certificate, "Certificate cannot be null");
  }

  public TestSignatureToken(PrivateKey privateKey, X509CertificateHolder x509CertificateHolder) {
    this(privateKey, TestCertificateUtil.toX509Certificate(x509CertificateHolder));
  }

  @Override
  public X509Certificate getCertificate() {
    return x509Certificate;
  }

  @Override
  public byte[] sign(DigestAlgorithm digestAlgorithm, byte[] dataToSign) {
    ContentSigner contentSigner = createContentSigner(eu.europa.esig.dss.enumerations.DigestAlgorithm.forXML(digestAlgorithm.toString()));
    try (OutputStream out = contentSigner.getOutputStream()) {
      out.write(dataToSign);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to write signable data to content signer", e);
    }
    return contentSigner.getSignature();
  }

  @Override
  public void close() {
    // Do nothing
  }

  private ContentSigner createContentSigner(eu.europa.esig.dss.enumerations.DigestAlgorithm digestAlgorithm) {
    String signatureAlgorithm = String.format("%swith%s", digestAlgorithm.getName(), privateKey.getAlgorithm());
    try {
      return new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(privateKey);
    } catch (OperatorCreationException e) {
      throw new IllegalStateException("Failed to create content signer", e);
    }
  }

}
