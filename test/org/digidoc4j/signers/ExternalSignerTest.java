package org.digidoc4j.signers;

import org.apache.commons.codec.binary.Base64;
import org.digidoc4j.Container;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.impl.Certificates;
import org.junit.Test;
import sun.security.x509.X509CertImpl;

import static org.junit.Assert.assertEquals;


public class ExternalSignerTest {

  @Test
  public void testGetCertificate() throws Exception {
    X509CertImpl cert = new X509CertImpl(Base64.decodeBase64(Certificates.SIGNING_CERTIFICATE));

    ExternalSigner externalSigner = new ExternalSigner(cert) {
      @Override
      public byte[] sign(Container container, byte[] dataToSign) {
        return new byte[0];
      }
    };
    byte[] certificateBytes = externalSigner.getCertificate().getEncoded();

    assertEquals(Certificates.SIGNING_CERTIFICATE, Base64.encodeBase64String(certificateBytes));
  }

  @Test(expected = NotSupportedException.class)
  public void testGetPrivateKey() throws Exception {

    X509CertImpl cert = new X509CertImpl(Base64.decodeBase64(Certificates.SIGNING_CERTIFICATE));

    ExternalSigner externalSigner = new ExternalSigner(cert) {
      @Override
      public byte[] sign(Container container, byte[] dataToSign) {
        return new byte[0];
      }
    };

    externalSigner.getPrivateKey();
  }
}