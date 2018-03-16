/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.signers;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.apache.commons.codec.binary.Base64;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Container;
import org.digidoc4j.DataToSign;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.Certificates;
import org.digidoc4j.test.util.TestSigningUtil;
import org.digidoc4j.utils.Helper;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import eu.europa.esig.dss.DSSUtils;

public class ExternalSignerTest extends AbstractTest {

  @Test
  public void testGetCertificate() throws Exception {
    X509Certificate certificate = DSSUtils.loadCertificate(Base64.decodeBase64(Certificates.SIGNING_CERTIFICATE)).getCertificate();
    ExternalSigner externalSigner = new ExternalSigner(certificate) {

      @Override
      public byte[] sign(DigestAlgorithm digestAlgorithm, byte[] dataToSign) {
        return new byte[0];
      }

    };
    Assert.assertEquals(Certificates.SIGNING_CERTIFICATE, Base64.encodeBase64String(externalSigner.getCertificate().getEncoded()));
  }

  @Test
  @Ignore // TODO Fix me when possible
  public void testAsyncSigning() {
    Container container = this.createNonEmptyContainer();
    DataToSign dataToSign = SignatureBuilder.aSignature(container).withSigningCertificate(this.pkcs12SignatureToken.getCertificate()).
        buildDataToSign();
    String containerFile = this.getFileBy("bin");
    String dataToSignFile = this.getFileBy("bin");
    Helper.serialize(container, containerFile);
    Helper.serialize(dataToSign, dataToSignFile);
    byte[] signatureValue = this.getExternalSignatureToken().sign(dataToSign.getDigestAlgorithm(), dataToSign.getDataToSign());
    container = Helper.deserializer(containerFile);
    dataToSign = Helper.deserializer(dataToSignFile);
    Signature signature = dataToSign.finalize(signatureValue);
    container.addSignature(signature);
    container.saveAsFile(this.getFileBy("bdoc"));
  }

  /*
   * RESTRICTED METHODS
   */

  private SignatureToken getExternalSignatureToken() {
    return new ExternalSigner(this.pkcs12SignatureToken.getCertificate()) {

      @Override
      public byte[] sign(DigestAlgorithm digestAlgorithm, byte[] dataToSign) {
        try {
          KeyStore keyStore = KeyStore.getInstance("PKCS12");
          try (FileInputStream stream = new FileInputStream("src/test/resources/testFiles/p12/signout.p12")) {
            keyStore.load(stream, "test".toCharArray());
          }
          PrivateKey privateKey = (PrivateKey) keyStore.getKey("1", "test".toCharArray());
          return TestSigningUtil.encrypt(String.format("NONEwith%s", privateKey.getAlgorithm()), privateKey, TestSigningUtil.addPadding(dataToSign));
        } catch (Exception e) {
          throw new DigiDoc4JException("Loading private key failed", e);
        }
      }

    };
  }

}
