/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.bdoc.xades;

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SignerLocation;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.impl.asic.xades.XadesSigningDssFacade;
import org.digidoc4j.test.TestAssert;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import static eu.europa.esig.dss.enumerations.DigestAlgorithm.SHA256;
import static eu.europa.esig.dss.enumerations.SignatureLevel.XAdES_BASELINE_B;
import static eu.europa.esig.dss.enumerations.SignatureLevel.XAdES_BASELINE_LT;
import static org.apache.commons.codec.binary.Base64.decodeBase64;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XadesSigningDssFacadeTest extends AbstractTest {

  private XadesSigningDssFacade facade;

  @Test
  void getDataToSign() throws Exception {
    facade = new XadesSigningDssFacade();
    byte[] dataToSign = getDataToSign(facade);
    assertNotNull(dataToSign);
    assertTrue(dataToSign.length > 0);
  }

  @Test
  void signDocumentTest() throws Exception {
    TestAssert.assertDSSDocumentIsSigned(sign(facade, DigestAlgorithm.SHA256));
  }

  @Test
  void signDocumentWithSha512() throws Exception {
    facade.setSignatureDigestAlgorithm(DigestAlgorithm.SHA512);
    TestAssert.assertDSSDocumentIsSigned(sign(facade, DigestAlgorithm.SHA512));
  }

  @Test
  void signDocumentWithECC() throws Exception {
    X509Certificate signingCert = pkcs12EccSignatureToken.getCertificate();
    facade.setEncryptionAlgorithm(EncryptionAlgorithm.ECDSA);
    facade.setSigningCertificate(signingCert);
    List<DataFile> dataFilesToSign = createDataFilesToSign();
    byte[] dataToSign = facade.getDataToSign(dataFilesToSign);
    byte[] signatureValue = pkcs12EccSignatureToken.sign(DigestAlgorithm.SHA256, dataToSign);
    TestAssert.assertDSSDocumentIsSigned(facade.signDocument(signatureValue, dataFilesToSign));
  }

  @Test
  void signWithSignerInformation() throws Exception {
    SignerLocation signerLocation = new SignerLocation();
    signerLocation.setCountry("Val Verde");
    signerLocation.setPostalCode("1776");
    signerLocation.setLocality("Kansas City");
    facade.setSignerLocation(signerLocation);
    facade.setSignerRoles(Arrays.asList("manager", "potato expert"));
    TestAssert.assertDSSDocumentIsSigned(sign(facade, DigestAlgorithm.SHA256));
  }

  @Test
  void signWithSignaturePolicy() throws IOException {
    Policy signaturePolicy = new Policy();
    signaturePolicy.setId("urn:oid:1.3.6.1.4.1.10015.1000.3.2.1");
    signaturePolicy.setDigestValue(decodeBase64("3Tl1oILSvOAWomdI9VeWV6IA/32eSXRUri9kPEz1IVs="));
    signaturePolicy.setDigestAlgorithm(SHA256);
    signaturePolicy.setSpuri("https://www.sk.ee/repository/bdoc-spec21.pdf");
    facade.setSignaturePolicy(signaturePolicy);
    TestAssert.assertDSSDocumentIsSigned(sign(facade, DigestAlgorithm.SHA256));
  }

  @Test
  void signWithBesSignatureProfile() throws Exception {
    facade.setSignatureLevel(XAdES_BASELINE_B);
    TestAssert.assertDSSDocumentIsSigned(sign(facade, DigestAlgorithm.SHA256));
  }

  @Test
  void setSignatureId() throws Exception {
    facade.setSignatureId("Signature-0");
    TestAssert.assertDSSDocumentIsSigned(sign(facade, DigestAlgorithm.SHA256));
  }

  @Test
  void extendBesSignature_toTimestampSignature() throws Exception {
    facade.setSignatureLevel(XAdES_BASELINE_B);
    DSSDocument signedDocument = sign(facade, DigestAlgorithm.SHA256);
    XadesSigningDssFacade extendingFacade = createSigningFacade();
    extendingFacade.setSignatureLevel(XAdES_BASELINE_LT);
    DSSDocument detachedContent = new FileDocument("src/test/resources/testFiles/helper-files/test.txt");
    TestAssert.assertDSSDocumentIsSigned(extendingFacade.extendSignature(signedDocument, Arrays.asList(detachedContent)));
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
    facade = createSigningFacade();
  }

}
