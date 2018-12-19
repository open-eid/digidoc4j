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

import static eu.europa.esig.dss.DigestAlgorithm.SHA256;
import static eu.europa.esig.dss.SignatureLevel.XAdES_BASELINE_B;
import static eu.europa.esig.dss.SignatureLevel.XAdES_BASELINE_LT;
import static org.apache.commons.codec.binary.Base64.decodeBase64;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.impl.asic.xades.XadesSigningDssFacade;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.digidoc4j.test.TestAssert;
import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.Policy;
import eu.europa.esig.dss.SignerLocation;

public class XadesSigningDssFacadeTest extends AbstractTest {

  private XadesSigningDssFacade facade;

  @Test
  public void getDataToSign() throws Exception {
    this.facade = new XadesSigningDssFacade();
    byte[] dataToSign = this.getDataToSign(this.facade);
    Assert.assertNotNull(dataToSign);
    Assert.assertTrue(dataToSign.length > 0);
  }

  @Test
  public void signDocumentTest() throws Exception {
    TestAssert.assertDSSDocumentIsSigned(this.sign(this.facade, DigestAlgorithm.SHA256));
  }

  @Test
  public void signDocumentWithSha512() throws Exception {
    this.facade.setSignatureDigestAlgorithm(DigestAlgorithm.SHA512);
    TestAssert.assertDSSDocumentIsSigned(this.sign(this.facade, DigestAlgorithm.SHA512));
  }

  @Test
  public void signDocumentWithECC() throws Exception {
    PKCS12SignatureToken eccSignatureToken = new PKCS12SignatureToken("src/test/resources/testFiles/p12/MadDogOY.p12", "test".toCharArray());
    X509Certificate signingCert = eccSignatureToken.getCertificate();
    this.facade.setEncryptionAlgorithm(EncryptionAlgorithm.ECDSA);
    this.facade.setSigningCertificate(signingCert);
    List<DataFile> dataFilesToSign = this.createDataFilesToSign();
    byte[] dataToSign = this.facade.getDataToSign(dataFilesToSign);
    byte[] signatureValue = eccSignatureToken.sign(DigestAlgorithm.SHA256, dataToSign);
    TestAssert.assertDSSDocumentIsSigned(this.facade.signDocument(signatureValue, dataFilesToSign));
  }

  @Test
  public void signWithSignerInformation() throws Exception {
    SignerLocation signerLocation = new SignerLocation();
    signerLocation.setCountry("Val Verde");
    signerLocation.setPostalCode("1776");
    signerLocation.setLocality("Kansas City");
    this.facade.setSignerLocation(signerLocation);
    this.facade.setSignerRoles(Arrays.asList("manager", "potato expert"));
    TestAssert.assertDSSDocumentIsSigned(this.sign(this.facade, DigestAlgorithm.SHA256));
  }

  @Test
  public void signWithSignaturePolicy() throws IOException {
    Policy signaturePolicy = new Policy();
    signaturePolicy.setId("urn:oid:1.3.6.1.4.1.10015.1000.3.2.1");
    signaturePolicy.setDigestValue(decodeBase64("3Tl1oILSvOAWomdI9VeWV6IA/32eSXRUri9kPEz1IVs="));
    signaturePolicy.setDigestAlgorithm(SHA256);
    signaturePolicy.setSpuri("https://www.sk.ee/repository/bdoc-spec21.pdf");
    this.facade.setSignaturePolicy(signaturePolicy);
    TestAssert.assertDSSDocumentIsSigned(this.sign(this.facade, DigestAlgorithm.SHA256));
  }

  @Test
  public void signWithBesSignatureProfile() throws Exception {
    this.facade.setSignatureLevel(XAdES_BASELINE_B);
    TestAssert.assertDSSDocumentIsSigned(this.sign(this.facade, DigestAlgorithm.SHA256));
  }

  @Test
  public void setSignatureId() throws Exception {
    this.facade.setSignatureId("Signature-0");
    TestAssert.assertDSSDocumentIsSigned(this.sign(this.facade, DigestAlgorithm.SHA256));
  }

  @Test
  public void extendBesSignature_toTimestampSignature() throws Exception {
    this.facade.setSignatureLevel(XAdES_BASELINE_B);
    DSSDocument signedDocument = this.sign(this.facade, DigestAlgorithm.SHA256);
    XadesSigningDssFacade extendingFacade = this.createSigningFacade();
    extendingFacade.setSignatureLevel(XAdES_BASELINE_LT);
    DSSDocument detachedContent = new FileDocument("src/test/resources/testFiles/helper-files/test.txt");
    TestAssert.assertDSSDocumentIsSigned(extendingFacade.extendSignature(signedDocument, detachedContent));
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    this.facade = this.createSigningFacade();
  }

}
