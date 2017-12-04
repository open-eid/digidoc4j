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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.impl.asic.xades.XadesSigningDssFacade;
import org.digidoc4j.impl.asic.SkDataLoader;
import org.digidoc4j.impl.asic.ocsp.BDocTSOcspSource;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.digidoc4j.testutils.TestSigningHelper;
import org.junit.Before;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.Policy;
import eu.europa.esig.dss.SignerLocation;
import eu.europa.esig.dss.client.tsp.OnlineTSPSource;

public class XadesSigningDssFacadeTest {

  static Configuration configuration = new Configuration(Configuration.Mode.TEST);
  private XadesSigningDssFacade facade;

  @Before
  public void setUp() throws Exception {
    facade = createSigningFacade();
  }

  @Test
  public void getDataToSign() throws Exception {
    facade = new XadesSigningDssFacade();
    List<DataFile> dataFilesToSign = createDataFilesToSign();
    byte[] dataToSign = getDataToSign(dataFilesToSign);
    assertNotNull(dataToSign);
    assertTrue(dataToSign.length > 0);
  }

  @Test
  public void signDocumentTest() throws Exception {
    facade.setCertificateSource(configuration.getTSL());
    facade.setOcspSource(createOcspSource());
    DSSDocument signedDocument = signTestData(DigestAlgorithm.SHA256);
    assertDocumentSigned(signedDocument);
  }

  @Test
  public void signDocumentWithSha512() throws Exception {
    facade.setSignatureDigestAlgorithm(DigestAlgorithm.SHA512);
    DSSDocument signedDocument = signTestData(DigestAlgorithm.SHA512);
    assertDocumentSigned(signedDocument);
  }

  @Test
  public void signDocumentWithECC() throws Exception {
    PKCS12SignatureToken eccSignatureToken = new PKCS12SignatureToken("src/test/resources/testFiles/p12/ec-digiid.p12", "inno".toCharArray());
    X509Certificate signingCert = eccSignatureToken.getCertificate();
    facade.setEncryptionAlgorithm(EncryptionAlgorithm.ECDSA);
    facade.setSigningCertificate(signingCert);
    List<DataFile> dataFilesToSign = createDataFilesToSign();
    byte[] dataToSign = facade.getDataToSign(dataFilesToSign);
    byte[] signatureValue = eccSignatureToken.sign(DigestAlgorithm.SHA256, dataToSign);
    DSSDocument signedDocument = facade.signDocument(signatureValue, dataFilesToSign);
    assertDocumentSigned(signedDocument);
  }

  @Test
  public void signWithSignerInformation() throws Exception {
    SignerLocation signerLocation = new SignerLocation();
    signerLocation.setCountry("Val Verde");
    signerLocation.setPostalCode("1776");
    signerLocation.setLocality("Kansas City");
    facade.setSignerLocation(signerLocation);
    facade.setSignerRoles(Arrays.asList("manager", "potato expert"));
    DSSDocument signedDocument = signTestData(DigestAlgorithm.SHA256);
    assertDocumentSigned(signedDocument);
  }

  @Test
  public void signWithSignaturePolicy() throws IOException {
    Policy signaturePolicy = new Policy();
    signaturePolicy.setId("urn:oid:1.3.6.1.4.1.10015.1000.3.2.1");
    signaturePolicy.setDigestValue(decodeBase64("3Tl1oILSvOAWomdI9VeWV6IA/32eSXRUri9kPEz1IVs="));
    signaturePolicy.setDigestAlgorithm(SHA256);
    signaturePolicy.setSpuri("https://www.sk.ee/repository/bdoc-spec21.pdf");
    facade.setSignaturePolicy(signaturePolicy);
    DSSDocument signedDocument = signTestData(DigestAlgorithm.SHA256);
    assertDocumentSigned(signedDocument);
  }

  @Test
  public void signWithBesSignatureProfile() throws Exception {
    facade.setSignatureLevel(XAdES_BASELINE_B);
    DSSDocument signedDocument = signTestData(DigestAlgorithm.SHA256);
    assertDocumentSigned(signedDocument);
  }

  @Test
  public void setSignatureId() throws Exception {
    facade.setSignatureId("Signature-0");
    DSSDocument signedDocument = signTestData(DigestAlgorithm.SHA256);
    assertDocumentSigned(signedDocument);
  }

  @Test
  public void extendBesSignature_toTimestampSignature() throws Exception {
    facade.setSignatureLevel(XAdES_BASELINE_B);
    DSSDocument signedDocument = signTestData(DigestAlgorithm.SHA256);
    XadesSigningDssFacade extendingFacade = createSigningFacade();
    extendingFacade.setSignatureLevel(XAdES_BASELINE_LT);
    DSSDocument detachedContent = new FileDocument("src/test/resources/testFiles/helper-files/test.txt");
    DSSDocument extendedDocument = extendingFacade.extendSignature(signedDocument, detachedContent);
    assertDocumentSigned(extendedDocument);
  }

  private DSSDocument signTestData(DigestAlgorithm digestAlgorithm) {
    List<DataFile> dataFilesToSign = createDataFilesToSign();
    byte[] dataToSign = getDataToSign(dataFilesToSign);
    byte[] signatureValue = signData(dataToSign, digestAlgorithm);
    return facade.signDocument(signatureValue, dataFilesToSign);
  }

  private byte[] getDataToSign(List<DataFile> dataFilesToSign) {
    X509Certificate signingCert = TestSigningHelper.getSigningCert();
    facade.setSigningCertificate(signingCert);
    return facade.getDataToSign(dataFilesToSign);
  }

  private byte[] signData(byte[] dataToSign, DigestAlgorithm digestAlgorithm) {
    byte[] digestToSign = calculateDigestToSign(dataToSign, digestAlgorithm);
    return TestSigningHelper.sign(digestToSign, digestAlgorithm);
  }

  private XadesSigningDssFacade createSigningFacade() {
    XadesSigningDssFacade facade = new XadesSigningDssFacade();
    facade.setCertificateSource(configuration.getTSL());
    facade.setOcspSource(createOcspSource());
    facade.setTspSource(createTSPSource());
    return facade;
  }

  private BDocTSOcspSource createOcspSource() {
    BDocTSOcspSource ocspSource = new BDocTSOcspSource(configuration);
    SkDataLoader dataLoader = SkDataLoader.createOcspDataLoader(configuration);
    dataLoader.setUserAgentSignatureProfile(SignatureProfile.LT);
    ocspSource.setDataLoader(dataLoader);
    return ocspSource;
  }

  private OnlineTSPSource createTSPSource() {
    SkDataLoader timestampDataLoader = SkDataLoader.createTimestampDataLoader(configuration);
    timestampDataLoader.setUserAgentSignatureProfile(SignatureProfile.LT);
    OnlineTSPSource tspSource = new OnlineTSPSource(configuration.getTspSource());
    tspSource.setDataLoader(timestampDataLoader);
    return tspSource;
  }

  private List<DataFile> createDataFilesToSign() {
    List<DataFile> dataFilesToSign = new ArrayList<>();
    dataFilesToSign.add(new DataFile("src/test/resources/testFiles/helper-files/test.txt", "plain/text"));
    return dataFilesToSign;
  }

  private byte[] calculateDigestToSign(byte[] dataToDigest, DigestAlgorithm digestAlgorithm) {
    return DSSUtils.digest(digestAlgorithm.getDssDigestAlgorithm(), dataToDigest);
  }

  private void assertDocumentSigned(DSSDocument signedDocument) throws IOException {
    assertNotNull(signedDocument);
    byte[] bytes = IOUtils.toByteArray(signedDocument.openStream());
    assertNotNull(bytes);
    assertTrue(bytes.length > 0);
  }

}
