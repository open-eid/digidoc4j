/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j;

import static org.digidoc4j.ContainerBuilder.BDOC_CONTAINER_TYPE;
import static org.digidoc4j.ContainerBuilder.DDOC_CONTAINER_TYPE;
import static org.digidoc4j.testutils.TestSigningHelper.getSigningCert;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.digidoc4j.exceptions.InvalidSignatureException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.SignatureTokenMissingException;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.digidoc4j.impl.bdoc.BDocSignature;
import org.digidoc4j.impl.bdoc.xades.validation.XadesSignatureValidator;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.digidoc4j.testutils.TestContainer;
import org.digidoc4j.testutils.TestDataBuilder;
import org.digidoc4j.testutils.TestSignatureBuilder;
import org.digidoc4j.testutils.TestSigningHelper;
import org.digidoc4j.utils.TokenAlgorithmSupport;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.x509.SignaturePolicy;

public class SignatureBuilderTest extends DigiDoc4JTestHelper {

  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();
  private final PKCS12SignatureToken testSignatureToken = new PKCS12SignatureToken("testFiles/p12/signout.p12", "test".toCharArray());

  @After
  public void tearDown() throws Exception {
    ContainerBuilder.removeCustomContainerImplementations();
    SignatureBuilder.removeCustomSignatureBuilders();
  }

  @Test
  public void buildingDataToSign_shouldReturnDigestToSign() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile(testFolder);
    X509Certificate signerCert = getSigningCert();
    SignatureBuilder builder = SignatureBuilder.
        aSignature(container).
        withSigningCertificate(signerCert);
    DataToSign dataToSign = builder.buildDataToSign();
    assertNotNull(dataToSign);
    assertNotNull(dataToSign.getDigestToSign());
    assertNotNull(dataToSign.getSignatureParameters());
    assertEquals(32, dataToSign.getDigestToSign().length); //SHA256 is always 256 bits long, equivalent to 32 bytes
    assertEquals(DigestAlgorithm.SHA256, dataToSign.getDigestAlgorithm());
  }

  @Test
  public void buildingDataToSign_shouldContainSignatureParameters() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile(testFolder);
    X509Certificate signerCert = getSigningCert();
    SignatureBuilder builder = SignatureBuilder.
        aSignature(container).
        withCity("San Pedro").
        withStateOrProvince("Puerto Vallarta").
        withPostalCode("13456").
        withCountry("Val Verde").
        withRoles("Manager", "Suspicious Fisherman").
        withSignatureDigestAlgorithm(DigestAlgorithm.SHA256).
        withSignatureProfile(SignatureProfile.LT_TM).
        withSignatureId("S0").
        withSigningCertificate(signerCert);
    DataToSign dataToSign = builder.buildDataToSign();
    SignatureParameters parameters = dataToSign.getSignatureParameters();
    assertEquals("San Pedro", parameters.getCity());
    assertEquals("Puerto Vallarta", parameters.getStateOrProvince());
    assertEquals("13456", parameters.getPostalCode());
    assertEquals("Val Verde", parameters.getCountry());
    assertEquals("Manager", parameters.getRoles().get(0));
    assertEquals(DigestAlgorithm.SHA256, parameters.getDigestAlgorithm());
    assertEquals(SignatureProfile.LT_TM, parameters.getSignatureProfile());
    assertEquals("S0", parameters.getSignatureId());
    assertSame(signerCert, parameters.getSigningCertificate());
    byte[] bytesToSign = dataToSign.getDigestToSign();
    assertNotNull(bytesToSign);
    assertTrue(bytesToSign.length > 1);
  }

  @Test
  public void signDocumentExternallyTwice() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile(testFolder);

    DataToSign dataToSign = TestDataBuilder.buildDataToSign(container, "S0");
    Signature signature = TestDataBuilder.makeSignature(container, dataToSign);
    assertSignatureIsValid(signature);

    DataToSign dataToSign2 = TestDataBuilder.buildDataToSign(container, "S1");
    Signature signature2 = TestDataBuilder.makeSignature(container, dataToSign2);
    assertSignatureIsValid(signature2);

    container.saveAsFile(testFolder.newFile("test-container.bdoc").getPath());
  }

  @Test
  public void signContainerWithSignatureToken() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile(testFolder);

    Signature signature = SignatureBuilder.
        aSignature(container).
        withCity("Tallinn").
        withStateOrProvince("Harjumaa").
        withPostalCode("13456").
        withCountry("Estonia").
        withRoles("Manager", "Suspicious Fisherman").
        withSignatureDigestAlgorithm(DigestAlgorithm.SHA256).
        withSignatureProfile(SignatureProfile.LT_TM).
        withSignatureToken(testSignatureToken).
        invokeSigning();

    container.addSignature(signature);
    assertTrue(signature.validateSignature().isValid());

    container.saveAsFile(testFolder.newFile("test-container2.bdoc").getPath());

    assertSignatureIsValid(signature);
    assertEquals("Tallinn", signature.getCity());
    assertEquals("Harjumaa", signature.getStateOrProvince());
    assertEquals("13456", signature.getPostalCode());
    assertEquals("Estonia", signature.getCountryName());
    assertEquals(2, signature.getSignerRoles().size());
    assertEquals("Manager", signature.getSignerRoles().get(0));
    assertEquals("Suspicious Fisherman", signature.getSignerRoles().get(1));
  }

  @Test
  public void createTimeMarkSignature_shouldNotContainTimestamp() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile(testFolder);
    BDocSignature signature = (BDocSignature) SignatureBuilder.
        aSignature(container).
        withSignatureProfile(SignatureProfile.LT_TM).
        withSignatureToken(testSignatureToken).
        invokeSigning();
    assertTrue(signature.validateSignature().isValid());
    container.addSignature(signature);

    List<TimestampToken> signatureTimestamps = signature.getOrigin().getDssSignature().getSignatureTimestamps();
    assertTrue(signatureTimestamps == null || signatureTimestamps.isEmpty());
  }

  @Test
  public void signDDocContainerWithSignatureToken() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile(testFolder, "DDOC");
    assertEquals("DDOC", container.getType());

    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureDigestAlgorithm(DigestAlgorithm.SHA1).
        withSignatureToken(testSignatureToken).
        invokeSigning();

    container.addSignature(signature);
  }

  @Test(expected = SignatureTokenMissingException.class)
  public void signContainerWithMissingSignatureToken_shouldThrowException() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile(testFolder);
    SignatureBuilder.
        aSignature(container).
        invokeSigning();
  }

  @Test
  public void signDDocContainer() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile(testFolder, "DDOC");
    X509Certificate signingCert = getSigningCert();
    DataToSign dataToSign = SignatureBuilder.
        aSignature(container).
        withSigningCertificate(signingCert).
        buildDataToSign();

    assertEquals(DigestAlgorithm.SHA1, dataToSign.getDigestAlgorithm());
    byte[] bytesToSign = dataToSign.getDigestToSign();
    assertNotNull(bytesToSign);
    assertTrue(bytesToSign.length > 1);

    byte[] signatureValue = TestSigningHelper.sign(dataToSign.getDigestToSign(), dataToSign.getDigestAlgorithm());
    assertNotNull(signatureValue);
    assertTrue(signatureValue.length > 1);

    Signature signature = dataToSign.finalize(signatureValue);
    assertNotNull(signature);
    assertNotNull(signature.getClaimedSigningTime());

    container.addSignature(signature);
    container.saveAsFile(testFolder.newFile("test-container.bdoc").getPath());
  }

  @Test
  public void signatureProfileShouldBeSetProperlyForBDoc() throws Exception {
    Signature signature = createBDocSignatureWithProfile(SignatureProfile.B_BES);
    assertEquals(SignatureProfile.B_BES, signature.getProfile());
    assertTrue(signature.getSignerRoles().isEmpty());
  }

  @Test
  public void signatureProfileShouldBeSetProperlyForBDocTS() throws Exception {
    Signature signature = createBDocSignatureWithProfile(SignatureProfile.LT);
    assertEquals(SignatureProfile.LT, signature.getProfile());
  }

  @Test
  public void signatureProfileShouldBeSetProperlyForBDocTM() throws Exception {
    Signature signature = createBDocSignatureWithProfile(SignatureProfile.LT_TM);
    assertEquals(SignatureProfile.LT_TM, signature.getProfile());
  }

  @Test
  public void signatureProfileShouldBeSetProperlyForBEpes() throws Exception {
    Signature signature = createBDocSignatureWithProfile(SignatureProfile.B_EPES);
    assertEquals(SignatureProfile.B_EPES, signature.getProfile());
    assertNull(signature.getTrustedSigningTime());
    assertNull(signature.getOCSPCertificate());
    assertNull(signature.getOCSPResponseCreationTime());
    assertNull(signature.getTimeStampTokenCertificate());
    assertNull(signature.getTimeStampCreationTime());
    BDocSignature bDocSignature = (BDocSignature) signature;
    SignaturePolicy policyId = bDocSignature.getOrigin().getDssSignature().getPolicyId();
    assertEquals(XadesSignatureValidator.TM_POLICY, policyId.getIdentifier());
  }

  @Test
  public void signWithEccCertificate() throws Exception {
    PKCS12SignatureToken eccSignatureToken = new PKCS12SignatureToken("testFiles/p12/ec-digiid.p12", "inno".toCharArray());
    Container container = TestDataBuilder.createContainerWithFile(testFolder, "BDOC");
    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureToken(eccSignatureToken).
        withEncryptionAlgorithm(EncryptionAlgorithm.ECDSA).
        invokeSigning();
    assertTrue(signature.validateSignature().isValid());
  }

  @Test
  public void signTMWithEccCertificate() throws Exception {
    PKCS12SignatureToken eccSignatureToken = new PKCS12SignatureToken("testFiles/p12/ec-digiid.p12", "inno".toCharArray());
    Container container = TestDataBuilder.createContainerWithFile(testFolder, "BDOC");
    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureToken(eccSignatureToken).
        withEncryptionAlgorithm(EncryptionAlgorithm.ECDSA).
        withSignatureDigestAlgorithm(DigestAlgorithm.SHA256).
        withSignatureProfile(SignatureProfile.LT_TM).
        invokeSigning();
    assertTrue(signature.validateSignature().isValid());
    container.addSignature(signature);
    assertTrue(container.validate().isValid());
  }

  @Test
  public void signWithEccCertificate_determiningEncryptionAlgorithmAutomatically() throws Exception {
    PKCS12SignatureToken eccSignatureToken = new PKCS12SignatureToken("testFiles/p12/ec-digiid.p12", "inno".toCharArray());
    Container container = TestDataBuilder.createContainerWithFile(testFolder, "BDOC");
    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureToken(eccSignatureToken).
        invokeSigning();
    assertTrue(signature.validateSignature().isValid());
  }

  @Test
  public void signWithDeterminedSignatureDigestAlgorithm() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile(testFolder);

    X509Certificate certificate = testSignatureToken.getCertificate();
    DigestAlgorithm digestAlgorithm = TokenAlgorithmSupport.determineSignatureDigestAlgorithm(certificate);
    DataToSign dataToSign = SignatureBuilder.
        aSignature(container).
        withSignatureDigestAlgorithm(digestAlgorithm).
        withSigningCertificate(certificate).
        buildDataToSign();

    SignatureParameters signatureParameters = dataToSign.getSignatureParameters();
    assertEquals(DigestAlgorithm.SHA256, signatureParameters.getDigestAlgorithm());

    Signature signature = TestDataBuilder.makeSignature(container, dataToSign);
    assertEquals(DigestAlgorithm.SHA256.toString(), signature.getSignatureMethod());
    assertTrue(container.validate().isValid());
  }

  @Test(expected = InvalidSignatureException.class)
  public void openSignatureFromNull_shouldThrowException() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile("testFiles/helper-files/test.txt");
    SignatureBuilder.
        aSignature(container).
        openAdESSignature(null);
  }

  @Test
  public void openSignatureFromExistingSignatureDocument() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile("testFiles/helper-files/test.txt");
    Signature signature = openSignatureFromExistingSignatureDocument(container);
    assertTrue(signature.validateSignature().isValid());
  }

  @Test
  public void openSignatureForDDocFromExistingSignatureDocument() throws Exception {
    Container container = ContainerBuilder.
        aContainer(DDOC_CONTAINER_TYPE).
        withDataFile("testFiles/helper-files/test.txt", "text/plain").
        build();
    openSignatureFromExistingSignatureDocument(container);
  }

  @Test(expected = InvalidSignatureException.class)
  public void openSignatureFromInvalidSignatureDocument() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile("testFiles/helper-files/test.txt");
    byte[] signatureBytes = FileUtils.readFileToByteArray(new File("testFiles/helper-files/test.txt"));
    SignatureBuilder.
        aSignature(container).
        openAdESSignature(signatureBytes);
  }

  @Test
  public void openSignature_withDataFilesMismatch_shouldBeInvalid() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile("testFiles/helper-files/word_file.docx");
    Signature signature = openAdESSignature(container);
    SignatureValidationResult result = signature.validateSignature();
    assertFalse(result.isValid());
    assertEquals("The reference data object(s) is not found!", result.getErrors().get(0).getMessage());
  }

  @Test
  public void openXadesSignature_withoutXmlPreamble_shouldNotThrowException() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile("testFiles/helper-files/test.txt");
    byte[] signatureBytes = FileUtils.readFileToByteArray(new File("testFiles/xades/bdoc-tm-jdigidoc-mobile-id.xml"));
    SignatureBuilder.
        aSignature(container).
        openAdESSignature(signatureBytes);
  }

  @Test
  public void openXadesSignature_andSavingContainer_shouldNotChangeSignature() throws Exception {
    String containerPath = testFolder.newFile("test.bdoc").getPath();
    Container container = TestDataBuilder.createContainerWithFile("testFiles/helper-files/word_file.docx");
    Signature signature = openAdESSignature(container);
    container.addSignature(signature);
    container.saveAsFile(containerPath);
    container = ContainerOpener.open(containerPath);
    byte[] originalSignatureBytes = FileUtils.readFileToByteArray(new File("testFiles/xades/valid-bdoc-tm.xml"));
    byte[] signatureBytes = container.getSignatures().get(0).getAdESSignature();
    assertArrayEquals(originalSignatureBytes, signatureBytes);
  }

  private Signature openSignatureFromExistingSignatureDocument(Container container) throws IOException {
    Signature signature = openAdESSignature(container);
    assertEquals("id-6a5d6671af7a9e0ab9a5e4d49d69800d", signature.getId());
    return signature;
  }

  private Signature openAdESSignature(Container container) throws IOException {
    byte[] signatureBytes = FileUtils.readFileToByteArray(new File("testFiles/xades/valid-bdoc-tm.xml"));
    return SignatureBuilder.
        aSignature(container).
        openAdESSignature(signatureBytes);
  }

  @Test(expected = NotSupportedException.class)
  public void signUnknownContainerFormat_shouldThrowException() throws Exception {
    ContainerBuilder.setContainerImplementation("TEST-FORMAT", TestContainer.class);
    Container container = TestDataBuilder.createContainerWithFile(testFolder, "TEST-FORMAT");
    TestDataBuilder.buildDataToSign(container);
  }

  @Test
  public void signCustomContainer() throws Exception {
    ContainerBuilder.setContainerImplementation("TEST-FORMAT", TestContainer.class);
    SignatureBuilder.setSignatureBuilderForContainerType("TEST-FORMAT", TestSignatureBuilder.class);
    Container container = TestDataBuilder.createContainerWithFile(testFolder, "TEST-FORMAT");
    DataToSign dataToSign = TestDataBuilder.buildDataToSign(container);
    assertNotNull(dataToSign);
    byte[] signatureValue = TestSigningHelper.sign(dataToSign.getDigestToSign(), dataToSign.getDigestAlgorithm());
    Signature signature = dataToSign.finalize(signatureValue);
    assertNotNull(signature);
  }

  @Test
  public void invokeSigningForCustomContainer() throws Exception {
    ContainerBuilder.setContainerImplementation("TEST-FORMAT", TestContainer.class);
    SignatureBuilder.setSignatureBuilderForContainerType("TEST-FORMAT", TestSignatureBuilder.class);
    Container container = TestDataBuilder.createContainerWithFile(testFolder, "TEST-FORMAT");
    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureToken(testSignatureToken).
        invokeSigning();
    assertNotNull(signature);
  }

  @Test
  public void invokeSigning_whenOverridingBDocContainerFormat() throws Exception {
    TestContainer.type = BDOC_CONTAINER_TYPE;
    ContainerBuilder.setContainerImplementation(BDOC_CONTAINER_TYPE, TestContainer.class);
    SignatureBuilder.setSignatureBuilderForContainerType(BDOC_CONTAINER_TYPE, TestSignatureBuilder.class);
    Container container = TestDataBuilder.createContainerWithFile(testFolder, BDOC_CONTAINER_TYPE);
    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureToken(testSignatureToken).
        invokeSigning();
    assertNotNull(signature);
    TestContainer.resetType();
  }

  private Signature createBDocSignatureWithProfile(SignatureProfile profile) throws IOException {
    Container container = TestDataBuilder.createContainerWithFile(testFolder);
    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureToken(testSignatureToken).
        withSignatureProfile(profile).
        invokeSigning();
    container.addSignature(signature);
    return signature;
  }

  private void assertSignatureIsValid(Signature signature) {
    assertNotNull(signature.getProducedAt());
    assertEquals(SignatureProfile.LT_TM, signature.getProfile());
    assertNotNull(signature.getClaimedSigningTime());
    assertNotNull(signature.getAdESSignature());
    assertTrue(signature.getAdESSignature().length > 1);
    assertTrue(signature.validateSignature().isValid());
  }
}
