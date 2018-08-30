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

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.Security;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.digidoc4j.exceptions.InvalidSignatureException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.SignatureTokenMissingException;
import org.digidoc4j.impl.asic.asice.AsicESignature;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignature;
import org.digidoc4j.impl.asic.xades.validation.XadesSignatureValidator;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.digidoc4j.test.CustomContainer;
import org.digidoc4j.test.MockSignatureBuilder;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.digidoc4j.test.util.TestSigningUtil;
import org.digidoc4j.utils.TokenAlgorithmSupport;
import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.x509.SignaturePolicy;

public class SignatureBuilderTest extends AbstractTest {

  @Test
  public void buildingDataToSign_shouldReturnDataToSign() throws Exception {
    Container container = this.createNonEmptyContainer();
    SignatureBuilder builder = SignatureBuilder.aSignature(container).
        withSigningCertificate(this.pkcs12SignatureToken.getCertificate());
    DataToSign dataToSign = builder.buildDataToSign();
    Assert.assertNotNull(dataToSign);
    Assert.assertNotNull(dataToSign.getDataToSign());
    Assert.assertNotNull(dataToSign.getSignatureParameters());
    Assert.assertEquals(DigestAlgorithm.SHA256, dataToSign.getDigestAlgorithm());
  }

  @Test
  public void buildingDataToSign_shouldContainSignatureParameters() throws Exception {
    Container container = this.createNonEmptyContainer();
    SignatureBuilder builder = SignatureBuilder.aSignature(container).withCity("San Pedro").
        withStateOrProvince("Puerto Vallarta").withPostalCode("13456").withCountry("Val Verde").
        withRoles("Manager", "Suspicious Fisherman").withSignatureDigestAlgorithm(DigestAlgorithm.SHA256).
        withSignatureProfile(SignatureProfile.LT_TM).withSignatureId("S0").
        withSigningCertificate(this.pkcs12SignatureToken.getCertificate());
    DataToSign dataToSign = builder.buildDataToSign();
    SignatureParameters parameters = dataToSign.getSignatureParameters();
    Assert.assertEquals("San Pedro", parameters.getCity());
    Assert.assertEquals("Puerto Vallarta", parameters.getStateOrProvince());
    Assert.assertEquals("13456", parameters.getPostalCode());
    Assert.assertEquals("Val Verde", parameters.getCountry());
    Assert.assertEquals("Manager", parameters.getRoles().get(0));
    Assert.assertEquals(DigestAlgorithm.SHA256, parameters.getDigestAlgorithm());
    Assert.assertEquals(SignatureProfile.LT_TM, parameters.getSignatureProfile());
    Assert.assertEquals("S0", parameters.getSignatureId());
    Assert.assertSame(this.pkcs12SignatureToken.getCertificate(), parameters.getSigningCertificate());
    byte[] bytesToSign = dataToSign.getDataToSign();
    Assert.assertNotNull(bytesToSign);
    Assert.assertTrue(bytesToSign.length > 1);
  }

  @Test
  public void signDocumentExternallyTwice() throws Exception {
    Container container = this.createNonEmptyContainer();
    DataToSign dataToSign = TestDataBuilderUtil.buildDataToSign(container, "S0");
    Signature signature = TestDataBuilderUtil.makeSignature(container, dataToSign);
    this.assertSignatureIsValid(signature);
    DataToSign dataToSign2 = TestDataBuilderUtil.buildDataToSign(container, "S1");
    Signature signature2 = TestDataBuilderUtil.makeSignature(container, dataToSign2);
    this.assertSignatureIsValid(signature2);
    container.saveAsFile(this.getFileBy("bdoc"));
  }

  @Test
  public void signContainerWithSignatureToken() throws Exception {
    Container container = this.createNonEmptyContainer();
    Signature signature = SignatureBuilder.aSignature(container).withCity("Tallinn").
        withStateOrProvince("Harjumaa").withPostalCode("13456").withCountry("Estonia").
        withRoles("Manager", "Suspicious Fisherman").withSignatureDigestAlgorithm(DigestAlgorithm.SHA256).
        withSignatureProfile(SignatureProfile.LT_TM).withSignatureToken(this.pkcs12SignatureToken).invokeSigning();
    container.addSignature(signature);
    Assert.assertTrue(signature.validateSignature().isValid());
    container.saveAsFile(this.getFileBy("bdoc"));
    this.assertSignatureIsValid(signature);
    Assert.assertEquals("Tallinn", signature.getCity());
    Assert.assertEquals("Harjumaa", signature.getStateOrProvince());
    Assert.assertEquals("13456", signature.getPostalCode());
    Assert.assertEquals("Estonia", signature.getCountryName());
    Assert.assertEquals(2, signature.getSignerRoles().size());
    Assert.assertEquals("Manager", signature.getSignerRoles().get(0));
    Assert.assertEquals("Suspicious Fisherman", signature.getSignerRoles().get(1));
  }

  @Test
  public void createTimeMarkSignature_shouldNotContainTimestamp() throws Exception {
    Container container = this.createNonEmptyContainer();
    BDocSignature signature = (BDocSignature) SignatureBuilder.aSignature(container).
        withSignatureProfile(SignatureProfile.LT_TM).withSignatureToken(this.pkcs12SignatureToken).invokeSigning();
    Assert.assertTrue(signature.validateSignature().isValid());
    container.addSignature(signature);
    List<TimestampToken> signatureTimestamps = signature.getOrigin().getDssSignature().getSignatureTimestamps();
    Assert.assertTrue(signatureTimestamps == null || signatureTimestamps.isEmpty());
  }

  @Test(expected = SignatureTokenMissingException.class)
  public void signContainerWithMissingSignatureToken_shouldThrowException() throws Exception {
    Container container = this.createNonEmptyContainer();
    SignatureBuilder.aSignature(container).invokeSigning();
  }

  @Test
  public void signatureProfileShouldBeSetProperlyForBDoc() throws Exception {
    Signature signature = createBDocSignatureWithProfile(SignatureProfile.B_BES);
    Assert.assertEquals(SignatureProfile.B_BES, signature.getProfile());
    Assert.assertTrue(signature.getSignerRoles().isEmpty());
  }

  @Test
  public void signatureProfileShouldBeSetProperlyForBDocTS() throws Exception {
    Signature signature = createBDocSignatureWithProfile(SignatureProfile.LT);
    Assert.assertEquals(SignatureProfile.LT, signature.getProfile());
  }

  @Test
  public void signatureProfileShouldBeSetProperlyForBDocTM() throws Exception {
    Signature signature = createBDocSignatureWithProfile(SignatureProfile.LT_TM);
    Assert.assertEquals(SignatureProfile.LT_TM, signature.getProfile());
  }

  @Test
  public void signatureProfileShouldBeSetProperlyForBEpes() throws Exception {
    Signature signature = createBDocSignatureWithProfile(SignatureProfile.B_EPES);
    Assert.assertEquals(SignatureProfile.B_EPES, signature.getProfile());
    Assert.assertNull(signature.getTrustedSigningTime());
    Assert.assertNull(signature.getOCSPCertificate());
    Assert.assertNull(signature.getOCSPResponseCreationTime());
    Assert.assertNull(signature.getTimeStampTokenCertificate());
    Assert.assertNull(signature.getTimeStampCreationTime());
    AsicESignature bDocSignature = (AsicESignature) signature;
    SignaturePolicy policyId = bDocSignature.getOrigin().getDssSignature().getPolicyId();
    Assert.assertEquals(XadesSignatureValidator.TM_POLICY, policyId.getIdentifier());
  }

  @Test
  public void signWithEccCertificate() throws Exception {
    Container container = this.createNonEmptyContainer();
    Signature signature = SignatureBuilder.aSignature(container).
        withSignatureToken(new PKCS12SignatureToken("src/test/resources/testFiles/p12/MadDogOY.p12", "test".toCharArray())).
        withEncryptionAlgorithm(EncryptionAlgorithm.ECDSA).invokeSigning();
    Assert.assertTrue(signature.validateSignature().isValid());
    Assert.assertEquals(SignatureProfile.LT, signature.getProfile());
    container.addSignature(signature);
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void signWith2EccCertificate() throws Exception {
    Container container = this.createNonEmptyContainer();
    Signature signature = SignatureBuilder.aSignature(container).withSignatureToken(this.pkcs12EccSignatureToken).
        withEncryptionAlgorithm(EncryptionAlgorithm.ECDSA).withSignatureDigestAlgorithm(DigestAlgorithm.SHA256).
        withSignatureProfile(SignatureProfile.LT_TM).invokeSigning();
    Assert.assertTrue(signature.validateSignature().isValid());
    container.addSignature(signature);
    signature = SignatureBuilder.aSignature(container).
        withSignatureToken(new PKCS12SignatureToken("src/test/resources/testFiles/p12/MadDogOY.p12", "test".toCharArray())).
        withEncryptionAlgorithm(EncryptionAlgorithm.RSA).withSignatureProfile(SignatureProfile.LT).invokeSigning();
    Assert.assertTrue(signature.validateSignature().isValid());
    container.addSignature(signature);
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void signTMWithEccCertificate() throws Exception {
    Container container = this.createNonEmptyContainer();
    Signature signature = SignatureBuilder.aSignature(container).
        withSignatureToken(new PKCS12SignatureToken("src/test/resources/testFiles/p12/MadDogOY.p12", "test".toCharArray())).
        withEncryptionAlgorithm(EncryptionAlgorithm.ECDSA).withSignatureDigestAlgorithm(DigestAlgorithm.SHA256).
        withSignatureProfile(SignatureProfile.LT_TM).invokeSigning();
    Assert.assertNotNull(signature);
    Assert.assertTrue(signature.validateSignature().isValid());
    container.addSignature(signature);
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void signWithEccCertificate_determiningEncryptionAlgorithmAutomatically() throws Exception {
    Container container = this.createNonEmptyContainer();
    Signature signature = this.createSignatureBy(container, new PKCS12SignatureToken("src/test/resources/testFiles/p12/MadDogOY.p12", "test".toCharArray()));
    Assert.assertNotNull(signature);
    Assert.assertTrue(signature.validateSignature().isValid());
  }

  @Test
  public void signWithDeterminedSignatureDigestAlgorithm() throws Exception {
    Container container = this.createNonEmptyContainer();
    DigestAlgorithm digestAlgorithm = TokenAlgorithmSupport.determineSignatureDigestAlgorithm(this.pkcs12SignatureToken.getCertificate());
    DataToSign dataToSign = SignatureBuilder.aSignature(container).
        withSignatureDigestAlgorithm(digestAlgorithm).withSigningCertificate(this.pkcs12SignatureToken.getCertificate()).
        buildDataToSign();
    SignatureParameters signatureParameters = dataToSign.getSignatureParameters();
    Assert.assertEquals(DigestAlgorithm.SHA256, signatureParameters.getDigestAlgorithm());
    Signature signature = TestDataBuilderUtil.makeSignature(container, dataToSign);
    Assert.assertEquals(DigestAlgorithm.SHA256.toString(), signature.getSignatureMethod());
    Assert.assertTrue(container.validate().isValid());
  }

  @Test(expected = InvalidSignatureException.class)
  public void openSignatureFromNull_shouldThrowException() throws Exception {
    SignatureBuilder.aSignature(this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"))).
        openAdESSignature(null);
  }

  @Test
  public void openSignatureFromExistingSignatureDocument() throws Exception {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"));
    Signature signature = this.openSignatureFromExistingSignatureDocument(container);
    Assert.assertTrue(signature.validateSignature().isValid());
  }

  @Test(expected = NotSupportedException.class)
  public void SignatureBuilderWithDDoc_throwsException() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    SignatureBuilder.aSignature(container).buildDataToSign();
  }

  @Test(expected = InvalidSignatureException.class)
  public void openSignatureFromInvalidSignatureDocument() throws Exception {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"));
    byte[] signatureBytes = FileUtils.readFileToByteArray(new File("src/test/resources/testFiles/helper-files/test.txt"));
    SignatureBuilder.aSignature(container).openAdESSignature(signatureBytes);
  }

  @Test
  public void openSignature_withDataFilesMismatch_shouldBeInvalid() throws Exception {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/word_file.docx"));
    Signature signature = this.openAdESSignature(container);
    ValidationResult result = signature.validateSignature();
    Assert.assertFalse(result.isValid());
    Assert.assertEquals("The reference data object(s) is not found!", result.getErrors().get(0).getMessage());
  }

  @Test
  public void openXadesSignature_withoutXmlPreamble_shouldNotThrowException() throws Exception {
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"));
    byte[] signatureBytes = FileUtils.readFileToByteArray(new File("src/test/resources/testFiles/xades/bdoc-tm-jdigidoc-mobile-id.xml"));
    SignatureBuilder.aSignature(container).openAdESSignature(signatureBytes);
  }

  @Test
  public void openXadesSignature_andSavingContainer_shouldNotChangeSignature() throws Exception {
    Container container = TestDataBuilderUtil.createContainerWithFile("src/test/resources/testFiles/helper-files/word_file.docx");
    Signature signature = this.openAdESSignature(container);
    container.addSignature(signature);
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    byte[] originalSignatureBytes = FileUtils.readFileToByteArray(new File("src/test/resources/testFiles/xades/valid-bdoc-tm.xml"));
    byte[] signatureBytes = container.getSignatures().get(0).getAdESSignature();
    Assert.assertArrayEquals(originalSignatureBytes, signatureBytes);
  }

  @Test(expected = NotSupportedException.class)
  public void signUnknownContainerFormat_shouldThrowException() throws Exception {
    ContainerBuilder.setContainerImplementation("TEST-FORMAT", CustomContainer.class);
    Container container = TestDataBuilderUtil.createContainerWithFile(this.testFolder, "TEST-FORMAT");
    TestDataBuilderUtil.buildDataToSign(container);
  }

  @Test
  public void signCustomContainer() throws Exception {
    ContainerBuilder.setContainerImplementation("TEST-FORMAT", CustomContainer.class);
    SignatureBuilder.setSignatureBuilderForContainerType("TEST-FORMAT", MockSignatureBuilder.class);
    Container container = TestDataBuilderUtil.createContainerWithFile(testFolder, "TEST-FORMAT");
    DataToSign dataToSign = TestDataBuilderUtil.buildDataToSign(container);
    Assert.assertNotNull(dataToSign);
    byte[] signatureValue = TestSigningUtil.sign(dataToSign.getDataToSign(), dataToSign.getDigestAlgorithm());
    Signature signature = dataToSign.finalize(signatureValue);
    Assert.assertNotNull(signature);
  }

  @Test
  public void signAsiceContainerWithExtRsaTm() throws Exception {
    Container container = this.createNonEmptyContainer();
    DataToSign dataToSign = SignatureBuilder.aSignature(container).withSignatureDigestAlgorithm(DigestAlgorithm.SHA256).
        withSignatureProfile(SignatureProfile.LT_TM).withSigningCertificate(this.pkcs12SignatureToken.getCertificate()).
        buildDataToSign();
    Assert.assertNotNull(dataToSign);
    // This call mocks the using of external signing functionality with hashcode
    byte[] signatureValue = this.pkcs12SignatureToken.sign(dataToSign.getDigestAlgorithm(), dataToSign.getDataToSign());
    Signature signature = dataToSign.finalize(signatureValue);
    Assert.assertNotNull(signature);
    Assert.assertTrue(signature.validateSignature().isValid());
    container.addSignature(signature);
    Assert.assertTrue(container.validate().isValid());
    container.saveAsFile(this.getFileBy("bdoc"));
  }

  @Test
  public void signAsiceContainerWithExtRsaLt() throws Exception {
    Container container = this.createNonEmptyContainer();
    DataToSign dataToSign = SignatureBuilder.aSignature(container).withSignatureDigestAlgorithm(DigestAlgorithm.SHA256).
        withSignatureProfile(SignatureProfile.LT).withSigningCertificate(this.pkcs12SignatureToken.getCertificate()).
        buildDataToSign();
    Assert.assertNotNull(dataToSign);
    // This call mocks the using of external signing functionality with hashcode
    byte[] signatureValue = this.pkcs12SignatureToken.sign(dataToSign.getDigestAlgorithm(), dataToSign.getDataToSign());
    Signature signature = dataToSign.finalize(signatureValue);
    Assert.assertNotNull(signature);
    Assert.assertTrue(signature.validateSignature().isValid());
    container.addSignature(signature);
    Assert.assertTrue(container.validate().isValid());
    container.saveAsFile(this.getFileBy("asice"));
  }

  @Test
  public void signAsiceContainerWithExtEccTm() throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    String TEST_ECC_PKI_CONTAINER = "src/test/resources/testFiles/p12/MadDogOY.p12";
    String TEST_ECC_PKI_CONTAINER_PASSWORD = "test";
    PKCS12SignatureToken token = new PKCS12SignatureToken(TEST_ECC_PKI_CONTAINER, TEST_ECC_PKI_CONTAINER_PASSWORD,
        "test of esteid-sk 2011: mad dog oy");
    Assert.assertEquals("test of esteid-sk 2011: mad dog oy", token.getAlias());
    Container container = this.createNonEmptyContainer();
    DataToSign dataToSign = SignatureBuilder.aSignature(container).withSignatureDigestAlgorithm(DigestAlgorithm.SHA256).
        withSignatureProfile(SignatureProfile.LT_TM).withSigningCertificate(token.getCertificate()).
        buildDataToSign();
    Assert.assertNotNull(dataToSign);
    // This call mocks the using of external signing functionality with hashcode
    byte[] signatureValue = new byte[1];
    int counter = 5;
    do {
      signatureValue = token.sign(dataToSign.getDigestAlgorithm(), dataToSign.getDataToSign());
      counter--;
    } while (signatureValue.length == 72 && counter > 0); // Somehow the signature with length 72 is not correct
    Signature signature = dataToSign.finalize(signatureValue);
    Assert.assertNotNull(signature);
    Assert.assertTrue(signature.validateSignature().isValid());
    container.addSignature(signature);
    Assert.assertTrue(container.validate().isValid());
    container.saveAsFile(this.getFileBy("asice"));
  }

  @Test
  public void signAsiceContainerWithExtEccLt() throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    String TEST_ECC_PKI_CONTAINER = "src/test/resources/testFiles/p12/MadDogOY.p12";
    String TEST_ECC_PKI_CONTAINER_PASSWORD = "test";
    PKCS12SignatureToken token = new PKCS12SignatureToken(TEST_ECC_PKI_CONTAINER, TEST_ECC_PKI_CONTAINER_PASSWORD,
        "test of esteid-sk 2011: mad dog oy");
    Assert.assertEquals("test of esteid-sk 2011: mad dog oy", token.getAlias());
    Container container = this.createNonEmptyContainer();
    DataToSign dataToSign = SignatureBuilder.aSignature(container).withSignatureDigestAlgorithm(DigestAlgorithm.SHA256).
        withSignatureProfile(SignatureProfile.LT).withSigningCertificate(token.getCertificate()).
        withEncryptionAlgorithm(EncryptionAlgorithm.ECDSA).buildDataToSign();
    Assert.assertNotNull(dataToSign);
    // This call mocks the using of external signing functionality with hashcode
    byte[] signatureValue = new byte[1];
    int counter = 5;
    do {
      signatureValue = token.sign(dataToSign.getDigestAlgorithm(), dataToSign.getDataToSign());
      counter--;
    } while (signatureValue.length == 72 && counter > 0); // Somehow the signature with length 72 is not correct

    Signature signature = dataToSign.finalize(signatureValue);
    Assert.assertNotNull(signature);
    Assert.assertTrue(signature.validateSignature().isValid());
    container.addSignature(signature);
    Assert.assertTrue(container.validate().isValid());
    container.saveAsFile(this.getFileBy("asice"));
  }

  @Test
  public void invokeSigningForCustomContainer() throws Exception {
    ContainerBuilder.setContainerImplementation("TEST-FORMAT", CustomContainer.class);
    SignatureBuilder.setSignatureBuilderForContainerType("TEST-FORMAT", MockSignatureBuilder.class);
    Container container = TestDataBuilderUtil.createContainerWithFile(this.testFolder, "TEST-FORMAT");
    Signature signature = SignatureBuilder.aSignature(container).withSignatureToken(this.pkcs12SignatureToken).
        invokeSigning();
    Assert.assertNotNull(signature);
  }

  @Test
  public void invokeSigning_whenOverridingBDocContainerFormat() {
    CustomContainer.type = "BDOC";
    ContainerBuilder.setContainerImplementation("BDOC", CustomContainer.class);
    SignatureBuilder.setSignatureBuilderForContainerType("BDOC", MockSignatureBuilder.class);
    Container container = this.createNonEmptyContainer();
    Signature signature = this.createSignatureBy(container, this.pkcs12SignatureToken);
    Assert.assertNotNull(signature);
    CustomContainer.resetType();
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void after() {
    ContainerBuilder.removeCustomContainerImplementations();
    SignatureBuilder.removeCustomSignatureBuilders();
  }

  private Signature createBDocSignatureWithProfile(SignatureProfile signatureProfile) throws IOException {
    Container container = this.createNonEmptyContainer();
    Signature signature = this.createSignatureBy(container, signatureProfile, this.pkcs12SignatureToken);
    container.addSignature(signature);
    return signature;
  }

  private Signature openSignatureFromExistingSignatureDocument(Container container) throws IOException {
    Signature signature = this.openAdESSignature(container);
    Assert.assertEquals("id-6a5d6671af7a9e0ab9a5e4d49d69800d", signature.getId());
    return signature;
  }

  private Signature openAdESSignature(Container container) throws IOException {
    byte[] signatureBytes = FileUtils.readFileToByteArray(new File("src/test/resources/testFiles/xades/valid-bdoc-tm.xml"));
    return SignatureBuilder.aSignature(container).openAdESSignature(signatureBytes);
  }

  private void assertSignatureIsValid(Signature signature) {
    Assert.assertNotNull(signature.getProducedAt());
    Assert.assertEquals(SignatureProfile.LT_TM, signature.getProfile());
    Assert.assertNotNull(signature.getClaimedSigningTime());
    Assert.assertNotNull(signature.getAdESSignature());
    Assert.assertTrue(signature.getAdESSignature().length > 1);
    Assert.assertTrue(signature.validateSignature().isValid());
  }

}
