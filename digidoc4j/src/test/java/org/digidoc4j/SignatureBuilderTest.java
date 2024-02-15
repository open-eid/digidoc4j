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

import org.apache.commons.io.FileUtils;
import org.digidoc4j.exceptions.InvalidSignatureException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.ServiceUnreachableException;
import org.digidoc4j.exceptions.SignatureTokenMissingException;
import org.digidoc4j.impl.asic.report.SignatureValidationReport;
import org.digidoc4j.test.CustomContainer;
import org.digidoc4j.test.MockSignatureBuilder;
import org.digidoc4j.test.TestAssert;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.digidoc4j.test.util.TestSigningUtil;
import org.digidoc4j.utils.TokenAlgorithmSupport;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

import static org.digidoc4j.Configuration.Mode.TEST;
import static org.digidoc4j.Container.DocumentType.ASICE;
import static org.digidoc4j.Container.DocumentType.ASICS;
import static org.digidoc4j.Container.DocumentType.BDOC;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInRelativeOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class SignatureBuilderTest extends AbstractTest {

  @Test
  public void aSignature_WhenContainerTypeIsDDOC_ThrowsNotSupportedException() {
    Container container = ContainerOpener.open(DDOC_TEST_FILE);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> SignatureBuilder.aSignature(container)
    );

    assertThat(caughtException.getMessage(), containsString("Unknown container type: DDOC"));
  }

  @Test
  public void aSignature_WhenContainerTypeIsPADES_ThrowsNotSupportedException() {
    Container container = ContainerOpener
            .open("src/test/resources/testFiles/invalid-containers/hello_signed_INCSAVE_signed_EDITED.pdf");

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> SignatureBuilder.aSignature(container)
    );

    assertThat(caughtException.getMessage(), containsString("Unknown container type: PADES"));
  }

  @Test
  public void buildDataToSign_WhenContainerTypeIsASiCE_ReturnsDataToSign() {
    SignatureBuilder signatureBuilder = SignatureBuilder
            .aSignature(createNonEmptyContainerBy(ASICE))
            .withSigningCertificate(pkcs12SignatureToken.getCertificate());

    DataToSign dataToSign = signatureBuilder.buildDataToSign();

    assertNotNull(dataToSign);
    assertNotNull(dataToSign.getDataToSign());
    assertNotNull(dataToSign.getSignatureParameters());
    assertEquals(DigestAlgorithm.SHA256, dataToSign.getDigestAlgorithm());
  }

  @Test
  public void buildDataToSign_WhenContainerTypeIsBDOC_ReturnsDataToSign() {
    SignatureBuilder signatureBuilder = SignatureBuilder
            .aSignature(createNonEmptyContainerBy(BDOC))
            .withSigningCertificate(pkcs12SignatureToken.getCertificate());

    DataToSign dataToSign = signatureBuilder.buildDataToSign();

    assertNotNull(dataToSign);
    assertNotNull(dataToSign.getDataToSign());
    assertNotNull(dataToSign.getSignatureParameters());
    assertEquals(DigestAlgorithm.SHA256, dataToSign.getDigestAlgorithm());
  }

  @Test
  public void buildDataToSign_WhenContainerTypeIsASiCS_ReturnsDataToSign() {
    SignatureBuilder signatureBuilder = SignatureBuilder
            .aSignature(createNonEmptyContainerBy(ASICS))
            .withSigningCertificate(pkcs12SignatureToken.getCertificate());

    DataToSign dataToSign = signatureBuilder.buildDataToSign();

    assertNotNull(dataToSign);
    assertNotNull(dataToSign.getDataToSign());
    assertNotNull(dataToSign.getSignatureParameters());
    assertEquals(DigestAlgorithm.SHA256, dataToSign.getDigestAlgorithm());
  }

  @Test
  public void buildDataToSign_WhenSignatureParametersAreProvided_ReturnsDataToSignContainingSignatureParameters() {
    SignatureBuilder signatureBuilder = SignatureBuilder
            .aSignature(createNonEmptyContainerBy(ASICE))
            .withCity("San Pedro")
            .withStateOrProvince("Puerto Vallarta")
            .withPostalCode("13456")
            .withCountry("Val Verde")
            .withRoles("Manager", "Suspicious Fisherman")
            .withDataFileDigestAlgorithm(DigestAlgorithm.SHA512)
            .withSignatureDigestAlgorithm(DigestAlgorithm.SHA384)
            .withSignatureProfile(SignatureProfile.LTA)
            .withSignatureId("S0")
            .withSigningCertificate(pkcs12SignatureToken.getCertificate());

    DataToSign dataToSign = signatureBuilder.buildDataToSign();

    SignatureParameters parameters = dataToSign.getSignatureParameters();
    assertEquals("San Pedro", parameters.getCity());
    assertEquals("Puerto Vallarta", parameters.getStateOrProvince());
    assertEquals("13456", parameters.getPostalCode());
    assertEquals("Val Verde", parameters.getCountry());
    assertEquals("Manager", parameters.getRoles().get(0));
    assertEquals(DigestAlgorithm.SHA512, parameters.getDataFileDigestAlgorithm());
    assertEquals(DigestAlgorithm.SHA384, parameters.getSignatureDigestAlgorithm());
    assertEquals(SignatureProfile.LTA, parameters.getSignatureProfile());
    assertEquals("S0", parameters.getSignatureId());
    assertSame(pkcs12SignatureToken.getCertificate(), parameters.getSigningCertificate());
    byte[] bytesToSign = dataToSign.getDataToSign();
    assertNotNull(bytesToSign);
    assertThat(bytesToSign.length, greaterThan(1));
  }

  @Test
  public void signDocumentExternallyTwice() {
    Container container = createNonEmptyContainer();

    DataToSign dataToSign = TestDataBuilderUtil.buildDataToSign(container, "S0");
    Signature signature = TestDataBuilderUtil.makeSignature(container, dataToSign);
    assertSignatureIsValid(signature, SignatureProfile.LT);

    DataToSign dataToSign2 = TestDataBuilderUtil.buildDataToSign(container, "S1");
    Signature signature2 = TestDataBuilderUtil.makeSignature(container, dataToSign2);
    assertSignatureIsValid(signature2, SignatureProfile.LT);

    ContainerValidationResult validationResult = container.validate();
    TestAssert.assertContainerIsValid(validationResult);
    List<SignatureValidationReport> reports = validationResult.getReports();
    assertThat(reports, hasSize(2));
    assertThat(reports.get(0).getId(), equalTo("S0"));
    assertThat(reports.get(1).getId(), equalTo("S1"));
  }

  @Test
  public void invokeSigning_WhenContainerTypeIsASiCE_Signature() {
    SignatureBuilder signatureBuilder = SignatureBuilder
            .aSignature(createNonEmptyContainerBy(ASICE))
            .withSignatureToken(pkcs12SignatureToken);

    Signature signature = signatureBuilder.invokeSigning();

    assertNotNull(signature);
    assertSignatureIsValid(signature, SignatureProfile.LT);
  }

  @Test
  public void invokeSigning_WhenContainerTypeIsBDOC_Signature() {
    SignatureBuilder signatureBuilder = SignatureBuilder
            .aSignature(createNonEmptyContainerBy(BDOC))
            .withSignatureToken(pkcs12SignatureToken);

    Signature signature = signatureBuilder.invokeSigning();

    assertNotNull(signature);
    assertSignatureIsValid(signature, SignatureProfile.LT);
  }

  @Test
  public void invokeSigning_WhenContainerTypeIsASiCS_Signature() {
    SignatureBuilder signatureBuilder = SignatureBuilder
            .aSignature(createNonEmptyContainerBy(ASICS))
            .withSignatureToken(pkcs12SignatureToken);

    Signature signature = signatureBuilder.invokeSigning();

    assertNotNull(signature);
    assertSignatureIsValid(signature, SignatureProfile.LT);
  }

  @Test
  public void invokeSigning_WhenSignatureParametersAreProvided_ReturnsDataToSignContainingSignatureParameters() {
    SignatureBuilder signatureBuilder = SignatureBuilder
            .aSignature(createNonEmptyContainerBy(ASICE))
            .withCity("Tallinn")
            .withStateOrProvince("Harjumaa")
            .withPostalCode("13456")
            .withCountry("Estonia")
            .withRoles("Manager", "Suspicious Fisherman")
            .withDataFileDigestAlgorithm(DigestAlgorithm.SHA384)
            .withSignatureDigestAlgorithm(DigestAlgorithm.SHA224)
            .withSignatureProfile(SignatureProfile.LTA)
            .withSignatureToken(pkcs12SignatureToken);

    Signature signature = signatureBuilder.invokeSigning();

    assertNotNull(signature);
    assertSignatureIsValid(signature, SignatureProfile.LTA);
    assertThat(signature.getCity(), equalTo("Tallinn"));
    assertThat(signature.getStateOrProvince(), equalTo("Harjumaa"));
    assertThat(signature.getPostalCode(), equalTo("13456"));
    assertThat(signature.getCountryName(), equalTo("Estonia"));
    assertThat(signature.getSignerRoles(), hasSize(2));
    assertThat(signature.getSignerRoles(), containsInRelativeOrder("Manager", "Suspicious Fisherman"));
  }

  @Test
  public void signContainerWithSignatureToken() {
    Container container = createNonEmptyContainerBy(ASICE);
    Signature signature = SignatureBuilder
            .aSignature(container)
            .withCity("Tallinn")
            .withStateOrProvince("Harjumaa")
            .withPostalCode("13456")
            .withCountry("Estonia")
            .withRoles("Manager", "Suspicious Fisherman")
            .withSignatureDigestAlgorithm(DigestAlgorithm.SHA256)
            .withSignatureProfile(SignatureProfile.LT)
            .withSignatureToken(pkcs12SignatureToken)
            .invokeSigning();
    container.addSignature(signature);
    assertTrue(signature.validateSignature().isValid());
    container.saveAsFile(getFileBy("asice"));
    assertSignatureIsValid(signature, SignatureProfile.LT);
    assertEquals("Tallinn", signature.getCity());
    assertEquals("Harjumaa", signature.getStateOrProvince());
    assertEquals("13456", signature.getPostalCode());
    assertEquals("Estonia", signature.getCountryName());
    assertEquals(2, signature.getSignerRoles().size());
    assertEquals("Manager", signature.getSignerRoles().get(0));
    assertEquals("Suspicious Fisherman", signature.getSignerRoles().get(1));
  }

  @Test
  public void invokeSigning_WhenSignatureTokenIsMissingForASiCE_ThrowsSignatureTokenMissingException() {
    Container container = createNonEmptyContainerBy(ASICE);
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container);

    assertThrows(
            SignatureTokenMissingException.class,
            signatureBuilder::invokeSigning
    );
  }

  @Test
  public void invokeSigning_WhenSignatureTokenIsMissingForBDOC_ThrowsSignatureTokenMissingException() {
    Container container = createNonEmptyContainerBy(BDOC);
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container);

    assertThrows(
            SignatureTokenMissingException.class,
            signatureBuilder::invokeSigning
    );
  }

  @Test
  public void invokeSigning_WhenSignatureTokenIsMissingForASiCS_ThrowsSignatureTokenMissingException() {
    Container container = createNonEmptyContainerBy(ASICS);
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container);

    assertThrows(
            SignatureTokenMissingException.class,
            signatureBuilder::invokeSigning
    );
  }

  @Test
  public void signWithEccCertificate() {
    Container container = createNonEmptyContainer();
    Signature signature = SignatureBuilder.aSignature(container).withSignatureToken(pkcs12EccSignatureToken)
            .withEncryptionAlgorithm(EncryptionAlgorithm.ECDSA).invokeSigning();
    assertTrue(signature.validateSignature().isValid());
    assertThat(signature.getSignatureMethod(), containsString("ecdsa"));
    assertEquals(SignatureProfile.LT, signature.getProfile());
    container.addSignature(signature);
    assertTrue(container.validate().isValid());
  }

  @Test
  public void signWith2EccCertificate() {
    Container container = createNonEmptyContainer();
    Signature signature = SignatureBuilder.aSignature(container).withSignatureToken(pkcs12EccSignatureToken)
            .withEncryptionAlgorithm(EncryptionAlgorithm.ECDSA).withSignatureDigestAlgorithm(DigestAlgorithm.SHA256)
            .withSignatureProfile(SignatureProfile.LT).invokeSigning();
    assertTrue(signature.validateSignature().isValid());
    assertThat(signature.getSignatureMethod(), containsString("ecdsa"));
    container.addSignature(signature);
    signature = SignatureBuilder.aSignature(container)
            .withSignatureToken(pkcs12Esteid2018SignatureToken)
            .withEncryptionAlgorithm(EncryptionAlgorithm.RSA).withSignatureProfile(SignatureProfile.LT).invokeSigning();
    assertTrue(signature.validateSignature().isValid());
    assertThat(signature.getSignatureMethod(), containsString("ecdsa"));
    container.addSignature(signature);
    ContainerValidationResult validationResult = container.validate();
    TestAssert.assertContainerIsValid(validationResult);
    assertHasNoWarnings(validationResult);
  }

  @Test
  public void signWithEccCertificate_determiningEncryptionAlgorithmAutomatically() {
    Container container = createNonEmptyContainer();
    Signature signature = createSignatureBy(container, pkcs12EccSignatureToken);
    assertNotNull(signature);
    assertTrue(signature.validateSignature().isValid());
    assertThat(signature.getSignatureMethod(), containsString("ecdsa"));
  }

  @Test
  public void signWithDeterminedSignatureDigestAlgorithm() throws Exception {
    Container container = createNonEmptyContainer();
    DigestAlgorithm digestAlgorithm = TokenAlgorithmSupport.determineSignatureDigestAlgorithm(pkcs12SignatureToken.getCertificate());
    DataToSign dataToSign = SignatureBuilder.aSignature(container).
        withSignatureDigestAlgorithm(digestAlgorithm).withSigningCertificate(pkcs12SignatureToken.getCertificate()).
        buildDataToSign();
    SignatureParameters signatureParameters = dataToSign.getSignatureParameters();
    assertEquals(DigestAlgorithm.SHA256, signatureParameters.getSignatureDigestAlgorithm());
    Signature signature = TestDataBuilderUtil.makeSignature(container, dataToSign);
    assertEquals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", signature.getSignatureMethod());
    assertTrue(container.validate().isValid());
  }

  @Test
  public void openSignatureFromNull_shouldThrowException() {
    SignatureBuilder signatureBuilder = SignatureBuilder
            .aSignature(createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt")));

    InvalidSignatureException caughtException = assertThrows(
            InvalidSignatureException.class,
            () -> signatureBuilder.openAdESSignature(null)
    );

    assertThat(caughtException.getMessage(), equalTo("Invalid signature document"));
  }

  @Test
  public void openSignatureFromExistingSignatureDocument() throws Exception {
    Container container = createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"));
    Signature signature = openSignatureFromExistingSignatureDocument(container);
    assertTrue(signature.validateSignature().isValid());
  }

  @Test
  public void openSignatureFromInvalidSignatureDocument() throws Exception {
    Container container = createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"));
    byte[] signatureBytes = FileUtils.readFileToByteArray(new File("src/test/resources/testFiles/helper-files/test.txt"));
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container);

    InvalidSignatureException caughtException = assertThrows(
            InvalidSignatureException.class,
            () -> signatureBuilder.openAdESSignature(signatureBytes)
    );

    assertThat(caughtException.getMessage(), equalTo("Invalid signature document"));
  }

  @Test
  public void openSignature_withDataFilesMismatch_shouldBeInvalid() throws Exception {
    Container container = createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/word_file.docx"));
    Signature signature = openAdESSignature(container);
    ValidationResult result = signature.validateSignature();
    assertFalse(result.isValid());
    TestAssert.assertContainsErrors(result.getErrors(),
            "The reference data object has not been found!"
    );
  }

  @Test
  public void openXadesSignature_withoutXmlPreamble_shouldNotThrowException() throws Exception {
    Container container = createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"));
    byte[] signatureBytes = FileUtils.readFileToByteArray(new File("src/test/resources/testFiles/xades/bdoc-tm-jdigidoc-mobile-id.xml"));
    SignatureBuilder.aSignature(container).openAdESSignature(signatureBytes);
  }

  @Test
  public void openXadesSignature_andSavingContainer_shouldNotChangeSignature() throws Exception {
    Container container = TestDataBuilderUtil.createContainerWithFile("src/test/resources/testFiles/helper-files/word_file.docx");
    Signature signature = openAdESSignature(container);
    container.addSignature(signature);
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    byte[] originalSignatureBytes = FileUtils.readFileToByteArray(new File("src/test/resources/testFiles/xades/valid-bdoc-tm.xml"));
    byte[] signatureBytes = container.getSignatures().get(0).getAdESSignature();
    assertArrayEquals(originalSignatureBytes, signatureBytes);
  }

  @Test
  public void signUnknownContainerFormat_shouldThrowException() throws Exception {
    ContainerBuilder.setContainerImplementation("TEST-FORMAT", CustomContainer.class);
    Container container = TestDataBuilderUtil.createContainerWithFile(testFolder, "TEST-FORMAT");

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> SignatureBuilder.aSignature(container)
    );

    assertThat(caughtException.getMessage(), containsString("Unknown container type: TEST-FORMAT"));
  }

  @Test
  public void signCustomContainer() throws Exception {
    ContainerBuilder.setContainerImplementation("TEST-FORMAT", CustomContainer.class);
    SignatureBuilder.setSignatureBuilderForContainerType("TEST-FORMAT", MockSignatureBuilder.class);
    Container container = TestDataBuilderUtil.createContainerWithFile(testFolder, "TEST-FORMAT");
    DataToSign dataToSign = TestDataBuilderUtil.buildDataToSign(container);
    assertNotNull(dataToSign);
    byte[] signatureValue = TestSigningUtil.sign(dataToSign.getDataToSign(), dataToSign.getDigestAlgorithm());
    Signature signature = dataToSign.finalize(signatureValue);
    assertNotNull(signature);
  }

  @Test
  public void signAsiceContainerWithExtRsaLt() {
    Container container = createNonEmptyContainerBy(ASICE);
    DataToSign dataToSign = SignatureBuilder.aSignature(container).withSignatureDigestAlgorithm(DigestAlgorithm.SHA256).
        withSignatureProfile(SignatureProfile.LT).withSigningCertificate(pkcs12SignatureToken.getCertificate()).
        buildDataToSign();
    assertNotNull(dataToSign);
    // This call mocks the using of external signing functionality with hashcode
    byte[] signatureValue = pkcs12SignatureToken.sign(dataToSign.getDigestAlgorithm(), dataToSign.getDataToSign());
    Signature signature = dataToSign.finalize(signatureValue);
    assertNotNull(signature);
    assertTrue(signature.validateSignature().isValid());
    assertThat(signature.getSignatureMethod(), containsString("rsa"));
    container.addSignature(signature);
    assertTrue(container.validate().isValid());
    container.saveAsFile(getFileBy("asice"));
  }

  @Test
  public void signAsiceContainerWithExtEccLt() {
    Container container = createNonEmptyContainerBy(ASICE);
    DataToSign dataToSign = SignatureBuilder.aSignature(container).withSignatureDigestAlgorithm(DigestAlgorithm.SHA256).
        withSignatureProfile(SignatureProfile.LT).withSigningCertificate(pkcs12EccSignatureToken.getCertificate()).
        withEncryptionAlgorithm(EncryptionAlgorithm.ECDSA).buildDataToSign();
    assertNotNull(dataToSign);
    // This call mocks the using of external signing functionality with hashcode
    byte[] signatureValue = new byte[1];
    int counter = 5;
    do {
      signatureValue = pkcs12EccSignatureToken.sign(dataToSign.getDigestAlgorithm(), dataToSign.getDataToSign());
      counter--;
    } while (signatureValue.length == 72 && counter > 0); // Somehow the signature with length 72 is not correct

    Signature signature = dataToSign.finalize(signatureValue);
    assertNotNull(signature);
    assertTrue(signature.validateSignature().isValid());
    assertThat(signature.getSignatureMethod(), containsString("ecdsa"));
    container.addSignature(signature);
    assertTrue(container.validate().isValid());
    container.saveAsFile(getFileBy("asice"));
  }

  @Test
  public void invokeSigningForCustomContainer() throws Exception {
    ContainerBuilder.setContainerImplementation("TEST-FORMAT", CustomContainer.class);
    SignatureBuilder.setSignatureBuilderForContainerType("TEST-FORMAT", MockSignatureBuilder.class);
    Container container = TestDataBuilderUtil.createContainerWithFile(testFolder, "TEST-FORMAT");
    Signature signature = SignatureBuilder.aSignature(container).withSignatureToken(pkcs12SignatureToken).
        invokeSigning();
    assertNotNull(signature);
  }

  @Test
  public void invokingSigningBBesSignatureForAsicEContainer() {
    Container container = buildContainer(ASICE, ASICE_WITH_TS_SIG);
    assertAsicEContainer(container);

    Signature signature = SignatureBuilder.aSignature(container)
            .withSignatureDigestAlgorithm(DigestAlgorithm.SHA256)
            .withSignatureProfile(SignatureProfile.B_BES)
            .withSignatureToken(pkcs12SignatureToken)
            .invokeSigning();
    assertBBesSignature(signature);
  }

  @Test
  public void invokeSigning_whenOverridingBDocContainerFormat() {
    CustomContainer.type = "BDOC";
    ContainerBuilder.setContainerImplementation("BDOC", CustomContainer.class);
    SignatureBuilder.setSignatureBuilderForContainerType("BDOC", MockSignatureBuilder.class);
    Container container = createNonEmptyContainer();
    Signature signature = createSignatureBy(container, pkcs12SignatureToken);
    assertNotNull(signature);
    CustomContainer.resetType();
  }

  @Test
  public void bDocContainerWithTMSignature_signWithBesSignature_shouldSucceed() {
    Container container = buildContainer(BDOC, BDOC_WITH_TM_SIG);
    assertBDocContainer(container);
    assertSame(1, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));

    Signature signature = signContainerWithSignature(container, SignatureProfile.B_BES);
    assertBBesSignature(signature);
    assertFalse(signature.validateSignature().isValid());

    container.addSignature(signature);
    assertBDocContainer(container);
    assertSame(2, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));
    assertBBesSignature(container.getSignatures().get(1));
  }

  @Test
  public void bDocContainerWithTMSignature_signWithTimestampSignature_shouldSucceed() {
    Container container = buildContainer(BDOC, BDOC_WITH_TM_SIG);
    assertBDocContainer(container);
    assertSame(1, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));

    Signature signature = signContainerWithSignature(container, SignatureProfile.LT);
    assertTimestampSignature(signature);
    assertTrue(signature.validateSignature().isValid());

    container.addSignature(signature);
    assertBDocContainer(container);
    assertSame(2, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));
    assertTimestampSignature(container.getSignatures().get(1));
  }

  @Test
  public void bDocContainerWithTMSignature_signWithArchiveTimestampSignature_shouldSucceed() {
    Container container = buildContainer(BDOC, BDOC_WITH_TM_SIG);
    assertBDocContainer(container);
    assertSame(1, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));

    Signature signature = signContainerWithSignature(container, SignatureProfile.LTA);
    assertArchiveTimestampSignature(signature);
    assertTrue(signature.validateSignature().isValid());

    container.addSignature(signature);
    assertBDocContainer(container);
    assertSame(2, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));
    assertArchiveTimestampSignature(container.getSignatures().get(1));
  }

  @Test
  public void bDocContainerWithTMSignature_withSignatureProfileB_EPES_shouldFail() {
    Container container = buildContainer(BDOC, BDOC_WITH_TM_SIG);
    assertBDocContainer(container);
    assertSame(1, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withSignatureProfile(SignatureProfile.B_EPES)
    );

    assertThat(caughtException.getMessage(), containsString("Can't create B_EPES signatures"));
  }

  @Test
  public void bDocContainerWithTMSignature_withSignatureProfileLT_TM_shouldFail() {
    Container container = buildContainer(BDOC, BDOC_WITH_TM_SIG);
    assertBDocContainer(container);
    assertSame(1, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withSignatureProfile(SignatureProfile.LT_TM)
    );

    assertThat(caughtException.getMessage(), containsString("Can't create LT_TM signatures"));
  }

  @Test
  public void bDocContainerWithTMSignature_withOwnSignaturePolicy_ShouldFail() {
    Container container = buildContainer(BDOC, BDOC_WITH_TM_SIG);
    assertBDocContainer(container);
    assertSame(1, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withOwnSignaturePolicy(validCustomPolicy())
    );

    assertThat(caughtException.getMessage(), containsString("Can't define signature policy"));
  }

  @Test
  public void bDocContainerWithTMSignature_withOwnSignaturePolicyWithB_BES_ShouldFail() {
    Container container = buildContainer(BDOC, BDOC_WITH_TM_SIG);
    assertBDocContainer(container);
    assertSame(1, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container)
            .withSignatureProfile(SignatureProfile.B_BES);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withOwnSignaturePolicy(validCustomPolicy())
    );

    assertThat(caughtException.getMessage(), containsString("Can't define signature policy"));
  }

  @Test
  public void bDocContainerWithTMSignature_withOwnSignaturePolicyWithLT_ShouldFail() {
    Container container = buildContainer(BDOC, BDOC_WITH_TM_SIG);
    assertBDocContainer(container);
    assertSame(1, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container)
            .withSignatureProfile(SignatureProfile.LT);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withOwnSignaturePolicy(validCustomPolicy())
    );

    assertThat(caughtException.getMessage(), containsString("Can't define signature policy"));
  }

  @Test
  public void bDocContainerWithTMSignature_withOwnSignaturePolicyWithLTA_ShouldFail() {
    Container container = buildContainer(BDOC, BDOC_WITH_TM_SIG);
    assertBDocContainer(container);
    assertSame(1, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container)
            .withSignatureProfile(SignatureProfile.LTA);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withOwnSignaturePolicy(validCustomPolicy())
    );

    assertThat(caughtException.getMessage(), containsString("Can't define signature policy"));
  }

  @Test
  public void bDocContainerWithTMAndTSSignature_signWithBesSignature_shouldSucceed() {
    Container container = buildContainer(BDOC, BDOC_WITH_TM_AND_TS_SIG);
    assertBDocContainer(container);
    assertSame(2, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));
    assertTimestampSignature(container.getSignatures().get(1));

    Signature signature = signContainerWithSignature(container, SignatureProfile.B_BES);
    assertBBesSignature(signature);
    assertFalse(signature.validateSignature().isValid());

    container.addSignature(signature);
    assertBDocContainer(container);
    assertSame(3, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));
    assertTimestampSignature(container.getSignatures().get(1));
    assertBBesSignature(container.getSignatures().get(2));
  }

  @Test
  public void bDocContainerWithTMAndTSSignature_signWithTimestampSignature_shouldSucceed() {
    Container container = buildContainer(BDOC, BDOC_WITH_TM_AND_TS_SIG);
    assertBDocContainer(container);
    assertSame(2, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));
    assertTimestampSignature(container.getSignatures().get(1));

    Signature signature = signContainerWithSignature(container, SignatureProfile.LT);
    assertTimestampSignature(signature);
    assertTrue(signature.validateSignature().isValid());

    container.addSignature(signature);
    assertBDocContainer(container);
    assertSame(3, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));
    assertTimestampSignature(container.getSignatures().get(1));
    assertTimestampSignature(container.getSignatures().get(2));
  }

  @Test
  public void bDocContainerWithTMAndTSSignature_signWithArchiveTimestampSignature_shouldSucceed() {
    Container container = buildContainer(BDOC, BDOC_WITH_TM_AND_TS_SIG);
    assertBDocContainer(container);
    assertSame(2, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));
    assertTimestampSignature(container.getSignatures().get(1));

    Signature signature = signContainerWithSignature(container, SignatureProfile.LTA);
    assertArchiveTimestampSignature(signature);
    assertTrue(signature.validateSignature().isValid());

    container.addSignature(signature);
    assertBDocContainer(container);
    assertSame(3, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));
    assertTimestampSignature(container.getSignatures().get(1));
    assertArchiveTimestampSignature(container.getSignatures().get(2));
  }

  @Test
  public void bDocContainerWithTMAndTSSignature_withSignatureProfileB_EPES_shouldFail() {
    Container container = buildContainer(BDOC, BDOC_WITH_TM_AND_TS_SIG);
    assertBDocContainer(container);
    assertSame(2, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));
    assertTimestampSignature(container.getSignatures().get(1));
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withSignatureProfile(SignatureProfile.B_EPES)
    );

    assertThat(caughtException.getMessage(), containsString("Can't create B_EPES signatures"));
  }

  @Test
  public void bDocContainerWithTMAndTSSignature_withSignatureProfileLT_TM_shouldFail() {
    Container container = buildContainer(BDOC, BDOC_WITH_TM_AND_TS_SIG);
    assertBDocContainer(container);
    assertSame(2, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));
    assertTimestampSignature(container.getSignatures().get(1));
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withSignatureProfile(SignatureProfile.LT_TM)
    );

    assertThat(caughtException.getMessage(), containsString("Can't create LT_TM signatures"));
  }

  @Test
  public void bDocContainerWithTMAndTSSignature_withOwnSignaturePolicy_ShouldFail() {
    Container container = buildContainer(BDOC, BDOC_WITH_TM_AND_TS_SIG);
    assertBDocContainer(container);
    assertSame(2, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));
    assertTimestampSignature(container.getSignatures().get(1));
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withOwnSignaturePolicy(validCustomPolicy())
    );

    assertThat(caughtException.getMessage(), containsString("Can't define signature policy"));
  }

  @Test
  public void bDocContainerWithTMAndTSSignature_withOwnSignaturePolicyWithB_BES_ShouldFail() {
    Container container = buildContainer(BDOC, BDOC_WITH_TM_AND_TS_SIG);
    assertBDocContainer(container);
    assertSame(2, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));
    assertTimestampSignature(container.getSignatures().get(1));
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container)
            .withSignatureProfile(SignatureProfile.B_BES);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withOwnSignaturePolicy(validCustomPolicy())
    );

    assertThat(caughtException.getMessage(), containsString("Can't define signature policy"));
  }

  @Test
  public void bDocContainerWithTMAndTSSignature_withOwnSignaturePolicyWithLT_ShouldFail() {
    Container container = buildContainer(BDOC, BDOC_WITH_TM_AND_TS_SIG);
    assertBDocContainer(container);
    assertSame(2, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));
    assertTimestampSignature(container.getSignatures().get(1));
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container)
            .withSignatureProfile(SignatureProfile.LT);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withOwnSignaturePolicy(validCustomPolicy())
    );

    assertThat(caughtException.getMessage(), containsString("Can't define signature policy"));
  }

  @Test
  public void bDocContainerWithTMAndTSSignature_withOwnSignaturePolicyWithLTA_ShouldFail() {
    Container container = buildContainer(BDOC, BDOC_WITH_TM_AND_TS_SIG);
    assertBDocContainer(container);
    assertSame(2, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));
    assertTimestampSignature(container.getSignatures().get(1));
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container)
            .withSignatureProfile(SignatureProfile.LTA);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withOwnSignaturePolicy(validCustomPolicy())
    );

    assertThat(caughtException.getMessage(), containsString("Can't define signature policy"));
  }

  @Test
  public void bDocContainerWithoutSignatures_signWithoutAssignedProfile_defaultProfileIsUsed_shouldSucceedWithTimestampSignature() {
    Container container = buildContainer(BDOC, ASIC_WITH_NO_SIG);
    assertBDocContainer(container);
    assertTrue(container.getSignatures().isEmpty());

    DataToSign dataToSign = SignatureBuilder.aSignature(container)
          .withSigningCertificate(pkcs12SignatureToken.getCertificate())
          .withSignatureDigestAlgorithm(DigestAlgorithm.SHA256)
          .buildDataToSign();

    Signature signature = dataToSign.finalize(pkcs12SignatureToken.sign(dataToSign.getDigestAlgorithm(), dataToSign.getDataToSign()));
    assertSame(Constant.Default.SIGNATURE_PROFILE, signature.getProfile());
    assertTimestampSignature(signature);
    assertValidSignature(signature);

    container.addSignature(signature);
    assertBDocContainer(container);
    assertSame(1, container.getSignatures().size());
    assertTimestampSignature(container.getSignatures().get(0));
  }

  @Test
  public void bDocContainerWithoutSignatures_signWithBesSignature_shouldSucceed() {
    Container container = buildContainer(BDOC, ASIC_WITH_NO_SIG);
    assertBDocContainer(container);
    assertTrue(container.getSignatures().isEmpty());

    Signature signature = signContainerWithSignature(container, SignatureProfile.B_BES);
    assertBBesSignature(signature);
    assertFalse(signature.validateSignature().isValid());

    container.addSignature(signature);
    assertBDocContainer(container);
    assertSame(1, container.getSignatures().size());
    assertBBesSignature(container.getSignatures().get(0));
  }

  @Test
  public void bDocContainerWithoutSignatures_signWithTimestampSignature_shouldSucceed() {
    Container container = buildContainer(BDOC, ASIC_WITH_NO_SIG);
    assertBDocContainer(container);
    assertTrue(container.getSignatures().isEmpty());

    Signature signature = signContainerWithSignature(container, SignatureProfile.LT);
    assertTimestampSignature(signature);
    assertTrue(signature.validateSignature().isValid());

    container.addSignature(signature);
    assertBDocContainer(container);
    assertSame(1, container.getSignatures().size());
    assertTimestampSignature(container.getSignatures().get(0));
  }

  @Test
  public void bDocContainerWithoutSignatures_signWithArchiveTimestampSignature_shouldSucceed() {
    Container container = buildContainer(BDOC, ASIC_WITH_NO_SIG);
    assertBDocContainer(container);
    assertTrue(container.getSignatures().isEmpty());

    Signature signature = signContainerWithSignature(container, SignatureProfile.LTA);
    assertArchiveTimestampSignature(signature);
    assertTrue(signature.validateSignature().isValid());

    container.addSignature(signature);
    assertBDocContainer(container);
    assertSame(1, container.getSignatures().size());
    assertArchiveTimestampSignature(container.getSignatures().get(0));
  }

  @Test
  public void bDocContainerWithoutSignatures_withSignatureProfileB_EPES_shouldFail() {
    Container container = buildContainer(BDOC, ASIC_WITH_NO_SIG);
    assertBDocContainer(container);
    assertTrue(container.getSignatures().isEmpty());
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withSignatureProfile(SignatureProfile.B_EPES)
    );

    assertThat(caughtException.getMessage(), containsString("Can't create B_EPES signatures"));
  }

  @Test
  public void bDocContainerWithoutSignatures_withSignatureProfileLT_TM_shouldFail() {
    Container container = buildContainer(BDOC, ASIC_WITH_NO_SIG);
    assertBDocContainer(container);
    assertTrue(container.getSignatures().isEmpty());
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withSignatureProfile(SignatureProfile.LT_TM)
    );

    assertThat(caughtException.getMessage(), containsString("Can't create LT_TM signatures"));
  }

  @Test
  public void bDocContainerWithoutSignatures_withOwnSignaturePolicy_ShouldFail() {
    Container container = buildContainer(BDOC, ASIC_WITH_NO_SIG);
    assertBDocContainer(container);
    assertTrue(container.getSignatures().isEmpty());
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withOwnSignaturePolicy(validCustomPolicy())
    );

    assertThat(caughtException.getMessage(), containsString("Can't define signature policy"));
  }

  @Test
  public void bDocContainerWithoutSignatures_withOwnSignaturePolicyWithB_BES_ShouldFail() {
    Container container = buildContainer(BDOC, ASIC_WITH_NO_SIG);
    assertBDocContainer(container);
    assertTrue(container.getSignatures().isEmpty());
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container)
            .withSignatureProfile(SignatureProfile.B_BES);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withOwnSignaturePolicy(validCustomPolicy())
    );

    assertThat(caughtException.getMessage(), containsString("Can't define signature policy"));
  }

  @Test
  public void bDocContainerWithoutSignatures_withOwnSignaturePolicyWithLT_ShouldFail() {
    Container container = buildContainer(BDOC, ASIC_WITH_NO_SIG);
    assertBDocContainer(container);
    assertTrue(container.getSignatures().isEmpty());
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container)
            .withSignatureProfile(SignatureProfile.LT);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withOwnSignaturePolicy(validCustomPolicy())
    );

    assertThat(caughtException.getMessage(), containsString("Can't define signature policy"));
  }

  @Test
  public void bDocContainerWithoutSignatures_withOwnSignaturePolicyWithLTA_ShouldFail() {
    Container container = buildContainer(BDOC, ASIC_WITH_NO_SIG);
    assertBDocContainer(container);
    assertTrue(container.getSignatures().isEmpty());
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container)
            .withSignatureProfile(SignatureProfile.LTA);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withOwnSignaturePolicy(validCustomPolicy())
    );

    assertThat(caughtException.getMessage(), containsString("Can't define signature policy"));
  }

  @Test
  public void asiceContainerWithoutSignatures_signWithoutAssignedProfile_defaultPofileIsUsed_shouldSucceedWithTimestampSignature() {
    Container container = buildContainer(ASICE, ASIC_WITH_NO_SIG);
    assertAsicEContainer(container);
    assertTrue(container.getSignatures().isEmpty());

    DataToSign dataToSign = SignatureBuilder.aSignature(container)
          .withSigningCertificate(pkcs12SignatureToken.getCertificate())
          .withSignatureDigestAlgorithm(DigestAlgorithm.SHA256)
          .buildDataToSign();

    Signature signature = dataToSign.finalize(pkcs12SignatureToken.sign(dataToSign.getDigestAlgorithm(), dataToSign.getDataToSign()));
    assertSame(Constant.Default.SIGNATURE_PROFILE, signature.getProfile());
    assertTimestampSignature(signature);
    assertValidSignature(signature);

    container.addSignature(signature);
    assertAsicEContainer(container);
    assertSame(1, container.getSignatures().size());
    assertTimestampSignature(container.getSignatures().get(0));
  }

  @Test
  public void signWith256EcKey_withoutAssigningSignatureDigestAlgo_sha256SignatureDigestAlgoIsUsed() {
    Container container = buildContainer(ASICE, ASIC_WITH_NO_SIG);
    assertAsicEContainer(container);
    assertTrue(container.getSignatures().isEmpty());

    DataToSign dataToSign = SignatureBuilder.aSignature(container)
            .withSigningCertificate(pkcs12EccSignatureToken.getCertificate())
            .buildDataToSign();

    Signature signature = dataToSign.finalize(pkcs12EccSignatureToken.sign(dataToSign.getDigestAlgorithm(), dataToSign.getDataToSign()));
    assertEquals(DigestAlgorithm.SHA256, dataToSign.getSignatureParameters().getSignatureDigestAlgorithm());
    assertValidSignature(signature);
  }

  @Test
  public void signWith384EcKey_withoutAssigningSignatureDigestAlgo_sha384SignatureDigestAlgoIsUsed() {
    Container container = buildContainer(ASICE, ASIC_WITH_NO_SIG);
    assertAsicEContainer(container);
    assertTrue(container.getSignatures().isEmpty());

    DataToSign dataToSign = SignatureBuilder.aSignature(container)
            .withSigningCertificate(pkcs12Esteid2018SignatureToken.getCertificate())
            .buildDataToSign();

    Signature signature = dataToSign.finalize(pkcs12Esteid2018SignatureToken.sign(dataToSign.getDigestAlgorithm(), dataToSign.getDataToSign()));
    assertEquals(DigestAlgorithm.SHA384, dataToSign.getSignatureParameters().getSignatureDigestAlgorithm());
    assertValidSignature(signature);
  }

  @Test
  public void signWithDifferentDataFileAndSignatureDigestAlgorithm() {
    Container container = createNonEmptyContainer();
    DataToSign dataToSign = SignatureBuilder.aSignature(container)
            .withSignatureDigestAlgorithm(DigestAlgorithm.SHA384)
            .withDataFileDigestAlgorithm(DigestAlgorithm.SHA512)
            .withSigningCertificate(pkcs12SignatureToken.getCertificate())
            .buildDataToSign();
    SignatureParameters signatureParameters = dataToSign.getSignatureParameters();
    assertEquals(DigestAlgorithm.SHA384, signatureParameters.getSignatureDigestAlgorithm());
    assertEquals(DigestAlgorithm.SHA512, signatureParameters.getDataFileDigestAlgorithm());
    Signature signature = dataToSign.finalize(pkcs12SignatureToken.sign(dataToSign.getDigestAlgorithm(), dataToSign.getDataToSign()));
    assertEquals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", signature.getSignatureMethod());
    assertTrue(container.validate().isValid());
  }

  @Test
  public void asiceContainerWithoutSignatures_signWithBesSignature_shouldSucceed() {
    Container container = buildContainer(ASICE, ASIC_WITH_NO_SIG);
    assertAsicEContainer(container);
    assertTrue(container.getSignatures().isEmpty());

    Signature signature = signContainerWithSignature(container, SignatureProfile.B_BES);
    assertBBesSignature(signature);
    assertFalse(signature.validateSignature().isValid());

    container.addSignature(signature);
    assertAsicEContainer(container);
    assertSame(1, container.getSignatures().size());
    assertBBesSignature(container.getSignatures().get(0));
  }

  @Test
  public void asiceContainerWithoutSignatures_signWithTimestampSignature_shouldSucceed() {
    Container container = buildContainer(ASICE, ASIC_WITH_NO_SIG);
    assertAsicEContainer(container);
    assertTrue(container.getSignatures().isEmpty());

    Signature signature = signContainerWithSignature(container, SignatureProfile.LT);
    assertTimestampSignature(signature);
    assertTrue(signature.validateSignature().isValid());

    container.addSignature(signature);
    assertAsicEContainer(container);
    assertSame(1, container.getSignatures().size());
    assertTimestampSignature(container.getSignatures().get(0));
  }

  @Test
  public void asiceContainerWithoutSignatures_signWithArchiveTimestampSignature_shouldSucceed() {
    Container container = buildContainer(ASICE, ASIC_WITH_NO_SIG);
    assertAsicEContainer(container);
    assertTrue(container.getSignatures().isEmpty());

    Signature signature = signContainerWithSignature(container, SignatureProfile.LTA);
    assertArchiveTimestampSignature(signature);
    assertTrue(signature.validateSignature().isValid());

    container.addSignature(signature);
    assertAsicEContainer(container);
    assertSame(1, container.getSignatures().size());
    assertArchiveTimestampSignature(container.getSignatures().get(0));
  }

  @Test
  public void asiceContainerWithoutSignatures_withSignatureProfileB_EPES_shouldFail() {
    Container container = buildContainer(ASICE, ASIC_WITH_NO_SIG);
    assertAsicEContainer(container);
    assertTrue(container.getSignatures().isEmpty());
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withSignatureProfile(SignatureProfile.B_EPES)
    );

    assertThat(caughtException.getMessage(), containsString("Can't create B_EPES signatures"));
  }

  @Test
  public void asiceContainerWithoutSignatures_withSignatureProfileLT_TM_shouldFail() {
    Container container = buildContainer(ASICE, ASIC_WITH_NO_SIG);
    assertAsicEContainer(container);
    assertTrue(container.getSignatures().isEmpty());
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withSignatureProfile(SignatureProfile.LT_TM)
    );

    assertThat(caughtException.getMessage(), containsString("Can't create LT_TM signatures"));
  }

  @Test
  public void asiceContainerWithoutSignatures_withOwnSignaturePolicy_ShouldFail() {
    Container container = buildContainer(ASICE, ASIC_WITH_NO_SIG);
    assertAsicEContainer(container);
    assertTrue(container.getSignatures().isEmpty());
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withOwnSignaturePolicy(validCustomPolicy())
    );

    assertThat(caughtException.getMessage(), containsString("Can't define signature policy"));
  }

  @Test
  public void asiceContainerWithoutSignatures_withOwnSignaturePolicyWithB_BES_ShouldFail() {
    Container container = buildContainer(ASICE, ASIC_WITH_NO_SIG);
    assertAsicEContainer(container);
    assertTrue(container.getSignatures().isEmpty());
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container)
            .withSignatureProfile(SignatureProfile.B_BES);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withOwnSignaturePolicy(validCustomPolicy())
    );

    assertThat(caughtException.getMessage(), containsString("Can't define signature policy"));
  }

  @Test
  public void asiceContainerWithoutSignatures_withOwnSignaturePolicyWithLT_ShouldFail() {
    Container container = buildContainer(ASICE, ASIC_WITH_NO_SIG);
    assertAsicEContainer(container);
    assertTrue(container.getSignatures().isEmpty());
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container)
            .withSignatureProfile(SignatureProfile.LT);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withOwnSignaturePolicy(validCustomPolicy())
    );

    assertThat(caughtException.getMessage(), containsString("Can't define signature policy"));
  }

  @Test
  public void asiceContainerWithoutSignatures_withOwnSignaturePolicyWithLTA_ShouldFail() {
    Container container = buildContainer(ASICE, ASIC_WITH_NO_SIG);
    assertAsicEContainer(container);
    assertTrue(container.getSignatures().isEmpty());
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container)
            .withSignatureProfile(SignatureProfile.LTA);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withOwnSignaturePolicy(validCustomPolicy())
    );

    assertThat(caughtException.getMessage(), containsString("Can't define signature policy"));
  }

  @Test
  public void asicEContainerWithTSSignature_signWithBesSignature_shouldSucceed() {
    Container container = buildContainer(ASICE, ASICE_WITH_TS_SIG);
    assertAsicEContainer(container);
    assertSame(1, container.getSignatures().size());
    assertTimestampSignature(container.getSignatures().get(0));

    Signature signature = signContainerWithSignature(container, SignatureProfile.B_BES);
    assertBBesSignature(signature);
    assertFalse(signature.validateSignature().isValid());

    container.addSignature(signature);
    assertAsicEContainer(container);
    assertSame(2, container.getSignatures().size());
    assertTimestampSignature(container.getSignatures().get(0));
    assertBBesSignature(container.getSignatures().get(1));
  }

  @Test
  public void asicEContainerWithTSSignature_signWithTimestampSignature_shouldSucceed() {
    Container container = buildContainer(ASICE, ASICE_WITH_TS_SIG);
    assertAsicEContainer(container);
    assertSame(1, container.getSignatures().size());
    assertTimestampSignature(container.getSignatures().get(0));

    Signature signature = signContainerWithSignature(container, SignatureProfile.LT);
    assertTimestampSignature(signature);
    assertTrue(signature.validateSignature().isValid());

    container.addSignature(signature);
    assertAsicEContainer(container);
    assertSame(2, container.getSignatures().size());
    assertTimestampSignature(container.getSignatures().get(0));
    assertTimestampSignature(container.getSignatures().get(1));
  }

  @Test
  public void asicEContainerWithTSSignature_signWithArchiveTimestampSignature_shouldSucceed() {
    Container container = buildContainer(ASICE, ASICE_WITH_TS_SIG);
    assertAsicEContainer(container);
    assertSame(1, container.getSignatures().size());
    assertTimestampSignature(container.getSignatures().get(0));

    Signature signature = signContainerWithSignature(container, SignatureProfile.LTA);
    assertArchiveTimestampSignature(signature);
    assertTrue(signature.validateSignature().isValid());

    container.addSignature(signature);
    assertAsicEContainer(container);
    assertSame(2, container.getSignatures().size());
    assertTimestampSignature(container.getSignatures().get(0));
    assertArchiveTimestampSignature(container.getSignatures().get(1));
  }

  @Test
  public void asicEContainerWithTSSignature_withSignatureProfileB_EPES_ShouldFail() {
    Container container = buildContainer(ASICE, ASICE_WITH_TS_SIG);
    assertAsicEContainer(container);
    assertSame(1, container.getSignatures().size());
    assertTimestampSignature(container.getSignatures().get(0));
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withSignatureProfile(SignatureProfile.B_EPES)
    );

    assertThat(caughtException.getMessage(), containsString("Can't create B_EPES signatures"));
  }

  @Test
  public void asicEContainerWithTSSignature_withSignatureProfileLT_TM_ShouldFail() {
    Container container = buildContainer(ASICE, ASICE_WITH_TS_SIG);
    assertAsicEContainer(container);
    assertSame(1, container.getSignatures().size());
    assertTimestampSignature(container.getSignatures().get(0));
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withSignatureProfile(SignatureProfile.LT_TM)
    );

    assertThat(caughtException.getMessage(), containsString("Can't create LT_TM signatures"));
  }

  @Test
  public void asicEContainerWithTSSignature_withOwnSignaturePolicy_ShouldFail() {
    Container container = buildContainer(ASICE, ASICE_WITH_TS_SIG);
    assertAsicEContainer(container);
    assertSame(1, container.getSignatures().size());
    assertTimestampSignature(container.getSignatures().get(0));
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withOwnSignaturePolicy(validCustomPolicy())
    );

    assertThat(caughtException.getMessage(), containsString("Can't define signature policy"));
  }

  @Test
  public void asicEContainerWithTSSignature_withOwnSignaturePolicyWithB_BES_ShouldFail() {
    Container container = buildContainer(ASICE, ASICE_WITH_TS_SIG);
    assertAsicEContainer(container);
    assertSame(1, container.getSignatures().size());
    assertTimestampSignature(container.getSignatures().get(0));
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container)
            .withSignatureProfile(SignatureProfile.B_BES);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withOwnSignaturePolicy(validCustomPolicy())
    );

    assertThat(caughtException.getMessage(), containsString("Can't define signature policy"));
  }

  @Test
  public void asicEContainerWithTSSignature_withOwnSignaturePolicyWithLT_ShouldFail() {
    Container container = buildContainer(ASICE, ASICE_WITH_TS_SIG);
    assertAsicEContainer(container);
    assertSame(1, container.getSignatures().size());
    assertTimestampSignature(container.getSignatures().get(0));
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container)
            .withSignatureProfile(SignatureProfile.LT);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withOwnSignaturePolicy(validCustomPolicy())
    );

    assertThat(caughtException.getMessage(), containsString("Can't define signature policy"));
  }

  @Test
  public void asicEContainerWithTSSignature_withOwnSignaturePolicyWithLTA_ShouldFail() {
    Container container = buildContainer(ASICE, ASICE_WITH_TS_SIG);
    assertAsicEContainer(container);
    assertSame(1, container.getSignatures().size());
    assertTimestampSignature(container.getSignatures().get(0));
    SignatureBuilder signatureBuilder = SignatureBuilder.aSignature(container)
            .withSignatureProfile(SignatureProfile.LTA);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withOwnSignaturePolicy(validCustomPolicy())
    );

    assertThat(caughtException.getMessage(), containsString("Can't define signature policy"));
  }

  @Test
  public void claimedSigningTimeInitializedDuringDataToSignBuilding() {
    Container container = ContainerBuilder.aContainer(ASICE).build();
    container.addDataFile(new ByteArrayInputStream("something".getBytes()), "name", "text/plain");

    Instant claimedSigningTimeLowerBound = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    DataToSign dataToSign = buildDataToSign(container, SignatureProfile.LT);
    Instant claimedSigningTimeUpperBound = Instant.now();

    Date claimedSigningTime = dataToSign.getSignatureParameters().getClaimedSigningDate();
    assertTimeInBounds(claimedSigningTime, claimedSigningTimeLowerBound, claimedSigningTimeUpperBound, Duration.ZERO);
  }

  @Test
  public void invokeSigning_networkExceptionIsNotCaught() {
    Configuration configuration = Configuration.of(TEST);
    configuration.setOcspSource("http://invalid.ocsp.url");

    expectedException.expect(ServiceUnreachableException.class);
    expectedException.expectMessage("Failed to connect to OCSP service <" + configuration.getOcspSource() + ">");

    Container container = ContainerBuilder.aContainer(Container.DocumentType.BDOC).withConfiguration(configuration).build();
    container.addDataFile(new ByteArrayInputStream("something".getBytes(StandardCharsets.UTF_8)), "file name", "text/plain");

    SignatureBuilder.aSignature(container)
          .withSignatureToken(pkcs12SignatureToken)
          .invokeSigning();
  }

  @Test
  public void dataToSignFinalize_networkExceptionIsNotCaught() {
    Configuration configuration = Configuration.of(TEST);
    configuration.setOcspSource("http://invalid.ocsp.url");

    expectedException.expect(ServiceUnreachableException.class);
    expectedException.expectMessage("Failed to connect to OCSP service <" + configuration.getOcspSource() + ">");

    Container container = ContainerBuilder.aContainer(Container.DocumentType.BDOC).withConfiguration(configuration).build();
    container.addDataFile(new ByteArrayInputStream("something".getBytes(StandardCharsets.UTF_8)), "file name", "text/plain");

    DataToSign dataToSign = SignatureBuilder.aSignature(container)
          .withSigningCertificate(pkcs12SignatureToken.getCertificate())
          .buildDataToSign();
    dataToSign.finalize(pkcs12SignatureToken.sign(dataToSign.getDigestAlgorithm(), dataToSign.getDataToSign()));
  }

  private Signature signContainerWithSignature(Container container, SignatureProfile signatureProfile) {
    DataToSign dataToSign = buildDataToSign(container, signatureProfile);
    assertNotNull(dataToSign);
    assertEquals(signatureProfile, dataToSign.getSignatureParameters().getSignatureProfile());

    return dataToSign.finalize(pkcs12SignatureToken.sign(dataToSign.getDigestAlgorithm(), dataToSign.getDataToSign()));
  }

  private DataToSign buildDataToSign(Container container, SignatureProfile signatureProfile) {
    return SignatureBuilder.aSignature(container)
              .withSigningCertificate(pkcs12SignatureToken.getCertificate())
              .withSignatureDigestAlgorithm(DigestAlgorithm.SHA256)
              .withSignatureProfile(signatureProfile)
              .buildDataToSign();
  }

  private Container buildContainer(Container.DocumentType documentType, String path) {
    try (InputStream stream = FileUtils.openInputStream(new File(path))) {
      return ContainerBuilder
              .aContainer(documentType)
              .fromStream(stream)
              .build();
    } catch (IOException e) {
      fail("Failed to read container from stream");
      throw new IllegalStateException(e);
    }
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void after() {
    ContainerBuilder.removeCustomContainerImplementations();
    SignatureBuilder.removeCustomSignatureBuilders();
  }

  private Signature openSignatureFromExistingSignatureDocument(Container container) throws IOException {
    Signature signature = openAdESSignature(container);
    assertEquals("id-6a5d6671af7a9e0ab9a5e4d49d69800d", signature.getId());
    return signature;
  }

  private Signature openAdESSignature(Container container) throws IOException {
    byte[] signatureBytes = FileUtils.readFileToByteArray(new File("src/test/resources/testFiles/xades/valid-bdoc-tm.xml"));
    return SignatureBuilder.aSignature(container).openAdESSignature(signatureBytes);
  }

  private void assertSignatureIsValid(Signature signature, SignatureProfile expectedSignatureProfile) {
    assertNotNull(signature.getOCSPResponseCreationTime());
    assertEquals(expectedSignatureProfile, signature.getProfile());
    assertNotNull(signature.getClaimedSigningTime());
    assertNotNull(signature.getAdESSignature());
    assertThat(signature.getAdESSignature().length, greaterThan(1));
    assertTrue(signature.validateSignature().isValid());
  }
}
