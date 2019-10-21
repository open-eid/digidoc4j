package org.digidoc4j;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.SerializationUtils;
import org.digidoc4j.exceptions.InvalidSignatureException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.SignatureTokenMissingException;
import org.digidoc4j.exceptions.SignerCertificateRequiredException;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignature;
import org.digidoc4j.test.util.TestIdUtil;
import org.junit.Assert;
import org.junit.Test;

public class DetachedXadesSignatureBuilderTest extends AbstractTest {

  @Test
  public void signExternally() throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes());
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest, "text/plain");

    DataToSign dataToSign = DetachedXadesSignatureBuilder.withConfiguration(new Configuration())
        .withDataFile(digestDataFile)
        .withSigningCertificate(pkcs12EccSignatureToken.getCertificate())
        .buildDataToSign();

    byte[] serializedDataToSign = SerializationUtils.serialize(dataToSign);
    DataToSign deserializedDataToSign = SerializationUtils.deserialize(serializedDataToSign);

    byte[] signatureValue = pkcs12EccSignatureToken.sign(deserializedDataToSign.getDigestAlgorithm(), deserializedDataToSign.getDataToSign());
    Signature signature = dataToSign.finalize(signatureValue);
    assertTimestampSignature(signature);
    assertValidSignature(signature);
  }

  @Test
  public void signWithSignatureToken() throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes());
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest, "text/plain");

    Signature signature = DetachedXadesSignatureBuilder.withConfiguration(new Configuration())
        .withDataFile(digestDataFile)
        .withSignatureToken(pkcs12EccSignatureToken)
        .invokeSigning();

    assertTimestampSignature(signature);
    assertValidSignature(signature);
  }

  @Test
  public void signWithRSASignatureToken() throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes());
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest, "text/plain");

    Signature signature = DetachedXadesSignatureBuilder.withConfiguration(new Configuration())
        .withDataFile(digestDataFile)
        .withSignatureToken(pkcs12SignatureToken)
        .invokeSigningProcess();

    assertTimestampSignature(signature);
    assertValidSignature(signature);
  }

  @Test
  public void signWithMultipleDataFiles() throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes());
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest, "text/plain");

    byte[] digest2 = MessageDigest.getInstance("SHA-256").digest("hello2".getBytes());
    DigestDataFile digestDataFile2 = new DigestDataFile("hello2.txt", DigestAlgorithm.SHA256, digest2, "text/plain");

    Signature signature = DetachedXadesSignatureBuilder.withConfiguration(new Configuration())
        .withDataFile(digestDataFile)
        .withDataFile(digestDataFile2)
        .withSignatureToken(pkcs12EccSignatureToken)
        .invokeSigning();

    assertTimestampSignature(signature);
    assertValidSignature(signature);
  }

  @Test
  public void signWithNormalDataFile() {
    DataFile dataFile = new DataFile("hello".getBytes(), "hello.txt", "text/plain");

    Signature signature = DetachedXadesSignatureBuilder.withConfiguration(new Configuration())
        .withDataFile(dataFile)
        .withSignatureToken(pkcs12EccSignatureToken)
        .invokeSigning();

    assertTimestampSignature(signature);
    assertValidSignature(signature);
  }

  @Test(expected = SignatureTokenMissingException.class)
  public void invokeSigningWithoutSignatureTokenThrowsException() {
    DataFile dataFile = new DataFile("hello".getBytes(), "hello.txt", "text/plain");
    DetachedXadesSignatureBuilder.withConfiguration(new Configuration())
         .withDataFile(dataFile)
         .invokeSigning();
  }

  @Test(expected = SignerCertificateRequiredException.class)
  public void buildDataToSignWithoutSignatureTokenThrowsException() {
    DataFile dataFile = new DataFile("hello".getBytes(), "hello.txt", "text/plain");
    DetachedXadesSignatureBuilder.withConfiguration(new Configuration())
         .withDataFile(dataFile)
         .buildDataToSign();
  }

  @Test(expected = InvalidSignatureException.class)
  public void openAdESSignatureWithoutSignatureDocumentThrowsException() {
    DataFile dataFile = new DataFile("hello".getBytes(), "hello.txt", "text/plain");
    DetachedXadesSignatureBuilder.withConfiguration(new Configuration())
         .withDataFile(dataFile)
         .openAdESSignature(null);
  }

  @Test
  public void signWithLT_TMProfile() throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes());
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest, "text/plain");

    Signature signature = DetachedXadesSignatureBuilder.withConfiguration(new Configuration())
         .withDataFile(digestDataFile)
         .withSignatureToken(pkcs12EccSignatureToken)
         .withSignatureProfile(SignatureProfile.LT_TM)
         .invokeSigningProcess();

    assertTimemarkSignature(signature);
    assertValidSignature(signature);
  }

  @Test
  public void signWithB_EPESProfile() throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes());
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest, "text/plain");

    Signature signature = DetachedXadesSignatureBuilder.withConfiguration(new Configuration())
        .withDataFile(digestDataFile)
        .withSignatureToken(pkcs12EccSignatureToken)
        .withSignatureProfile(SignatureProfile.B_EPES)
        .invokeSigningProcess();
    assertBEpesSignature(signature);
    ValidationResult validationResult = signature.validateSignature();
    Assert.assertFalse(validationResult.isValid());
    Assert.assertEquals(1, validationResult.getWarnings().size());
    Assert.assertEquals("The signature/seal is an INDETERMINATE AdES!", validationResult.getWarnings().get(0).getMessage());
    Assert.assertEquals(1, validationResult.getErrors().size());
    Assert.assertEquals("The result of the LTV validation process is not acceptable to continue the process!", validationResult.getErrors().get(0).getMessage());
  }

  @Test
  public void signWithLTProfile() throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes());
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest, "text/plain");

    Signature signature = DetachedXadesSignatureBuilder.withConfiguration(new Configuration())
         .withDataFile(digestDataFile)
         .withSignatureToken(pkcs12EccSignatureToken)
         .withSignatureProfile(SignatureProfile.LT)
         .invokeSigningProcess();
    assertTimestampSignature(signature);
    assertValidSignature(signature);
  }

  @Test
  public void signWithLTAProfile() throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes());
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest, "text/plain");

    Signature signature = DetachedXadesSignatureBuilder.withConfiguration(new Configuration())
         .withDataFile(digestDataFile)
         .withSignatureToken(pkcs12EccSignatureToken)
         .withSignatureProfile(SignatureProfile.LTA)
         .invokeSigningProcess();
    assertArchiveTimestampSignature(signature);
    assertValidSignature(signature);
  }

  @Test
  public void signWithSignerInfo() throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes());
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest, "text/plain");

    Signature signature = DetachedXadesSignatureBuilder.withConfiguration(new Configuration())
        .withDataFile(digestDataFile)
        .withDataFile(digestDataFile)
        .withCity("myCity")
        .withStateOrProvince("myStateOrProvince")
        .withPostalCode("myPostalCode")
        .withCountry("myCountry")
        .withRoles("myRole / myResolution")
        .withSignatureId("SIGNATURE-1")
        .withSignatureToken(pkcs12EccSignatureToken)
        .invokeSigningProcess();
    Assert.assertTrue(signature.validateSignature().isValid());
    Assert.assertEquals("myCity", signature.getCity());
    Assert.assertEquals("myStateOrProvince", signature.getStateOrProvince());
    Assert.assertEquals("myPostalCode", signature.getPostalCode());
    Assert.assertEquals("myCountry", signature.getCountryName());
    Assert.assertEquals(1, signature.getSignerRoles().size());
    Assert.assertEquals("myRole / myResolution", signature.getSignerRoles().get(0));
    Assert.assertEquals("SIGNATURE-1", signature.getXmlDigitalSignatureId());
    TestIdUtil.assertMatchesSignatureIdPattern(signature.getId());
    assertTimestampSignature(signature);
    assertValidSignature(signature);
  }

  @Test
  public void readExistingSignatureAndValidate() throws Exception {
    byte[] xadesSignature =  FileUtils.readFileToByteArray(new File
        ("src/test/resources/testFiles/xades/test-signature-with-timestamp.xml"));

    byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes());
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest, "text/plain");

    Signature signature = DetachedXadesSignatureBuilder
        .withConfiguration(new Configuration())
        .withDataFile(digestDataFile)
        .openAdESSignature(xadesSignature);

    assertTimestampSignature(signature);
    assertValidSignature(signature);
  }

  @Test
  public void customSignaturePolicyAllowedForLT_TMSignatureProfile_resultsWithLTProfileBDocSignature() {
    DataFile dataFile = new DataFile("something".getBytes(StandardCharsets.UTF_8), "filename", "text/plain");
    DataToSign dataToSign = DetachedXadesSignatureBuilder.withConfiguration(new Configuration())
          .withDataFile(dataFile)
          .withSigningCertificate(this.pkcs12SignatureToken.getCertificate())
          .withSignatureProfile(SignatureProfile.LT_TM)
          .withOwnSignaturePolicy(validCustomPolicy())
          .buildDataToSign();

    byte[] signatureValue = pkcs12SignatureToken.sign(dataToSign.getDigestAlgorithm(), dataToSign.getDataToSign());
    Signature signature = dataToSign.finalize(signatureValue);

    Assert.assertNotNull(signature);
    Assert.assertTrue(signature instanceof BDocSignature);
    Assert.assertEquals(SignatureProfile.LT, signature.getProfile());
  }

  @Test
  public void customSignaturePolicyWhenSignatureProfileNotSet_resultsWithTimestampSignature() {
    DataFile dataFile = new DataFile("something".getBytes(StandardCharsets.UTF_8), "filename", "text/plain");
    DataToSign dataToSign = DetachedXadesSignatureBuilder.withConfiguration(new Configuration())
         .withDataFile(dataFile)
         .withSigningCertificate(this.pkcs12SignatureToken.getCertificate())
         .withOwnSignaturePolicy(validCustomPolicy())
         .buildDataToSign();

    byte[] signatureValue = pkcs12SignatureToken.sign(dataToSign.getDigestAlgorithm(), dataToSign.getDataToSign());
    Signature signature = dataToSign.finalize(signatureValue);
    assertTimestampSignature(signature);
  }

  @Test
  public void encryptionMethodECDSA() {
    DataFile dataFile = new DataFile("something".getBytes(StandardCharsets.UTF_8), "filename", "text/plain");
    DataToSign dataToSign = DetachedXadesSignatureBuilder.withConfiguration(new Configuration())
         .withDataFile(dataFile)
         .withSigningCertificate(this.pkcs12EccSignatureToken.getCertificate())
         .withOwnSignaturePolicy(validCustomPolicy())
         .withEncryptionAlgorithm(EncryptionAlgorithm.ECDSA)
         .buildDataToSign();

    Assert.assertEquals(EncryptionAlgorithm.ECDSA, dataToSign.getSignatureParameters().getEncryptionAlgorithm());
    byte[] signatureValue = pkcs12EccSignatureToken.sign(dataToSign.getDigestAlgorithm(), dataToSign.getDataToSign());
    Signature signature = dataToSign.finalize(signatureValue);
    assertTimestampSignature(signature);
  }

  @Test(expected = NotSupportedException.class)
  public void signatureProfileLTNotAllowedForCustomSignaturePolicy() {
    DataFile dataFile = new DataFile("something".getBytes(StandardCharsets.UTF_8), "filename", "text/plain");
    DetachedXadesSignatureBuilder.withConfiguration(new Configuration())
          .withDataFile(dataFile)
          .withSigningCertificate(this.pkcs12SignatureToken.getCertificate())
          .withOwnSignaturePolicy(validCustomPolicy())
          .withSignatureProfile(SignatureProfile.LT)
          .buildDataToSign();
  }

  @Test(expected = NotSupportedException.class)
  public void customSignaturePolicyNotAllowedForLTSignatureProfile() {
    DataFile dataFile = new DataFile("something".getBytes(StandardCharsets.UTF_8), "filename", "text/plain");
    DetachedXadesSignatureBuilder.withConfiguration(new Configuration())
          .withDataFile(dataFile)
          .withSignatureProfile(SignatureProfile.LT)
          .withOwnSignaturePolicy(validCustomPolicy())
          .buildDataToSign();
  }

  @Test
  public void signWithoutAssigningProfile_profileTakenFromConfiguration_shouldSucceedWithTimestampSignature() {
    DataFile dataFile = new DataFile("something".getBytes(StandardCharsets.UTF_8), "filename", "text/plain");
    Configuration configuration = new Configuration();
    Assert.assertSame(SignatureProfile.LT, configuration.getSignatureProfile());

    DataToSign dataToSign = DetachedXadesSignatureBuilder.withConfiguration(configuration)
         .withDataFile(dataFile)
         .withSigningCertificate(this.pkcs12SignatureToken.getCertificate())
         .withSignatureDigestAlgorithm(DigestAlgorithm.SHA256)
         .buildDataToSign();

    Signature signature = dataToSign.finalize(this.pkcs12SignatureToken.sign(dataToSign.getDigestAlgorithm(), dataToSign.getDataToSign()));
    assertTimestampSignature(signature);
    assertValidSignature(signature);
  }

  @Test
  public void mimeTypeValueNotInitialized() throws Exception{
    byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes());
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest);

    Signature signature = DetachedXadesSignatureBuilder
        .withConfiguration(new Configuration())
        .withDataFile(digestDataFile)
        .withSignatureToken(pkcs12EccSignatureToken)
        .invokeSigningProcess();

    assertTimestampSignature(signature);
    assertValidSignature(signature);
  }

  @Test
  public void mimeTypeValueNotValidated() throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes());
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest, "randomMimeType/in-valid-format");

    Signature signature = DetachedXadesSignatureBuilder
            .withConfiguration(new Configuration())
            .withDataFile(digestDataFile)
            .withSignatureToken(pkcs12EccSignatureToken)
            .invokeSigningProcess();

    assertTimestampSignature(signature);
    assertValidSignature(signature);
  }

  @Test
  public void addDetachedSignatureToContainer() throws Exception {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    String mimeType = "text/plain";
    byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes());
    DigestDataFile digestDataFile = new DigestDataFile("test.txt", DigestAlgorithm.SHA256, digest, mimeType);

    Signature signature = DetachedXadesSignatureBuilder
            .withConfiguration(configuration)
            .withDataFile(digestDataFile)
            .withSignatureToken(pkcs12EccSignatureToken)
            .withSignatureProfile(SignatureProfile.LT)
            .invokeSigningProcess();

    assertTimestampSignature(signature);
    assertValidSignature(signature);

    Container container = ContainerOpener.open(BDOC_WITH_TM_SIG, configuration);
    container.addSignature(signature);
    Assert.assertEquals(mimeType, container.getDataFiles().get(0).getMediaType());
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void addDetachedSignatureToContainerWithNotMatchingMimeType_validationShouldFail() throws Exception {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    String mimeType = "text/something-else";
    byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes());
    DigestDataFile digestDataFile = new DigestDataFile("test.txt", DigestAlgorithm.SHA256, digest, mimeType);

    Signature signature = DetachedXadesSignatureBuilder
            .withConfiguration(configuration)
            .withDataFile(digestDataFile)
            .withSignatureToken(pkcs12EccSignatureToken)
            .withSignatureProfile(SignatureProfile.LT)
            .invokeSigningProcess();

    assertTimestampSignature(signature);
    assertValidSignature(signature);

    Container container = ContainerOpener.open(BDOC_WITH_TM_SIG, configuration);
    container.addSignature(signature);
    Assert.assertNotEquals(mimeType, container.getDataFiles().get(0).getMediaType());
    ContainerValidationResult validationResult = container.validate();
    Assert.assertFalse(validationResult.isValid());
    Assert.assertSame(1, validationResult.getContainerErrors().size());
    Assert.assertTrue(validationResult.getContainerErrors().get(0).getMessage().startsWith("Manifest file has an entry for file <test.txt> with mimetype <text/plain> but the signature file for signature "));
  }
}
