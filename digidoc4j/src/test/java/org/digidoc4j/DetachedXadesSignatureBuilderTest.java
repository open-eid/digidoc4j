package org.digidoc4j;

import java.io.File;
import java.security.MessageDigest;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.SerializationUtils;
import org.junit.Assert;
import org.junit.Test;

public class DetachedXadesSignatureBuilderTest extends AbstractTest {

  @Test
  public void signExternally() throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes());
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest);

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
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest);

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
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest);

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
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest);

    byte[] digest2 = MessageDigest.getInstance("SHA-256").digest("hello2".getBytes());
    DigestDataFile digestDataFile2 = new DigestDataFile("hello2.txt", DigestAlgorithm.SHA256, digest2);

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

  @Test
  public void signWithLT_TMProfile() throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes());
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest);

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
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest);

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
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest);

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
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest);

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
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest);

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
    Assert.assertEquals("SIGNATURE-1", signature.getId());
    assertTimestampSignature(signature);
    assertValidSignature(signature);
  }

  @Test
  public void readExistingSignatureAndValidate() throws Exception {
    byte[] xadesSignature =  FileUtils.readFileToByteArray(new File
        ("src/test/resources/testFiles/xades/test-signature-with-timestamp.xml"));

    byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes());
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest);

    Signature signature = DetachedXadesSignatureBuilder
        .withConfiguration(new Configuration())
        .withDataFile(digestDataFile)
        .openAdESSignature(xadesSignature);

    assertTimestampSignature(signature);
    assertValidSignature(signature);
  }

}
