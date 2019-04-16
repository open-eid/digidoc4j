package org.digidoc4j;

import java.io.File;
import java.security.MessageDigest;

import org.apache.commons.io.FileUtils;
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

    byte[] signatureValue = pkcs12EccSignatureToken.sign(dataToSign.getDigestAlgorithm(), dataToSign.getDataToSign());
    Signature signature = dataToSign.finalize(signatureValue);
    Assert.assertTrue(signature.validateSignature().isValid());
  }

  @Test
  public void signWithSignatureToken() throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes());
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest);

    Signature signature = DetachedXadesSignatureBuilder.withConfiguration(new Configuration())
        .withDataFile(digestDataFile)
        .withSignatureToken(pkcs12EccSignatureToken)
        .invokeSigning();
    Assert.assertTrue(signature.validateSignature().isValid());
  }

  @Test
  public void signWithRSASignatureToken() throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes());
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest);

    Signature signature = DetachedXadesSignatureBuilder.withConfiguration(new Configuration())
        .withDataFile(digestDataFile)
        .withSignatureToken(pkcs12SignatureToken)
        .invokeSigningProcess();
    Assert.assertTrue(signature.validateSignature().isValid());
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
    Assert.assertTrue(signature.validateSignature().isValid());
  }

  @Test
  public void signWithNormalDataFile() {
    DataFile dataFile = new DataFile("hello".getBytes(), "hello.txt", "text/plain");

    Signature signature = DetachedXadesSignatureBuilder.withConfiguration(new Configuration())
        .withDataFile(dataFile)
        .withSignatureToken(pkcs12EccSignatureToken)
        .invokeSigning();
    Assert.assertTrue(signature.validateSignature().isValid());
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
    Assert.assertTrue(signature.validateSignature().isValid());
    assertTimemarkSignature(signature);
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
    Assert.assertTrue(signature.validateSignature().isValid());
  }

}
