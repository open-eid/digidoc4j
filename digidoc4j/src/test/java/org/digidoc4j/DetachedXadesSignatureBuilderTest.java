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
import org.apache.commons.lang3.SerializationUtils;
import org.digidoc4j.exceptions.InvalidDataFileException;
import org.digidoc4j.exceptions.InvalidSignatureException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.SignatureTokenMissingException;
import org.digidoc4j.exceptions.SignerCertificateRequiredException;
import org.digidoc4j.test.TestAssert;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertThrows;

public class DetachedXadesSignatureBuilderTest extends AbstractTest {

  @Test
  public void signExternally() throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes());
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest, "text/plain");

    DataToSign dataToSign = DetachedXadesSignatureBuilder
            .withConfiguration(new Configuration())
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

    Signature signature = DetachedXadesSignatureBuilder
            .withConfiguration(new Configuration())
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

    Signature signature = DetachedXadesSignatureBuilder
            .withConfiguration(new Configuration())
            .withDataFile(digestDataFile)
            .withSignatureToken(pkcs12SignatureToken)
            .invokeSigning();

    assertTimestampSignature(signature);
    assertValidSignature(signature);
  }

  @Test
  public void signWithMultipleDataFiles() throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes());
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest, "text/plain");

    byte[] digest2 = MessageDigest.getInstance("SHA-256").digest("hello2".getBytes());
    DigestDataFile digestDataFile2 = new DigestDataFile("hello2.txt", DigestAlgorithm.SHA256, digest2, "text/plain");

    Signature signature = DetachedXadesSignatureBuilder
            .withConfiguration(new Configuration())
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

    Signature signature = DetachedXadesSignatureBuilder
            .withConfiguration(new Configuration())
            .withDataFile(dataFile)
            .withSignatureToken(pkcs12EccSignatureToken)
            .invokeSigning();

    assertTimestampSignature(signature);
    assertValidSignature(signature);
  }

  @Test
  public void invokeSigningWithEmptyDataFileThrowsException() {
    DataFile dataFile = new DataFile(new byte[0], "hello.txt", "text/plain");
    DetachedXadesSignatureBuilder signatureBuilder = DetachedXadesSignatureBuilder
            .withConfiguration(new Configuration())
            .withDataFile(dataFile)
            .withSignatureToken(pkcs12EccSignatureToken);

    InvalidDataFileException caughtException = assertThrows(
            InvalidDataFileException.class,
            signatureBuilder::invokeSigning
    );

    assertThat(caughtException.getMessage(), startsWith("Cannot sign empty datafile"));
  }

  @Test
  public void buildDataToSignWithEmptyDataFileThrowsException() {
    DataFile dataFile = new DataFile(new byte[0], "hello.txt", "text/plain");
    DetachedXadesSignatureBuilder signatureBuilder = DetachedXadesSignatureBuilder
            .withConfiguration(new Configuration())
            .withDataFile(dataFile)
            .withSigningCertificate(pkcs12EccSignatureToken.getCertificate());

    InvalidDataFileException caughtException = assertThrows(
            InvalidDataFileException.class,
            signatureBuilder::buildDataToSign
    );

    assertThat(caughtException.getMessage(), startsWith("Cannot sign empty datafile"));
  }

  @Test
  public void invokeSigningWithoutSignatureTokenThrowsException() {
    DataFile dataFile = new DataFile("hello".getBytes(), "hello.txt", "text/plain");
    DetachedXadesSignatureBuilder signatureBuilder = DetachedXadesSignatureBuilder
            .withConfiguration(new Configuration())
            .withDataFile(dataFile);

    SignatureTokenMissingException caughtException = assertThrows(
            SignatureTokenMissingException.class,
            signatureBuilder::invokeSigning
    );

    assertThat(caughtException.getMessage(), nullValue());
  }

  @Test
  public void buildDataToSignWithoutSignatureTokenThrowsException() {
    DataFile dataFile = new DataFile("hello".getBytes(), "hello.txt", "text/plain");
    DetachedXadesSignatureBuilder signatureBuilder = DetachedXadesSignatureBuilder
            .withConfiguration(new Configuration())
            .withDataFile(dataFile);

    SignerCertificateRequiredException caughtException = assertThrows(
            SignerCertificateRequiredException.class,
            signatureBuilder::buildDataToSign
    );

    assertThat(caughtException.getMessage(), nullValue());
  }

  @Test
  public void openAdESSignatureWithoutSignatureDocumentThrowsException() {
    DataFile dataFile = new DataFile("hello".getBytes(), "hello.txt", "text/plain");
    DetachedXadesSignatureBuilder signatureBuilder = DetachedXadesSignatureBuilder
            .withConfiguration(new Configuration())
            .withDataFile(dataFile);

    InvalidSignatureException caughtException = assertThrows(
            InvalidSignatureException.class,
            () -> signatureBuilder.openAdESSignature(null)
    );

    assertThat(caughtException.getMessage(), equalTo("Invalid signature document"));
  }

  @Test
  public void usingLT_TMProfileNotAllowed() {
    DetachedXadesSignatureBuilder signatureBuilder = DetachedXadesSignatureBuilder
            .withConfiguration(new Configuration());

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withSignatureProfile(SignatureProfile.LT_TM)
    );

    assertThat(caughtException.getMessage(), containsString("Can't create LT_TM signatures"));
  }

  @Test
  public void usingB_EPESProfileNotAllowed() {
    DetachedXadesSignatureBuilder signatureBuilder = DetachedXadesSignatureBuilder
            .withConfiguration(new Configuration());

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withSignatureProfile(SignatureProfile.B_EPES)
    );

    assertThat(caughtException.getMessage(), containsString("Can't create B_EPES signatures"));
  }

  @Test
  public void signWithB_BESProfile() throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes());
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest, "text/plain");

    Signature signature = DetachedXadesSignatureBuilder
            .withConfiguration(new Configuration())
            .withDataFile(digestDataFile)
            .withSignatureToken(pkcs12EccSignatureToken)
            .withSignatureProfile(SignatureProfile.B_BES)
            .invokeSigning();

    assertBBesSignature(signature);
    ValidationResult validationResult = signature.validateSignature();
    Assert.assertFalse(validationResult.isValid());
    TestAssert.assertContainsExactSetOfErrors(validationResult.getWarnings(),
            "The signature/seal is an INDETERMINATE AdES digital signature!"
    );
    TestAssert.assertContainsExactSetOfErrors(validationResult.getErrors(),
            "The certificate validation is not conclusive!",
            "No revocation data found for the certificate!"
    );
  }

  @Test
  public void signWithLTProfile() throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes());
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest, "text/plain");

    Signature signature = DetachedXadesSignatureBuilder
            .withConfiguration(new Configuration())
            .withDataFile(digestDataFile)
            .withSignatureToken(pkcs12EccSignatureToken)
            .withSignatureProfile(SignatureProfile.LT)
            .invokeSigning();

    assertTimestampSignature(signature);
    assertValidSignature(signature);
  }

  @Test
  public void signWithLTAProfileNotAllowed() throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes());
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest, "text/plain");

    DetachedXadesSignatureBuilder signatureBuilder = DetachedXadesSignatureBuilder
            .withConfiguration(new Configuration())
            .withDataFile(digestDataFile)
            .withSignatureToken(pkcs12EccSignatureToken)
            .withSignatureProfile(SignatureProfile.LTA);

    IllegalArgumentException caughtException = assertThrows(
            IllegalArgumentException.class,
            signatureBuilder::invokeSigning
    );

    assertThat(caughtException.getMessage(), equalTo(
            "XAdES-LTA requires complete binaries of signed documents! Extension with a DigestDocument is not possible."
    ));
  }

  @Test
  public void signWithSignerInfo() throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes());
    DigestDataFile digestDataFile1 = new DigestDataFile("hello1.txt", DigestAlgorithm.SHA256, digest, "text/plain");
    DigestDataFile digestDataFile2 = new DigestDataFile("hello2.txt", DigestAlgorithm.SHA256, digest, "text/plain");

    Signature signature = DetachedXadesSignatureBuilder
            .withConfiguration(new Configuration())
            .withDataFile(digestDataFile1)
            .withDataFile(digestDataFile2)
            .withCity("myCity")
            .withStateOrProvince("myStateOrProvince")
            .withPostalCode("myPostalCode")
            .withCountry("myCountry")
            .withRoles("myRole / myResolution")
            .withSignatureId("SIGNATURE-1")
            .withSignatureToken(pkcs12EccSignatureToken)
            .invokeSigning();

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
    DigestDataFile digestDataFile = new DigestDataFile("hello.txt", DigestAlgorithm.SHA256, digest, "text/plain");

    Signature signature = DetachedXadesSignatureBuilder
            .withConfiguration(new Configuration())
            .withDataFile(digestDataFile)
            .openAdESSignature(xadesSignature);

    assertTimestampSignature(signature);
    assertValidSignatureWithWarnings(signature);
  }

  @Test
  public void usingCustomSignaturePolicy_WhenSignatureProfileNotSet_NotSupported() {
    DetachedXadesSignatureBuilder signatureBuilder = DetachedXadesSignatureBuilder
            .withConfiguration(new Configuration());

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withOwnSignaturePolicy(validCustomPolicy())
    );

    assertThat(caughtException.getMessage(), containsString("Can't define signature policy"));
  }

  @Test
  public void usingCustomSignaturePolicy_WhenSignatureProfileIsB_BES_NotSupported() {
    DetachedXadesSignatureBuilder signatureBuilder = DetachedXadesSignatureBuilder
            .withConfiguration(new Configuration())
            .withSignatureProfile(SignatureProfile.B_BES);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withOwnSignaturePolicy(validCustomPolicy())
    );

    assertThat(caughtException.getMessage(), containsString("Can't define signature policy"));
  }

  @Test
  public void usingCustomSignaturePolicy_WhenSignatureProfileIsLT_NotSupported() {
    DetachedXadesSignatureBuilder signatureBuilder = DetachedXadesSignatureBuilder
            .withConfiguration(new Configuration())
            .withSignatureProfile(SignatureProfile.LT);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> signatureBuilder.withOwnSignaturePolicy(validCustomPolicy())
    );

    assertThat(caughtException.getMessage(), containsString("Can't define signature policy"));
  }

  @Test
  public void encryptionMethodECDSA() {
    DataFile dataFile = new DataFile("something".getBytes(StandardCharsets.UTF_8), "filename", "text/plain");
    DataToSign dataToSign = DetachedXadesSignatureBuilder
            .withConfiguration(new Configuration())
            .withDataFile(dataFile)
            .withSignatureProfile(SignatureProfile.LT)
            .withSigningCertificate(pkcs12EccSignatureToken.getCertificate())
            .withEncryptionAlgorithm(EncryptionAlgorithm.ECDSA)
            .buildDataToSign();

    Assert.assertEquals(EncryptionAlgorithm.ECDSA, dataToSign.getSignatureParameters().getEncryptionAlgorithm());
    byte[] signatureValue = pkcs12EccSignatureToken.sign(dataToSign.getDigestAlgorithm(), dataToSign.getDataToSign());
    Signature signature = dataToSign.finalize(signatureValue);
    assertTimestampSignature(signature);
  }

  @Test
  public void signWithoutAssigningProfile_defaultPofileIsUsed_shouldSucceedWithTimestampSignature() {
    DataFile dataFile = new DataFile("something".getBytes(StandardCharsets.UTF_8), "filename", "text/plain");
    Configuration configuration = new Configuration();

    DataToSign dataToSign = DetachedXadesSignatureBuilder
            .withConfiguration(configuration)
            .withDataFile(dataFile)
            .withSigningCertificate(pkcs12SignatureToken.getCertificate())
            .withSignatureDigestAlgorithm(DigestAlgorithm.SHA256)
            .buildDataToSign();

    Signature signature = dataToSign.finalize(pkcs12SignatureToken.sign(dataToSign.getDigestAlgorithm(), dataToSign.getDataToSign()));
    Assert.assertSame(Constant.Default.SIGNATURE_PROFILE, signature.getProfile());
    assertTimestampSignature(signature);
    assertValidSignature(signature);
  }

  @Test
  public void signWith256EcKey_withoutAssigningSignatureDigestAlgo_sha256SignatureDigestAlgoIsUsed() {
    DataFile dataFile = new DataFile("something".getBytes(StandardCharsets.UTF_8), "filename", "text/plain");
    Configuration configuration = new Configuration();

    DataToSign dataToSign = DetachedXadesSignatureBuilder
            .withConfiguration(configuration)
            .withDataFile(dataFile)
            .withSigningCertificate(pkcs12EccSignatureToken.getCertificate())
            .buildDataToSign();

    Signature signature = dataToSign.finalize(pkcs12EccSignatureToken.sign(dataToSign.getDigestAlgorithm(), dataToSign.getDataToSign()));
    Assert.assertEquals(DigestAlgorithm.SHA256, dataToSign.getSignatureParameters().getSignatureDigestAlgorithm());
    assertValidSignature(signature);
  }

  @Test
  public void signWith384EcKey_withoutAssigningSignatureDigestAlgo_sha384SignatureDigestAlgoIsUsed() {
    DataFile dataFile = new DataFile("something".getBytes(StandardCharsets.UTF_8), "filename", "text/plain");
    Configuration configuration = new Configuration();

    DataToSign dataToSign = DetachedXadesSignatureBuilder
            .withConfiguration(configuration)
            .withDataFile(dataFile)
            .withSigningCertificate(pkcs12Esteid2018SignatureToken.getCertificate())
            .buildDataToSign();

    Signature signature = dataToSign.finalize(pkcs12Esteid2018SignatureToken.sign(dataToSign.getDigestAlgorithm(), dataToSign.getDataToSign()));
    Assert.assertEquals(DigestAlgorithm.SHA384, dataToSign.getSignatureParameters().getSignatureDigestAlgorithm());
    assertValidSignature(signature);
  }

  @Test
  public void signWithDifferentDataFileAndSignatureDigestAlgorithm() {
    DataFile dataFile = new DataFile("something".getBytes(StandardCharsets.UTF_8), "filename", "text/plain");
    Configuration configuration = new Configuration();

    DataToSign dataToSign = DetachedXadesSignatureBuilder
            .withConfiguration(configuration)
            .withSignatureDigestAlgorithm(DigestAlgorithm.SHA384)
            .withDataFileDigestAlgorithm(DigestAlgorithm.SHA512)
            .withDataFile(dataFile)
            .withSigningCertificate(pkcs12SignatureToken.getCertificate())
            .buildDataToSign();

    SignatureParameters signatureParameters = dataToSign.getSignatureParameters();
    Assert.assertEquals(DigestAlgorithm.SHA384, signatureParameters.getSignatureDigestAlgorithm());
    Assert.assertEquals(DigestAlgorithm.SHA512, signatureParameters.getDataFileDigestAlgorithm());
    Signature signature = dataToSign.finalize(pkcs12SignatureToken.sign(dataToSign.getDigestAlgorithm(), dataToSign.getDataToSign()));
    Assert.assertEquals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", signature.getSignatureMethod());
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
            .invokeSigning();

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
            .invokeSigning();

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
