/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.bdoc;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.SerializationUtils;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.DataFile;
import org.digidoc4j.DataToSign;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.exceptions.ServiceUnreachableException;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.junit.Assert;
import org.junit.Test;

import java.util.Date;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertThrows;

public class BDocSerializationTest extends AbstractTest {

  private String containerLocation;
  private String serializedContainerLocation;

  @Test
  public void twoStepSigningWithSerialization() {
    String serializedDataToSignPath = this.getFileBy("bdoc");
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    DataToSign dataToSign = SignatureBuilder.aSignature(container)
            .withSigningCertificate(pkcs12SignatureToken.getCertificate())
            .buildDataToSign();
    this.serialize(container, this.serializedContainerLocation);
    this.serialize(dataToSign, serializedDataToSignPath);
    dataToSign = this.deserializer(serializedDataToSignPath);
    byte[] signatureValue = this.sign(dataToSign.getDataToSign(), dataToSign.getDigestAlgorithm());
    container = this.deserializer(this.serializedContainerLocation);
    Signature signature = dataToSign.finalize(signatureValue);
    container.addSignature(signature);
    container.saveAsFile(this.containerLocation);
    container = ContainerOpener.open(this.containerLocation);
    SignatureValidationResult validate = container.validate();
    Assert.assertTrue(validate.isValid());
    Assert.assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void changeConfigurationAfterDeserializationToInvalidOcspAndThrowConnectionFailureException(){
    String serializedDataToSignPath = this.getFileBy("bdoc");
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    DataToSign originalDataToSign = SignatureBuilder.aSignature(container)
            .withSigningCertificate(pkcs12SignatureToken.getCertificate())
            .buildDataToSign();
    this.serialize(container, this.serializedContainerLocation);
    this.serialize(originalDataToSign, serializedDataToSignPath);
    DataToSign deserializedDataToSign = this.deserializer(serializedDataToSignPath);
    deserializedDataToSign.getConfiguration().setOcspSource("http://invalid.ocsp.url");
    byte[] signatureValue = this.sign(deserializedDataToSign.getDataToSign(), deserializedDataToSign.getDigestAlgorithm());

    ServiceUnreachableException caughtException = assertThrows(
            ServiceUnreachableException.class,
            () -> deserializedDataToSign.finalize(signatureValue)
    );

    assertThat(caughtException.getMessage(), containsString("Failed to connect to OCSP service"));
  }

  @Test
  public void verifySerialization() {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, pkcs12SignatureToken);
    this.serialize(container, this.serializedContainerLocation);
    Container deserializedContainer = this.deserializer(this.serializedContainerLocation);
    Assert.assertTrue(deserializedContainer.validate().isValid());
  }

  @Test
  public void serializeExistingContainer() {
    Container container = TestDataBuilderUtil.open("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc");
    serialize(container, serializedContainerLocation);
    Container deserializedContainer = deserializer(serializedContainerLocation);
    Assert.assertEquals(1, deserializedContainer.getDataFiles().size());
    Assert.assertEquals(1, deserializedContainer.getSignatures().size());
  }

  @Test
  public void validateAfterSerializingExistingContainer() {
    Container container = TestDataBuilderUtil.open("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc");
    this.serialize(container, this.serializedContainerLocation);
    Container deserializedContainer = this.deserializer(this.serializedContainerLocation);
    Assert.assertTrue(deserializedContainer.validate().isValid());
  }

  @Test
  public void serializationVerifySpecifiedSignatureParameters() {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    Signature signature = SignatureBuilder.aSignature(container).withSignatureDigestAlgorithm(DigestAlgorithm.SHA512).
        withSignatureToken(pkcs12SignatureToken).withSignatureId("S99").withRoles("manager", "employee").
        withCity("city").withStateOrProvince("state").withPostalCode("postalCode").withCountry("country").
        invokeSigning();
    container.addSignature(signature);
    this.serialize(container, this.serializedContainerLocation);
    Container deserializedContainer = this.deserializer(this.serializedContainerLocation);
    Signature deserializedSignature = deserializedContainer.getSignatures().get(0);
    Assert.assertEquals("postalCode", deserializedSignature.getPostalCode());
    Assert.assertEquals("city", deserializedSignature.getCity());
    Assert.assertEquals("state", deserializedSignature.getStateOrProvince());
    Assert.assertEquals("country", deserializedSignature.getCountryName());
    Assert.assertEquals("employee", deserializedSignature.getSignerRoles().get(1));
    Assert.assertEquals("S99", deserializedSignature.getId());
    Assert.assertEquals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", deserializedSignature.getSignatureMethod());
  }

  @Test
  public void serializationVerifyDefaultSignatureParameters() {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, pkcs12SignatureToken);
    this.serialize(container, this.serializedContainerLocation);
    Container deserializedContainer = this.deserializer(this.serializedContainerLocation);
    Signature signature = deserializedContainer.getSignatures().get(0);
    Assert.assertEquals("", signature.getCity());
    assertThat(signature.getSignerRoles(), empty());
    assertThat(signature.getId(), startsWith("id-"));
    Assert.assertEquals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", signature.getSignatureMethod());
  }

  @Test
  public void serializationGetDocumentType() {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, pkcs12SignatureToken);
    this.serialize(container, this.serializedContainerLocation);
    Container deserializedContainer = this.deserializer(this.serializedContainerLocation);
    Assert.assertEquals(container.getType(), deserializedContainer.getType());
  }

  @Test
  public void serializationGetOCSPCertificate() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, pkcs12SignatureToken);
    this.serialize(container, this.serializedContainerLocation);
    Container deserializedContainer = this.deserializer(this.serializedContainerLocation);
    byte[] ocspCertBeforeSerialization = container.getSignatures().get(0).getOCSPCertificate().
        getX509Certificate().getEncoded();
    byte[] ocspCertAfterSerialization = deserializedContainer.getSignatures().get(0).getOCSPCertificate().
        getX509Certificate().getEncoded();
    Assert.assertArrayEquals(ocspCertBeforeSerialization, ocspCertAfterSerialization);
  }

  @Test
  public void serializationGetSigningTime() {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, pkcs12SignatureToken);
    this.serialize(container, this.serializedContainerLocation);
    Container deserializedContainer = this.deserializer(this.serializedContainerLocation);
    Date signingTimeBeforeSerialization = container.getSignatures().get(0).getClaimedSigningTime();
    Date signingTimeAfterSerialization = deserializedContainer.getSignatures().get(0).getClaimedSigningTime();
    Assert.assertEquals(signingTimeBeforeSerialization, signingTimeAfterSerialization);
  }

  @Test
  public void serializationGetSigningCertificate() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, pkcs12SignatureToken);
    this.serialize(container, this.serializedContainerLocation);
    Container deserializedContainer = this.deserializer(this.serializedContainerLocation);
    byte[] signingCertBeforeSerialization = container.getSignatures().get(0).getSigningCertificate().
        getX509Certificate().getEncoded();
    byte[] singingCertAfterSerialization = deserializedContainer.getSignatures().get(0).getSigningCertificate().
        getX509Certificate().getEncoded();
    Assert.assertArrayEquals(signingCertBeforeSerialization, singingCertAfterSerialization);
  }

  @Test
  public void serializationGetRawSignature() {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, pkcs12SignatureToken);
    this.serialize(container, this.serializedContainerLocation);
    Container deserializedContainer = this.deserializer(this.serializedContainerLocation);
    byte[] rawSignatureBeforeSerialization = container.getSignatures().get(0).getAdESSignature();
    byte[] rawSignatureAfterSerialization = deserializedContainer.getSignatures().get(0).getAdESSignature();
    Assert.assertArrayEquals(rawSignatureBeforeSerialization, rawSignatureAfterSerialization);
  }

  @Test
  public void serializationGetTimeStampTokenCertificate() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken);
    this.serialize(container, this.serializedContainerLocation);
    Container deserializedContainer = this.deserializer(this.serializedContainerLocation);
    byte[] timeStampTokenCertificateBeforeSerialization = container.getSignatures().get(0).
        getTimeStampTokenCertificate().getX509Certificate().getEncoded();
    byte[] timeStampTokenCertificateAfterSerialization = deserializedContainer.getSignatures().get(0).
        getTimeStampTokenCertificate().getX509Certificate().getEncoded();
    Assert.assertArrayEquals(timeStampTokenCertificateBeforeSerialization, timeStampTokenCertificateAfterSerialization);
  }

  @Test
  public void serializationGetProfile() {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, pkcs12SignatureToken);
    this.serialize(container, this.serializedContainerLocation);
    Container deserializedContainer = this.deserializer(this.serializedContainerLocation);
    SignatureProfile signatureProfileBeforeSerialization = container.getSignatures().get(0).getProfile();
    SignatureProfile signatureProfileAfterSerialization = deserializedContainer.getSignatures().get(0).getProfile();
    Assert.assertEquals(signatureProfileBeforeSerialization, signatureProfileAfterSerialization);
  }

  @Test
  public void serializationGetDataFiles() {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, pkcs12SignatureToken);
    this.serialize(container, this.serializedContainerLocation);
    Container deserializedContainer = this.deserializer(this.serializedContainerLocation);
    int nrOfDataFilesBeforeSerialization = container.getDataFiles().size();
    int nrOfDataFilesAfterSerialization = deserializedContainer.getDataFiles().size();
    Assert.assertEquals(nrOfDataFilesBeforeSerialization, nrOfDataFilesAfterSerialization);
  }

  @Test
  public void serializationDataFileCheck() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, pkcs12SignatureToken);
    this.serialize(container, this.serializedContainerLocation);
    Container deserializedContainer = this.deserializer(this.serializedContainerLocation);
    DataFile dataFileBeforeSerialization = container.getDataFiles().get(0);
    DataFile dataFileAfterSerialization = deserializedContainer.getDataFiles().get(0);
    Assert.assertEquals(dataFileBeforeSerialization.getFileSize(), dataFileAfterSerialization.getFileSize());
    Assert.assertArrayEquals(dataFileBeforeSerialization.getBytes(), dataFileAfterSerialization.getBytes());
    Assert.assertEquals(dataFileBeforeSerialization.getId(), dataFileAfterSerialization.getId());
    Assert.assertEquals(dataFileBeforeSerialization.getName(), dataFileAfterSerialization.getName());
    Assert.assertEquals(dataFileBeforeSerialization.getMediaType(), dataFileAfterSerialization.getMediaType());
    byte[] bytesBeforeSerialization = IOUtils.toByteArray(dataFileBeforeSerialization.getStream());
    byte[] bytesAfterSerialization = IOUtils.toByteArray(dataFileAfterSerialization.getStream());
    Assert.assertArrayEquals(bytesBeforeSerialization, bytesAfterSerialization);
    Assert.assertArrayEquals(dataFileAfterSerialization.calculateDigest(), dataFileBeforeSerialization.calculateDigest());
  }

  @Test
  public void twoStepSigningWithSerialization2() {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");

    byte[] serializedContainer = SerializationUtils.serialize(container);
    container = SerializationUtils.deserialize(serializedContainer);

    DataToSign dataToSign = SignatureBuilder.aSignature(container)
            .withSigningCertificate(pkcs12SignatureToken.getCertificate())
            .buildDataToSign();

    byte[] serializedDataToSign = SerializationUtils.serialize(dataToSign);
    dataToSign = SerializationUtils.deserialize(serializedDataToSign);

    byte[] signatureValue = this.sign(dataToSign.getDataToSign(), dataToSign.getDigestAlgorithm());
    Signature signature = dataToSign.finalize(signatureValue);
    assertTimestampSignature(signature);
    assertValidSignature(signature);

    container.addSignature(signature);
    container.saveAsFile(this.containerLocation);
    container = ContainerOpener.open(this.containerLocation);
    SignatureValidationResult validationResult = container.validate();
    Assert.assertTrue(validationResult.isValid());
    assertThat(container.getSignatures(), hasSize(1));
  }


  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.containerLocation = this.getFileBy("bdoc");
    this.serializedContainerLocation = this.getFileBy("ser");
  }

}
