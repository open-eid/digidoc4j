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
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BDocSerializationTest extends AbstractTest {

  private String containerLocation;
  private String serializedContainerLocation;

  @Test
  void twoStepSigningWithSerialization() {
    String serializedDataToSignPath = getFileBy("bdoc");
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    DataToSign dataToSign = SignatureBuilder.aSignature(container)
            .withSigningCertificate(pkcs12SignatureToken.getCertificate())
            .buildDataToSign();
    serialize(container, serializedContainerLocation);
    serialize(dataToSign, serializedDataToSignPath);
    dataToSign = deserializer(serializedDataToSignPath);
    byte[] signatureValue = sign(dataToSign.getDataToSign(), dataToSign.getDigestAlgorithm());
    container = deserializer(serializedContainerLocation);
    Signature signature = dataToSign.finalize(signatureValue);
    container.addSignature(signature);
    container.saveAsFile(containerLocation);
    container = ContainerOpener.open(containerLocation);
    SignatureValidationResult validate = container.validate();
    assertTrue(validate.isValid());
    assertEquals(1, container.getSignatures().size());
  }

  @Test
  void changeConfigurationAfterDeserializationToInvalidOcspAndThrowConnectionFailureException() {
    String serializedDataToSignPath = getFileBy("bdoc");
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    DataToSign originalDataToSign = SignatureBuilder.aSignature(container)
            .withSigningCertificate(pkcs12SignatureToken.getCertificate())
            .buildDataToSign();
    serialize(container, serializedContainerLocation);
    serialize(originalDataToSign, serializedDataToSignPath);
    DataToSign deserializedDataToSign = deserializer(serializedDataToSignPath);
    deserializedDataToSign.getConfiguration().setPreferAiaOcsp(false);
    deserializedDataToSign.getConfiguration().setOcspSource("http://invalid.ocsp.url");
    byte[] signatureValue = sign(deserializedDataToSign.getDataToSign(), deserializedDataToSign.getDigestAlgorithm());

    ServiceUnreachableException caughtException = assertThrows(
            ServiceUnreachableException.class,
            () -> deserializedDataToSign.finalize(signatureValue)
    );

    assertThat(caughtException.getMessage(), containsString("Failed to connect to OCSP service"));
  }

  @Test
  void verifySerialization() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    createSignatureBy(container, pkcs12SignatureToken);
    serialize(container, serializedContainerLocation);
    Container deserializedContainer = deserializer(serializedContainerLocation);
    assertTrue(deserializedContainer.validate().isValid());
  }

  @Test
  void serializeExistingContainer() {
    Container container = TestDataBuilderUtil.open("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc");
    serialize(container, serializedContainerLocation);
    Container deserializedContainer = deserializer(serializedContainerLocation);
    assertEquals(1, deserializedContainer.getDataFiles().size());
    assertEquals(1, deserializedContainer.getSignatures().size());
  }

  @Test
  void validateAfterSerializingExistingContainer() {
    Container container = TestDataBuilderUtil.open("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc");
    serialize(container, serializedContainerLocation);
    Container deserializedContainer = deserializer(serializedContainerLocation);
    assertTrue(deserializedContainer.validate().isValid());
  }

  @Test
  void serializationVerifySpecifiedSignatureParameters() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    Signature signature = SignatureBuilder.aSignature(container).withSignatureDigestAlgorithm(DigestAlgorithm.SHA512).
        withSignatureToken(pkcs12SignatureToken).withSignatureId("S99").withRoles("manager", "employee").
        withCity("city").withStateOrProvince("state").withPostalCode("postalCode").withCountry("country").
        invokeSigning();
    container.addSignature(signature);
    serialize(container, serializedContainerLocation);
    Container deserializedContainer = deserializer(serializedContainerLocation);
    Signature deserializedSignature = deserializedContainer.getSignatures().get(0);
    assertEquals("postalCode", deserializedSignature.getPostalCode());
    assertEquals("city", deserializedSignature.getCity());
    assertEquals("state", deserializedSignature.getStateOrProvince());
    assertEquals("country", deserializedSignature.getCountryName());
    assertEquals("employee", deserializedSignature.getSignerRoles().get(1));
    assertEquals("S99", deserializedSignature.getId());
    assertEquals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", deserializedSignature.getSignatureMethod());
  }

  @Test
  void serializationVerifyDefaultSignatureParameters() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    createSignatureBy(container, pkcs12SignatureToken);
    serialize(container, serializedContainerLocation);
    Container deserializedContainer = deserializer(serializedContainerLocation);
    Signature signature = deserializedContainer.getSignatures().get(0);
    assertEquals("", signature.getCity());
    assertThat(signature.getSignerRoles(), empty());
    assertThat(signature.getId(), startsWith("id-"));
    assertEquals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", signature.getSignatureMethod());
  }

  @Test
  void serializationGetDocumentType() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    createSignatureBy(container, pkcs12SignatureToken);
    serialize(container, serializedContainerLocation);
    Container deserializedContainer = deserializer(serializedContainerLocation);
    assertEquals(container.getType(), deserializedContainer.getType());
  }

  @Test
  void serializationGetOCSPCertificate() throws Exception {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    createSignatureBy(container, pkcs12SignatureToken);
    serialize(container, serializedContainerLocation);
    Container deserializedContainer = deserializer(serializedContainerLocation);
    byte[] ocspCertBeforeSerialization = container.getSignatures().get(0).getOCSPCertificate().
        getX509Certificate().getEncoded();
    byte[] ocspCertAfterSerialization = deserializedContainer.getSignatures().get(0).getOCSPCertificate().
        getX509Certificate().getEncoded();
    assertArrayEquals(ocspCertBeforeSerialization, ocspCertAfterSerialization);
  }

  @Test
  void serializationGetSigningTime() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    createSignatureBy(container, pkcs12SignatureToken);
    serialize(container, serializedContainerLocation);
    Container deserializedContainer = deserializer(serializedContainerLocation);
    Date signingTimeBeforeSerialization = container.getSignatures().get(0).getClaimedSigningTime();
    Date signingTimeAfterSerialization = deserializedContainer.getSignatures().get(0).getClaimedSigningTime();
    assertEquals(signingTimeBeforeSerialization, signingTimeAfterSerialization);
  }

  @Test
  void serializationGetSigningCertificate() throws Exception {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    createSignatureBy(container, pkcs12SignatureToken);
    serialize(container, serializedContainerLocation);
    Container deserializedContainer = deserializer(serializedContainerLocation);
    byte[] signingCertBeforeSerialization = container.getSignatures().get(0).getSigningCertificate().
        getX509Certificate().getEncoded();
    byte[] singingCertAfterSerialization = deserializedContainer.getSignatures().get(0).getSigningCertificate().
        getX509Certificate().getEncoded();
    assertArrayEquals(signingCertBeforeSerialization, singingCertAfterSerialization);
  }

  @Test
  void serializationGetRawSignature() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    createSignatureBy(container, pkcs12SignatureToken);
    serialize(container, serializedContainerLocation);
    Container deserializedContainer = deserializer(serializedContainerLocation);
    byte[] rawSignatureBeforeSerialization = container.getSignatures().get(0).getAdESSignature();
    byte[] rawSignatureAfterSerialization = deserializedContainer.getSignatures().get(0).getAdESSignature();
    assertArrayEquals(rawSignatureBeforeSerialization, rawSignatureAfterSerialization);
  }

  @Test
  void serializationGetTimeStampTokenCertificate() throws Exception {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken);
    serialize(container, serializedContainerLocation);
    Container deserializedContainer = deserializer(serializedContainerLocation);
    byte[] timeStampTokenCertificateBeforeSerialization = container.getSignatures().get(0).
        getTimeStampTokenCertificate().getX509Certificate().getEncoded();
    byte[] timeStampTokenCertificateAfterSerialization = deserializedContainer.getSignatures().get(0).
        getTimeStampTokenCertificate().getX509Certificate().getEncoded();
    assertArrayEquals(timeStampTokenCertificateBeforeSerialization, timeStampTokenCertificateAfterSerialization);
  }

  @Test
  void serializationGetProfile() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    createSignatureBy(container, pkcs12SignatureToken);
    serialize(container, serializedContainerLocation);
    Container deserializedContainer = deserializer(serializedContainerLocation);
    SignatureProfile signatureProfileBeforeSerialization = container.getSignatures().get(0).getProfile();
    SignatureProfile signatureProfileAfterSerialization = deserializedContainer.getSignatures().get(0).getProfile();
    assertEquals(signatureProfileBeforeSerialization, signatureProfileAfterSerialization);
  }

  @Test
  void serializationGetDataFiles() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    createSignatureBy(container, pkcs12SignatureToken);
    serialize(container, serializedContainerLocation);
    Container deserializedContainer = deserializer(serializedContainerLocation);
    int nrOfDataFilesBeforeSerialization = container.getDataFiles().size();
    int nrOfDataFilesAfterSerialization = deserializedContainer.getDataFiles().size();
    assertEquals(nrOfDataFilesBeforeSerialization, nrOfDataFilesAfterSerialization);
  }

  @Test
  void serializationDataFileCheck() throws Exception {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    createSignatureBy(container, pkcs12SignatureToken);
    serialize(container, serializedContainerLocation);
    Container deserializedContainer = deserializer(serializedContainerLocation);
    DataFile dataFileBeforeSerialization = container.getDataFiles().get(0);
    DataFile dataFileAfterSerialization = deserializedContainer.getDataFiles().get(0);
    assertEquals(dataFileBeforeSerialization.getFileSize(), dataFileAfterSerialization.getFileSize());
    assertArrayEquals(dataFileBeforeSerialization.getBytes(), dataFileAfterSerialization.getBytes());
    assertEquals(dataFileBeforeSerialization.getId(), dataFileAfterSerialization.getId());
    assertEquals(dataFileBeforeSerialization.getName(), dataFileAfterSerialization.getName());
    assertEquals(dataFileBeforeSerialization.getMediaType(), dataFileAfterSerialization.getMediaType());
    byte[] bytesBeforeSerialization = IOUtils.toByteArray(dataFileBeforeSerialization.getStream());
    byte[] bytesAfterSerialization = IOUtils.toByteArray(dataFileAfterSerialization.getStream());
    assertArrayEquals(bytesBeforeSerialization, bytesAfterSerialization);
    assertArrayEquals(dataFileAfterSerialization.calculateDigest(), dataFileBeforeSerialization.calculateDigest());
  }

  @Test
  void twoStepSigningWithSerialization2() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");

    byte[] serializedContainer = SerializationUtils.serialize(container);
    container = SerializationUtils.deserialize(serializedContainer);

    DataToSign dataToSign = SignatureBuilder.aSignature(container)
            .withSigningCertificate(pkcs12SignatureToken.getCertificate())
            .buildDataToSign();

    byte[] serializedDataToSign = SerializationUtils.serialize(dataToSign);
    dataToSign = SerializationUtils.deserialize(serializedDataToSign);

    byte[] signatureValue = sign(dataToSign.getDataToSign(), dataToSign.getDigestAlgorithm());
    Signature signature = dataToSign.finalize(signatureValue);
    assertLtSignature(signature);
    assertValidSignature(signature);

    container.addSignature(signature);
    container.saveAsFile(containerLocation);
    container = ContainerOpener.open(containerLocation);
    SignatureValidationResult validationResult = container.validate();
    assertTrue(validationResult.isValid());
    assertThat(container.getSignatures(), hasSize(1));
  }


  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    containerLocation = getFileBy("bdoc");
    serializedContainerLocation = getFileBy("ser");
  }

}
