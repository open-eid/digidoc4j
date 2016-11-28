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

import static org.digidoc4j.testutils.TestDataBuilder.PKCS12_SIGNER;
import static org.digidoc4j.testutils.TestDataBuilder.createEmptyBDocContainer;
import static org.digidoc4j.testutils.TestDataBuilder.signContainer;
import static org.digidoc4j.testutils.TestSigningHelper.getSigningCert;
import static org.digidoc4j.utils.Helper.deserializer;
import static org.digidoc4j.utils.Helper.serialize;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.commons.io.IOUtils;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.DataFile;
import org.digidoc4j.DataToSign;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.NotYetImplementedException;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.digidoc4j.testutils.TestDataBuilder;
import org.digidoc4j.testutils.TestSigningHelper;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class BDocSerializationTest extends DigiDoc4JTestHelper {

  String testContainerPath;
  String serializedContainerPath;

  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();

  @Before
  public void setUp() throws Exception {
    testContainerPath = testFolder.newFile("container.bdoc").getPath();
    serializedContainerPath = testFolder.newFile("container.bin").getPath();
  }

  @Test
  public void twoStepSigningWithSerialization() throws IOException, ClassNotFoundException {
    String serializedDataToSignPath = testFolder.newFile().getPath();
    Container container = createEmptyBDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    X509Certificate signerCert = getSigningCert();
    DataToSign dataToSign = SignatureBuilder.
        aSignature(container).
        withSigningCertificate(signerCert).
        buildDataToSign();

    serialize(container, serializedContainerPath);
    serialize(dataToSign, serializedDataToSignPath);
    dataToSign = deserializer(serializedDataToSignPath);
    byte[] signatureValue = TestSigningHelper.sign(dataToSign.getDigestToSign(), dataToSign.getDigestAlgorithm());

    container = deserializer(serializedContainerPath);
    Signature signature = dataToSign.finalize(signatureValue);
    container.addSignature(signature);
    container.saveAsFile(testContainerPath);

    container = ContainerOpener.open(testContainerPath);

    ValidationResult validate = container.validate();
    assertTrue(validate.isValid());

    assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void verifySerialization() throws Exception {
    Container container = createEmptyBDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    signContainer(container);

    serialize(container, serializedContainerPath);

    Container deserializedContainer = deserializer(serializedContainerPath);

    assertTrue(deserializedContainer.validate().isValid());
  }

  @Test
  public void verifySerializationAfterValidationAndTimestampInitialization() {
    Container container = TestDataBuilder.open("testFiles/valid-containers/valid-bdoc-ts-signature-file-name-with-non-numeric-characters.asice");

    container.validate();
    container.getSignatures().get(0).getTimeStampCreationTime();

    serialize(container, serializedContainerPath);

    Container deserializedContainer = deserializer(serializedContainerPath);

    assertTrue(deserializedContainer.validate().isValid());
  }

  @Test
  public void serializeExistingContainer() throws Exception {
    Container container = TestDataBuilder.open("testFiles/valid-containers/valid-bdoc-tm.bdoc");
    serialize(container, serializedContainerPath);
    Container deserializedContainer = deserializer(serializedContainerPath);
    assertEquals(1, deserializedContainer.getDataFiles().size());
    assertEquals(1, deserializedContainer.getSignatures().size());
  }

  @Test
  public void validateAfterSerializingExistingContainer() throws Exception {
    Container container = TestDataBuilder.open("testFiles/valid-containers/valid-bdoc-tm.bdoc");
    serialize(container, serializedContainerPath);
    Container deserializedContainer = deserializer(serializedContainerPath);
    assertTrue(deserializedContainer.validate().isValid());
  }

  @Test
  public void serializationVerifySpecifiedSignatureParameters() throws Exception {
    Container container = createEmptyBDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureDigestAlgorithm(DigestAlgorithm.SHA512).
        withSignatureToken(PKCS12_SIGNER).
        withSignatureId("S99").
        withRoles("manager", "employee").
        withCity("city").
        withStateOrProvince("state").
        withPostalCode("postalCode").
        withCountry("country").
        invokeSigning();
    container.addSignature(signature);

    serialize(container, serializedContainerPath);

    Container deserializedContainer = deserializer(serializedContainerPath);

    Signature deserializedSignature = deserializedContainer.getSignatures().get(0);
    assertEquals("postalCode", deserializedSignature.getPostalCode());
    assertEquals("city", deserializedSignature.getCity());
    assertEquals("state", deserializedSignature.getStateOrProvince());
    assertEquals("country", deserializedSignature.getCountryName());
    assertEquals("employee", deserializedSignature.getSignerRoles().get(1));
    assertEquals("S99", deserializedSignature.getId());
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha512", deserializedSignature.getSignatureMethod());
  }

  @Test
  public void serializationVerifyDefaultSignatureParameters() throws Exception {
    Container container = createEmptyBDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    signContainer(container);
    serialize(container, serializedContainerPath);
    Container deserializedContainer = deserializer(serializedContainerPath);

    Signature signature = deserializedContainer.getSignatures().get(0);

    assertNull(signature.getCity());
    assertThat(signature.getSignerRoles(), is(empty()));
    assertTrue(signature.getId().startsWith("id-"));
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha256", signature.getSignatureMethod());
  }

  @Test
  public void serializationGetDocumentType() throws Exception {
    Container container = createEmptyBDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    signContainer(container);
    serialize(container, serializedContainerPath);
    Container deserializedContainer = deserializer(serializedContainerPath);

    assertEquals(container.getType(), deserializedContainer.getType());
  }

  @Test
  public void serializationGetOCSPCertificate() throws Exception {
    Container container = createEmptyBDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    signContainer(container);
    serialize(container, serializedContainerPath);
    Container deserializedContainer = deserializer(serializedContainerPath);

    byte[] ocspCertBeforeSerialization = container.getSignatures().get(0).getOCSPCertificate().
        getX509Certificate().getEncoded();
    byte[] ocspCertAfterSerialization = deserializedContainer.getSignatures().get(0).getOCSPCertificate().
        getX509Certificate().getEncoded();

    assertArrayEquals(ocspCertBeforeSerialization, ocspCertAfterSerialization);
  }

  @Test
  public void serializationGetSigningTime() throws Exception {
    Container container = createEmptyBDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    signContainer(container);
    serialize(container, serializedContainerPath);
    Container deserializedContainer = deserializer(serializedContainerPath);

    Date signingTimeBeforeSerialization = container.getSignatures().get(0).getClaimedSigningTime();
    Date signingTimeAfterSerialization = deserializedContainer.getSignatures().get(0).getClaimedSigningTime();

    assertEquals(signingTimeBeforeSerialization, signingTimeAfterSerialization);
  }

  @Test(expected = NotYetImplementedException.class)
  public void serializationGetPolicy() throws Exception {
    Container container = createEmptyBDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    signContainer(container);
    serialize(container, serializedContainerPath);
    Container deserializedContainer = deserializer(serializedContainerPath);

    String signaturePolicyBeforeSerialization = container.getSignatures().get(0).getPolicy();
    String signaturePolicyAfterSerialization = deserializedContainer.getSignatures().get(0).getPolicy();

    assertEquals(signaturePolicyBeforeSerialization, signaturePolicyAfterSerialization);
  }

  @Test(expected = NotYetImplementedException.class)
  public void serializationGetSignaturePolicyURI() throws Exception {
    Container container = createEmptyBDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    signContainer(container);
    serialize(container, serializedContainerPath);
    Container deserializedContainer = deserializer(serializedContainerPath);

    URI signaturePolicyURIBeforeSerialization = container.getSignatures().get(0).getSignaturePolicyURI();
    URI signaturePolicyURIAfterSerialization = deserializedContainer.getSignatures().get(0).getSignaturePolicyURI();

    assertEquals(signaturePolicyURIBeforeSerialization, signaturePolicyURIAfterSerialization);
  }

  @Test
  public void serializationGetSigningCertificate() throws Exception {
    Container container = createEmptyBDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    signContainer(container);
    serialize(container, serializedContainerPath);
    Container deserializedContainer = deserializer(serializedContainerPath);

    byte[] signingCertBeforeSerialization = container.getSignatures().get(0).getSigningCertificate().
        getX509Certificate().getEncoded();
    byte[] singingCertAfterSerialization = deserializedContainer.getSignatures().get(0).getSigningCertificate().
        getX509Certificate().getEncoded();

    assertArrayEquals(signingCertBeforeSerialization, singingCertAfterSerialization);
  }

  @Test
  public void serializationGetRawSignature() throws Exception {
    Container container = createEmptyBDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    signContainer(container);
    serialize(container, serializedContainerPath);
    Container deserializedContainer = deserializer(serializedContainerPath);

    byte[] rawSignatureBeforeSerialization = container.getSignatures().get(0).getAdESSignature();
    byte[] rawSignatureAfterSerialization = deserializedContainer.getSignatures().get(0).getAdESSignature();

    assertArrayEquals(rawSignatureBeforeSerialization, rawSignatureAfterSerialization);
  }

  @Test
  public void serializationGetTimeStampTokenCertificate() throws Exception {
    Container container = createEmptyBDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    signContainer(container, SignatureProfile.LT);
    serialize(container, serializedContainerPath);
    Container deserializedContainer = deserializer(serializedContainerPath);

    byte[] timeStampTokenCertificateBeforeSerialization = container.getSignatures().get(0).
        getTimeStampTokenCertificate().getX509Certificate().getEncoded();
    byte[] timeStampTokenCertificateAfterSerialization = deserializedContainer.getSignatures().get(0).
        getTimeStampTokenCertificate().getX509Certificate().getEncoded();

    assertArrayEquals(timeStampTokenCertificateBeforeSerialization, timeStampTokenCertificateAfterSerialization);
  }

  @Test
  public void serializationGetProfile() throws Exception {
    Container container = createEmptyBDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    signContainer(container);
    serialize(container, serializedContainerPath);
    Container deserializedContainer = deserializer(serializedContainerPath);

    SignatureProfile signatureProfileBeforeSerialization = container.getSignatures().get(0).getProfile();
    SignatureProfile signatureProfileAfterSerialization = deserializedContainer.getSignatures().get(0).getProfile();

    assertEquals(signatureProfileBeforeSerialization, signatureProfileAfterSerialization);
  }

  @Test
  public void serializationGetDataFiles() throws Exception {
    Container container = createEmptyBDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    signContainer(container);
    serialize(container, serializedContainerPath);
    Container deserializedContainer = deserializer(serializedContainerPath);

    int nrOfDataFilesBeforeSerialization = container.getDataFiles().size();
    int nrOfDataFilesAfterSerialization = deserializedContainer.getDataFiles().size();

    assertEquals(nrOfDataFilesBeforeSerialization, nrOfDataFilesAfterSerialization);
  }

  @Test
  public void serializationDataFileCheck() throws Exception {
    Container container = createEmptyBDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    signContainer(container);
    serialize(container, serializedContainerPath);
    Container deserializedContainer = deserializer(serializedContainerPath);

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
}
