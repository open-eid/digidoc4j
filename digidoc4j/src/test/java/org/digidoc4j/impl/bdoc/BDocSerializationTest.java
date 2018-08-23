/* DigiDoc4J library
*
* ThMatchers.is software Matchers.is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as thMatchers.is
* project Matchers.is concerned Matchers.is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc;

import java.io.IOException;
import java.net.URI;
import java.util.Date;

import org.apache.commons.io.IOUtils;
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
import org.digidoc4j.exceptions.NotYetImplementedException;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Test;

public class BDocSerializationTest extends AbstractTest {

  private String containerLocation;
  private String serializedContainerLocation;

  @Test
  public void twoStepSigningWithSerialization() throws IOException, ClassNotFoundException {
    String serializedDataToSignPath = this.getFileBy("bdoc");
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    DataToSign dataToSign = SignatureBuilder.aSignature(container).
        withSigningCertificate(this.pkcs12SignatureToken.getCertificate()).buildDataToSign();
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
  public void verifySerialization() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    this.serialize(container, this.serializedContainerLocation);
    Container deserializedContainer = this.deserializer(this.serializedContainerLocation);
    Assert.assertTrue(deserializedContainer.validate().isValid());
  }

  @Test
  public void serializeExistingContainer() throws Exception {
    Container container = TestDataBuilderUtil.open("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc");
    serialize(container, serializedContainerLocation);
    Container deserializedContainer = deserializer(serializedContainerLocation);
    Assert.assertEquals(1, deserializedContainer.getDataFiles().size());
    Assert.assertEquals(1, deserializedContainer.getSignatures().size());
  }

  @Test
  public void validateAfterSerializingExistingContainer() throws Exception {
    Container container = TestDataBuilderUtil.open("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc");
    this.serialize(container, this.serializedContainerLocation);
    Container deserializedContainer = this.deserializer(this.serializedContainerLocation);
    Assert.assertTrue(deserializedContainer.validate().isValid());
  }

  @Test
  public void serializationVerifySpecifiedSignatureParameters() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    Signature signature = SignatureBuilder.aSignature(container).withSignatureDigestAlgorithm(DigestAlgorithm.SHA512).
        withSignatureToken(this.pkcs12SignatureToken).withSignatureId("S99").withRoles("manager", "employee").
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
    Assert.assertEquals("http://www.w3.org/2001/04/xmlenc#sha512", deserializedSignature.getSignatureMethod());
  }

  @Test
  public void serializationVerifyDefaultSignatureParameters() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    this.serialize(container, this.serializedContainerLocation);
    Container deserializedContainer = this.deserializer(this.serializedContainerLocation);
    Signature signature = deserializedContainer.getSignatures().get(0);
    Assert.assertEquals("", signature.getCity());
    Assert.assertThat(signature.getSignerRoles(), Matchers.is(Matchers.empty()));
    Assert.assertTrue(signature.getId().startsWith("id-"));
    Assert.assertEquals("http://www.w3.org/2001/04/xmlenc#sha256", signature.getSignatureMethod());
  }

  @Test
  public void serializationGetDocumentType() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    this.serialize(container, this.serializedContainerLocation);
    Container deserializedContainer = this.deserializer(this.serializedContainerLocation);
    Assert.assertEquals(container.getType(), deserializedContainer.getType());
  }

  @Test
  public void serializationGetOCSPCertificate() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    this.serialize(container, this.serializedContainerLocation);
    Container deserializedContainer = this.deserializer(this.serializedContainerLocation);
    byte[] ocspCertBeforeSerialization = container.getSignatures().get(0).getOCSPCertificate().
        getX509Certificate().getEncoded();
    byte[] ocspCertAfterSerialization = deserializedContainer.getSignatures().get(0).getOCSPCertificate().
        getX509Certificate().getEncoded();
    Assert.assertArrayEquals(ocspCertBeforeSerialization, ocspCertAfterSerialization);
  }

  @Test
  public void serializationGetSigningTime() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    this.serialize(container, this.serializedContainerLocation);
    Container deserializedContainer = this.deserializer(this.serializedContainerLocation);
    Date signingTimeBeforeSerialization = container.getSignatures().get(0).getClaimedSigningTime();
    Date signingTimeAfterSerialization = deserializedContainer.getSignatures().get(0).getClaimedSigningTime();
    Assert.assertEquals(signingTimeBeforeSerialization, signingTimeAfterSerialization);
  }

  @Test(expected = NotYetImplementedException.class)
  public void serializationGetPolicy() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    this.serialize(container, this.serializedContainerLocation);
    Container deserializedContainer = this.deserializer(this.serializedContainerLocation);
    String signaturePolicyBeforeSerialization = container.getSignatures().get(0).getPolicy();
    String signaturePolicyAfterSerialization = deserializedContainer.getSignatures().get(0).getPolicy();
    Assert.assertEquals(signaturePolicyBeforeSerialization, signaturePolicyAfterSerialization);
  }

  @Test(expected = NotYetImplementedException.class)
  public void serializationGetSignaturePolicyURI() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    this.serialize(container, this.serializedContainerLocation);
    Container deserializedContainer = this.deserializer(this.serializedContainerLocation);
    URI signaturePolicyURIBeforeSerialization = container.getSignatures().get(0).getSignaturePolicyURI();
    URI signaturePolicyURIAfterSerialization = deserializedContainer.getSignatures().get(0).getSignaturePolicyURI();
    Assert.assertEquals(signaturePolicyURIBeforeSerialization, signaturePolicyURIAfterSerialization);
  }

  @Test
  public void serializationGetSigningCertificate() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    this.serialize(container, this.serializedContainerLocation);
    Container deserializedContainer = this.deserializer(this.serializedContainerLocation);
    byte[] signingCertBeforeSerialization = container.getSignatures().get(0).getSigningCertificate().
        getX509Certificate().getEncoded();
    byte[] singingCertAfterSerialization = deserializedContainer.getSignatures().get(0).getSigningCertificate().
        getX509Certificate().getEncoded();
    Assert.assertArrayEquals(signingCertBeforeSerialization, singingCertAfterSerialization);
  }

  @Test
  public void serializationGetRawSignature() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
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
    this.createSignatureBy(container, SignatureProfile.LT, this.pkcs12SignatureToken);
    this.serialize(container, this.serializedContainerLocation);
    Container deserializedContainer = this.deserializer(this.serializedContainerLocation);
    byte[] timeStampTokenCertificateBeforeSerialization = container.getSignatures().get(0).
        getTimeStampTokenCertificate().getX509Certificate().getEncoded();
    byte[] timeStampTokenCertificateAfterSerialization = deserializedContainer.getSignatures().get(0).
        getTimeStampTokenCertificate().getX509Certificate().getEncoded();
    Assert.assertArrayEquals(timeStampTokenCertificateBeforeSerialization, timeStampTokenCertificateAfterSerialization);
  }

  @Test
  public void serializationGetProfile() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    this.serialize(container, this.serializedContainerLocation);
    Container deserializedContainer = this.deserializer(this.serializedContainerLocation);
    SignatureProfile signatureProfileBeforeSerialization = container.getSignatures().get(0).getProfile();
    SignatureProfile signatureProfileAfterSerialization = deserializedContainer.getSignatures().get(0).getProfile();
    Assert.assertEquals(signatureProfileBeforeSerialization, signatureProfileAfterSerialization);
  }

  @Test
  public void serializationGetDataFiles() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
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
    this.createSignatureBy(container, this.pkcs12SignatureToken);
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

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.containerLocation = this.getFileBy("bdoc");
    this.serializedContainerLocation = this.getFileBy("ser");
  }

}
