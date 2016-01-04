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

import static org.digidoc4j.ContainerBuilder.BDOC_CONTAINER_TYPE;
import static org.digidoc4j.testutils.TestSigningHelper.getSigningCert;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.cert.X509Certificate;

import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.SignatureTokenMissingException;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.digidoc4j.testutils.TestSignatureBuilder;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.digidoc4j.testutils.TestContainer;
import org.digidoc4j.testutils.TestDataBuilder;
import org.digidoc4j.testutils.TestSigningHelper;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class SignatureBuilderTest extends DigiDoc4JTestHelper {

  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();
  private final PKCS12SignatureToken testSignatureToken = new PKCS12SignatureToken("testFiles/signout.p12", "test".toCharArray());

  @After
  public void tearDown() throws Exception {
    ContainerBuilder.removeCustomContainerImplementations();
    SignatureBuilder.removeCustomSignatureBuilders();
  }

  @Test
  public void buildingDataToSign_shouldContainSignatureParameters() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile(testFolder);
    X509Certificate signerCert = getSigningCert();
    SignatureBuilder builder = SignatureBuilder.
        aSignature(container).
        withCity("San Pedro").
        withStateOrProvince("Puerto Vallarta").
        withPostalCode("13456").
        withCountry("Val Verde").
        withRoles("Manager", "Suspicious Fisherman").
        withSignatureDigestAlgorithm(DigestAlgorithm.SHA256).
        withSignatureProfile(SignatureProfile.LT_TM).
        withSignatureId("S0").
        withSigningCertificate(signerCert);
    DataToSign dataToSign = builder.buildDataToSign();
    SignatureParameters parameters = dataToSign.getSignatureParameters();
    assertEquals("San Pedro", parameters.getCity());
    assertEquals("Puerto Vallarta", parameters.getStateOrProvince());
    assertEquals("13456", parameters.getPostalCode());
    assertEquals("Val Verde", parameters.getCountry());
    assertEquals("Manager", parameters.getRoles().get(0));
    assertEquals(DigestAlgorithm.SHA256, parameters.getDigestAlgorithm());
    assertEquals(SignatureProfile.LT_TM, parameters.getSignatureProfile());
    assertEquals("S0", parameters.getSignatureId());
    assertSame(signerCert, parameters.getSigningCertificate());
    byte[] bytesToSign = dataToSign.getDigestToSign();
    assertNotNull(bytesToSign);
    assertTrue(bytesToSign.length > 1);
  }

  @Test
  public void signDocumentExternallyTwice() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile(testFolder);

    DataToSign dataToSign = TestDataBuilder.buildDataToSign(container, "S0");
    Signature signature = TestDataBuilder.makeSignature(container, dataToSign);
    assertSignatureIsValid(signature);

    DataToSign dataToSign2 = TestDataBuilder.buildDataToSign(container, "S1");
    Signature signature2 = TestDataBuilder.makeSignature(container, dataToSign2);
    assertSignatureIsValid(signature2);

    container.saveAsFile(testFolder.newFile("test-container.bdoc").getPath());
  }

  @Test
  public void signContainerWithSignatureToken() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile(testFolder);

    Signature signature = SignatureBuilder.
        aSignature(container).
        withCity("Tallinn").
        withStateOrProvince("Harjumaa").
        withPostalCode("13456").
        withCountry("Estonia").
        withRoles("Manager", "Suspicious Fisherman").
        withSignatureDigestAlgorithm(DigestAlgorithm.SHA256).
        withSignatureProfile(SignatureProfile.LT_TM).
        withSignatureToken(testSignatureToken).
        invokeSigning();

    container.addSignature(signature);
    container.saveAsFile(testFolder.newFile("test-container2.bdoc").getPath());

    assertSignatureIsValid(signature);
  }

  @Test
  public void signDDocContainerWithSignatureToken() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile(testFolder, "DDOC");
    assertEquals("DDOC", container.getType());

    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureDigestAlgorithm(DigestAlgorithm.SHA1).
        withSignatureToken(testSignatureToken).
        invokeSigning();

    container.addSignature(signature);
  }

  @Test(expected = SignatureTokenMissingException.class)
  public void signContainerWithMissingSignatureToken_shouldThrowException() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile(testFolder);
    SignatureBuilder.
        aSignature(container).
        invokeSigning();
  }

  @Test
  public void signDDocContainer() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile(testFolder, "DDOC");
    X509Certificate signingCert = getSigningCert();
    DataToSign dataToSign = SignatureBuilder.
        aSignature(container).
        withSigningCertificate(signingCert).
        buildDataToSign();

    assertEquals(DigestAlgorithm.SHA1, dataToSign.getDigestAlgorithm());
    byte[] bytesToSign = dataToSign.getDigestToSign();
    assertNotNull(bytesToSign);
    assertTrue(bytesToSign.length > 1);

    byte[] signatureValue = TestSigningHelper.sign(dataToSign.getDigestToSign(), dataToSign.getDigestAlgorithm());
    assertNotNull(signatureValue);
    assertTrue(signatureValue.length > 1);

    Signature signature = dataToSign.finalize(signatureValue);
    assertNotNull(signature);
    assertNotNull(signature.getClaimedSigningTime());

    container.addSignature(signature);
    container.saveAsFile(testFolder.newFile("test-container.bdoc").getPath());
  }

  @Test
  public void signatureProfileShouldBeSetProperlyForBDoc() throws Exception {
    Signature signature = createBDocSignatureWithProfile(SignatureProfile.B_BES);
    assertEquals(SignatureProfile.B_BES, signature.getProfile());
  }

  @Test
  public void signatureProfileShouldBeSetProperlyForBDocTS() throws Exception {
    Signature signature = createBDocSignatureWithProfile(SignatureProfile.LT);
    assertEquals(SignatureProfile.LT, signature.getProfile());
  }

  @Test
  public void signatureProfileShouldBeSetProperlyForBDocTM() throws Exception {
    Signature signature = createBDocSignatureWithProfile(SignatureProfile.LT_TM);
    assertEquals(SignatureProfile.LT_TM, signature.getProfile());
  }

  @Test(expected = NotSupportedException.class)
  public void signUnknownContainerFormat_shouldThrowException() throws Exception {
    ContainerBuilder.setContainerImplementation("TEST-FORMAT", TestContainer.class);
    Container container = TestDataBuilder.createContainerWithFile(testFolder, "TEST-FORMAT");
    TestDataBuilder.buildDataToSign(container);
  }

  @Test
  public void signCustomContainer() throws Exception {
    ContainerBuilder.setContainerImplementation("TEST-FORMAT", TestContainer.class);
    SignatureBuilder.setSignatureBuilderForContainerType("TEST-FORMAT", TestSignatureBuilder.class);
    Container container = TestDataBuilder.createContainerWithFile(testFolder, "TEST-FORMAT");
    DataToSign dataToSign = TestDataBuilder.buildDataToSign(container);
    assertNotNull(dataToSign);
    byte[] signatureValue = TestSigningHelper.sign(dataToSign.getDigestToSign(), dataToSign.getDigestAlgorithm());
    Signature signature = dataToSign.finalize(signatureValue);
    assertNotNull(signature);
  }

  @Test
  public void invokeSigningForCustomContainer() throws Exception {
    ContainerBuilder.setContainerImplementation("TEST-FORMAT", TestContainer.class);
    SignatureBuilder.setSignatureBuilderForContainerType("TEST-FORMAT", TestSignatureBuilder.class);
    Container container = TestDataBuilder.createContainerWithFile(testFolder, "TEST-FORMAT");
    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureToken(testSignatureToken).
        invokeSigning();
    assertNotNull(signature);
  }

  @Test
  public void invokeSigning_whenOverridingBDocContainerFormat() throws Exception {
    TestContainer.type = BDOC_CONTAINER_TYPE;
    ContainerBuilder.setContainerImplementation(BDOC_CONTAINER_TYPE, TestContainer.class);
    SignatureBuilder.setSignatureBuilderForContainerType(BDOC_CONTAINER_TYPE, TestSignatureBuilder.class);
    Container container = TestDataBuilder.createContainerWithFile(testFolder, BDOC_CONTAINER_TYPE);
    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureToken(testSignatureToken).
        invokeSigning();
    assertNotNull(signature);
    TestContainer.resetType();
  }

  private Signature createBDocSignatureWithProfile(SignatureProfile profile) throws IOException {
    Container container = TestDataBuilder.createContainerWithFile(testFolder);
    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureToken(testSignatureToken).
        withSignatureProfile(profile).
        invokeSigning();
    container.addSignature(signature);
    return signature;
  }

  private void assertSignatureIsValid(Signature signature) {
    assertNotNull(signature.getProducedAt());
    assertEquals(SignatureProfile.LT_TM, signature.getProfile());
    assertNotNull(signature.getClaimedSigningTime());
    assertNotNull(signature.getAdESSignature());
    assertTrue(signature.getAdESSignature().length > 1);
    assertTrue(signature.validate().isEmpty());
  }
}
