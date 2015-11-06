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

import static org.custommonkey.xmlunit.XMLAssert.assertXMLEqual;
import static org.digidoc4j.Container.DocumentType.BDOC;
import static org.digidoc4j.Container.DocumentType.DDOC;
import static org.digidoc4j.ContainerBuilder.BDOC_CONTAINER_TYPE;
import static org.digidoc4j.ContainerBuilder.DDOC_CONTAINER_TYPE;
import static org.digidoc4j.utils.DateUtils.isAlmostNow;
import static org.digidoc4j.utils.Helper.deleteFile;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.security.cert.CertificateEncodingException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import org.apache.commons.codec.binary.Base64;
import org.digidoc4j.exceptions.CertificateNotFoundException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotYetImplementedException;
import org.digidoc4j.impl.bdoc.AsicFacade;
import org.digidoc4j.impl.Certificates;
import org.digidoc4j.impl.ddoc.DDocFacade;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.digidoc4j.impl.ddoc.DDocOpener;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.digidoc4j.testutils.TSLHelper;
import org.digidoc4j.testutils.TestDataBuilder;
import org.digidoc4j.utils.Helper;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class SignatureTest extends DigiDoc4JTestHelper {

  private PKCS12SignatureToken PKCS12_SIGNER;

  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();

  @Before
  public void setUp() throws Exception {
    PKCS12_SIGNER = new PKCS12SignatureToken("testFiles/signout.p12", "test".toCharArray());
  }

  @Test
  public void testGetSigningCertificateForBDoc() throws Exception {
    Container container = ContainerOpener.open("testFiles/asics_for_testing.bdoc");
    byte[] certificate = container.getSignatures().get(0).getSigningCertificate().getX509Certificate().getEncoded();
    assertEquals(Certificates.SIGNING_CERTIFICATE, Base64.encodeBase64String(certificate));
  }

  @Test
  public void testTimeStampCreationTimeForBDoc() throws ParseException {
    Container container = ContainerOpener.open("testFiles/test.asice");
    Date timeStampCreationTime = container.getSignature(0).getTimeStampCreationTime();
    SimpleDateFormat dateFormat = new SimpleDateFormat("MMM d yyyy H:m:s", Locale.ENGLISH);
    assertEquals(dateFormat.parse("Nov 17 2014 16:11:46"), timeStampCreationTime);
  }

  @Test(expected = DigiDoc4JException.class)
  public void testTimeStampCreationTimeForDDoc() throws ParseException {
    Container container = createDDoc();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.getSignature(0).getTimeStampCreationTime();
    container.getSignature(0).getTimeStampCreationTime();
  }

  @Test
  public void testTimeStampCreationTimeForBDocWhereNotOCSP() throws ParseException {
    AsicFacade container = new AsicFacade();
    container.setSignatureProfile(SignatureProfile.B_BES);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);

    assertNull(container.getSignature(0).getTimeStampCreationTime());
  }

  @Test
  public void testGetTimeStampTokenCertificateForBDoc() throws Exception {
    Signature signature = ContainerOpener.open("testFiles/ocsp_cert_is_not_in_tsl.bdoc").getSignatures().get(0);
    byte[] certificate = signature.getTimeStampTokenCertificate().getX509Certificate().getEncoded();
    assertEquals(Certificates.TS_CERTIFICATE, Base64.encodeBase64String(certificate));
  }

  @Test(expected = CertificateNotFoundException.class)
  public void testGetTimeStampTokenCertificateForBDocNoTimeStampExists() throws Exception {
    ContainerOpener.open("testFiles/asics_for_testing.bdoc").getSignatures().get(0).getTimeStampTokenCertificate();
  }

  @Test(expected = CertificateNotFoundException.class)
  public void testGetSignerRolesForBDoc_OCSP_Exception() {
    Container container = ContainerOpener.open("testFiles/ocsp_cert_is_not_in_tsl.bdoc");
    List<Signature> signatures = container.getSignatures();
    signatures.get(0).getOCSPCertificate();
  }

  @Test
  public void testGetSigningTimeForDDOC() {
    testGetSigningTime(DDOC);
  }

  @Test
  public void testGetSigningTimeForBDoc() {
    testGetSigningTime(BDOC);
  }

  private void testGetSigningTime(Container.DocumentType ddoc) {
    Signature signature = getSignature(ddoc);
    assertTrue(isAlmostNow(signature.getClaimedSigningTime()));
  }

  @Test
  public void testGetIdForDDOC() {
    Signature signature = getSignature(DDOC);
    assertEquals("S0", signature.getId());
  }

  @Test
  public void testGetIdForBDoc() {
    Container container = ContainerOpener.open("testFiles/ocsp_cert_is_not_in_tsl.bdoc");
    assertEquals("id-99E491801522116744419D9357CEFCC5", container.getSignatures().get(0).getId());
  }

  @Test
  public void testGetNonce() {
    Signature signature = getSignature(DDOC);
    assertEquals(null, Base64.encodeBase64String(signature.getOCSPNonce())); //todo correct nonce is needed
  }

  @Test
  public void testGetOCSPCertificateForDDoc() throws CertificateEncodingException {
    testGetOCSPCertificate(getSignature(DDOC));
  }

  @Test
  public void testGetOCSPCertificateForBDoc() throws CertificateEncodingException {
    testGetOCSPCertificate(getSignature(BDOC));
  }

  private void testGetOCSPCertificate(Signature signature) throws CertificateEncodingException {
    byte[] encoded = signature.getOCSPCertificate().getX509Certificate().getEncoded();
    assertEquals(Certificates.OCSP_CERTIFICATE, Base64.encodeBase64String(encoded));
  }

  @Test
  public void testGetSignaturePolicyForDDoc() {
    assertEquals("", getSignature(DDOC).getPolicy());
  }

  @Test(expected = NotYetImplementedException.class)
  public void testGetSignaturePolicyForBDoc() throws Exception {
    Signature signature = getSignature(BDOC);
    assertEquals("", signature.getPolicy());
  }

  @Test
  public void testGetProducedAtForDDoc() {
    assertTrue(isAlmostNow(getSignature(DDOC).getProducedAt()));
  }

  @Test
  public void testGetProducedAtForBDoc() throws ParseException {
    Container container = ContainerOpener.open("testFiles/ocsp_cert_is_not_in_tsl.bdoc");
    Date date = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z").parse("2014-07-08 12:51:16 +0000");
    assertEquals(date, container.getSignatures().get(0).getProducedAt());
  }

  @Test
  public void testValidationForDDoc() {
    assertEquals(0, getSignature(DDOC).validate().size());
  }

  @Test
  public void testValidationNoParametersForDDoc() {
    assertEquals(0, getSignature(DDOC).validate().size());
  }

  @Test
  public void testValidationForBDocDefaultValidation() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    TSLHelper.addSkTsaCertificateToTsl(configuration);
    Container container = ContainerOpener.open("testFiles/two_signatures.bdoc", configuration);
    Signature signature = container.getSignatures().get(0);
    assertEquals(0, signature.validate().size());
    signature = container.getSignatures().get(1);
    assertEquals(0, signature.validate().size());
  }

  @Test
  public void testValidationForBDocDefaultValidationWithFailure() throws Exception {
    Signature signature = ContainerOpener.open("testFiles/ocsp_cert_is_not_in_tsl.bdoc").getSignatures().get(0);
    assertEquals(2, signature.validate().size());
  }

  @Test
  public void testValidationForBDocDefaultValidationWithOneFailing() throws Exception {
    Container container = ContainerOpener.open("testFiles/two_signatures_one_invalid.bdoc");
    Signature signature = container.getSignatures().get(0);
    assertEquals(0, signature.validate().size());
    signature = container.getSignatures().get(1);
    assertEquals(1, signature.validate().size());
    ValidationResult validate = container.validate();
    assertEquals(1, validate.getErrors().size());

    assertTrue(validate.getReport().contains("Id=\"S0\" SignatureFormat=\"XAdES_BASELINE_LT\""));
    assertTrue(validate.getReport().contains("Id=\"S1\" SignatureFormat=\"XAdES_BASELINE_LT\""));
  }

  @Test
  public void testValidationWithInvalidDDoc() {
    Signature signature = ContainerOpener.open("testFiles/changed_digidoc_test.ddoc").getSignatures().get(0);
    assertEquals(4, signature.validate().size());
  }

  @Test
  public void testGetSignaturePolicyURIForDDoc() {
    assertNull(getSignature(DDOC).getSignaturePolicyURI());
  }

  @Test(expected = NotYetImplementedException.class)
  public void testGetSignaturePolicyURIForBDoc() throws Exception {
    Container container = ContainerOpener.open("testFiles/ocsp_cert_is_not_in_tsl.bdoc");
    assertEquals(new URI(""), container.getSignatures().get(0).getSignaturePolicyURI());
  }

  @Test
  public void testGetSignatureMethodDDoc() {
    assertEquals("http://www.w3.org/2000/09/xmldsig#rsa-sha1", getSignature(DDOC).getSignatureMethod());
  }

  @Test
  public void testGetSignatureMethodForBDoc() {
    Container container = ContainerOpener.open("testFiles/ocsp_cert_is_not_in_tsl.bdoc");
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha256",
        container.getSignatures().get(0).getSignatureMethod());
  }

  @Test
  public void testGetProfileForDDoc() {
    assertEquals(SignatureProfile.LT_TM, getSignature(DDOC).getProfile());
  }

  @Test
  public void testGetProfileForBDoc_TS() throws Exception {
    Container container = ContainerOpener.open("testFiles/ocsp_cert_is_not_in_tsl.bdoc");
    assertEquals(SignatureProfile.LT, container.getSignatures().get(0).getProfile());
  }

  @Test
  public void testGetProfileForBDoc_None() throws Exception {
    Container container = ContainerOpener.open("testFiles/asics_for_testing.bdoc");
    assertEquals(SignatureProfile.B_BES, container.getSignatures().get(0).getProfile());
  }

  @Test(expected = NotYetImplementedException.class)
  public void testGetTimeStampTokenCertificateForDDoc() {
    assertNull(getSignature(DDOC).getTimeStampTokenCertificate());
  }

  @Test(expected = NotYetImplementedException.class)
  public void testGetNonceForBDoc() {
    Container container = ContainerOpener.open("testFiles/asics_for_testing.bdoc");
    container.getSignatures().get(0).getOCSPNonce();
  }

  @Test
  public void testGetSignaturesWhereNoSignaturePresent() throws Exception {
    DDocFacade container = new DDocFacade();
    assertTrue(container.getSignatures().isEmpty());
  }

  @Test
  public void testGetSignaturesWhereSignatureDoesNotHaveLastCertificate() throws Exception {
    Container container = new DDocOpener().open("testFiles/signature_without_last_certificate.ddoc");
    assertEquals(0, container.getSignatures().size());
  }

  @Test
  public void getSignatureXMLForBDOC() throws Exception {
    Container container = ContainerBuilder.
        aContainer().
        withDataFile("testFiles/test.txt", "text/plain").
        build();

    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureToken(PKCS12_SIGNER).
        invokeSigning();
    container.addSignature(signature);

    container.saveAsFile("getSignatureXMLForBDOC.bdoc");
    String signatureFromContainer = Helper.extractSignature("getSignatureXMLForBDOC.bdoc", 0);


    deleteFile("getSignatureXMLForBDOC.bdoc");

    assertXMLEqual(signatureFromContainer, new String(signature.getAdESSignature()));
  }

  @Test
  public void signature_withoutProductionPlace_shouldNotThrowException() throws Exception {
    Container bdocContainer = TestDataBuilder.createContainerWithFile(testFolder, BDOC_CONTAINER_TYPE);
    Container ddocContainer = TestDataBuilder.createContainerWithFile(testFolder, DDOC_CONTAINER_TYPE);
    verifySignatureWithoutProductionPlaceDoesntThrow(bdocContainer);
    verifySignatureWithoutProductionPlaceDoesntThrow(ddocContainer);
  }

  @Test
  public void bDocBESSignature_TrustedSigningTime_shouldReturnNull() throws Exception {
    Signature signature = createSignatureFor(BDOC_CONTAINER_TYPE, SignatureProfile.B_BES);
    assertNull(signature.getTrustedSigningTime());
  }

  @Test
  public void dDocBESSignature_TrustedSigningTime_shouldReturnNull() throws Exception {
    Signature signature = createSignatureFor(DDOC_CONTAINER_TYPE, SignatureProfile.B_BES);
    assertNull(signature.getTrustedSigningTime());
  }

  @Test
  public void bDocTimeMarkSignature_TrustedSigningTime_shouldReturnOCSPResponseCreationTime() throws Exception {
    Signature signature = createSignatureFor(BDOC_CONTAINER_TYPE, SignatureProfile.LT_TM);
    assertNotNull(signature.getTrustedSigningTime());
    assertEquals(signature.getOCSPResponseCreationTime(), signature.getTrustedSigningTime());
  }

  @Test
  public void dDocTimeMarkSignature_TrustedSigningTime_shouldReturnOCSPResponseCreationTime() throws Exception {
    Signature signature = createSignatureFor(DDOC_CONTAINER_TYPE, SignatureProfile.LT_TM);
    assertNotNull(signature.getTrustedSigningTime());
    assertEquals(signature.getOCSPResponseCreationTime(), signature.getTrustedSigningTime());
  }

  @Test
  public void bDocTimeStampSignature_TrustedSigningTime_shouldReturnTimeStampCreationTime() throws Exception {
    Signature signature = createSignatureFor(BDOC_CONTAINER_TYPE, SignatureProfile.LT);
    assertNotNull(signature.getTrustedSigningTime());
    assertEquals(signature.getTimeStampCreationTime(), signature.getTrustedSigningTime());
  }

  @Test
  public void bDocLTASignature_TrustedSigningTime_shouldReturnTimeStampCreationTime() throws Exception {
    Signature signature = createSignatureFor(BDOC_CONTAINER_TYPE, SignatureProfile.LTA);
    assertNotNull(signature.getTrustedSigningTime());
    assertEquals(signature.getTimeStampCreationTime(), signature.getTrustedSigningTime());
  }

  private Signature getSignature(Container.DocumentType documentType) {
    Container container = ContainerBuilder.
        aContainer(documentType.name()).
        withConfiguration(new Configuration(Configuration.Mode.TEST)).
        withDataFile("testFiles/test.txt", "text/plain").
        build();

    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureToken(PKCS12_SIGNER).
        invokeSigning();
    container.addSignature(signature);

    return signature;
  }

  private Container createDDoc() {
    return ContainerBuilder.
        aContainer(DDOC_CONTAINER_TYPE).
        build();
  }

  private void verifySignatureWithoutProductionPlaceDoesntThrow(Container container) {
    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureToken(PKCS12_SIGNER).
        invokeSigning();
    assertProductionPlaceIsNull(signature);
  }

  private void assertProductionPlaceIsNull(Signature signature) {
    assertNull(signature.getCity());
    assertNull(signature.getCountryName());
    assertNull(signature.getPostalCode());
    assertNull(signature.getStateOrProvince());
  }

  private Signature createSignatureFor(String containerType, SignatureProfile signatureProfile) throws IOException {
    Container container = TestDataBuilder.createContainerWithFile(testFolder, containerType);
    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureToken(PKCS12_SIGNER).
        withSignatureProfile(signatureProfile).
        invokeSigning();
    return signature;
  }
}
