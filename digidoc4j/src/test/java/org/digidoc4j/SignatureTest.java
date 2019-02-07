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

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.validation.SignatureQualification;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;
import org.apache.commons.codec.binary.Base64;
import org.custommonkey.xmlunit.XMLAssert;
import org.digidoc4j.exceptions.CertificateNotFoundException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotYetImplementedException;
import org.digidoc4j.impl.Certificates;
import org.digidoc4j.impl.asic.SKCommonCertificateVerifier;
import org.digidoc4j.impl.asic.tsl.TSLCertificateSourceImpl;
import org.digidoc4j.impl.asic.tsl.TslManager;
import org.digidoc4j.impl.ddoc.ConfigManagerInitializer;
import org.digidoc4j.impl.ddoc.DDocOpener;
import org.digidoc4j.test.TestAssert;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.digidoc4j.test.util.TestTSLUtil;
import org.digidoc4j.utils.DateUtils;
import org.digidoc4j.utils.Helper;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Paths;
import java.security.cert.CertificateEncodingException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class SignatureTest extends AbstractTest {

  @Test
  public void findOcspCertificateByHashkey() throws Exception {
    Container container = this.openContainerByConfiguration(Paths.get("src/test/resources/testFiles/valid-containers/OCSPRigaTest.asice"), this.configuration);
    Signature signature = container.getSignatures().get(0);
    X509Cert cert = signature.getOCSPCertificate();
    Assert.assertNotNull(cert);
  }

  @Test
  public void testGetSigningCertificateForBDoc() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/asics_for_testing.bdoc");
    byte[] certificate = container.getSignatures().get(0).getSigningCertificate().getX509Certificate().getEncoded();
    Assert.assertEquals(Certificates.SIGNING_CERTIFICATE, Base64.encodeBase64String(certificate));
  }

  @Test
  public void testTimeStampCreationTimeForBDoc() throws ParseException {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/test.asice");
    Date timeStampCreationTime = container.getSignature(0).getTimeStampCreationTime();
    SimpleDateFormat dateFormat = new SimpleDateFormat("MMM d yyyy H:m:s", Locale.ENGLISH);
    Assert.assertEquals(dateFormat.parse("Nov 17 2014 16:11:46"), timeStampCreationTime);
  }

  @Test(expected = DigiDoc4JException.class)
  public void testTimeStampCreationTimeForDDoc() throws ParseException {
    Container container = this.createEmptyContainerBy(Container.DocumentType.DDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    container.sign(this.pkcs12SignatureToken);
    container.getSignature(0).getTimeStampCreationTime();
    container.getSignature(0).getTimeStampCreationTime();
  }

  @Test
  public void testTimeStampCreationTimeForBDocWhereNotOCSP() throws ParseException, IOException {
    Signature signature = this.createSignatureBy(Container.DocumentType.BDOC, SignatureProfile.B_BES, this.pkcs12SignatureToken);
    Assert.assertNull(signature.getTimeStampCreationTime());
  }

  @Test
  public void testGetTimeStampTokenCertificateForBDoc() throws Exception {
    Signature signature = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/ocsp_cert_is_not_in_tsl.bdoc").getSignatures().get(0);
    byte[] certificate = signature.getTimeStampTokenCertificate().getX509Certificate().getEncoded();
    Assert.assertEquals(Certificates.TS_CERTIFICATE, Base64.encodeBase64String(certificate));
  }

  @Test
  public void testGetTimeStampTokenCertificateForBDocNoTimeStampExists() throws Exception {
    Signature signature = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/asics_for_testing.bdoc").getSignatures().get(0);
    Assert.assertNull(signature.getTimeStampTokenCertificate());
  }

  @Test(expected = CertificateNotFoundException.class)
  public void testGetSignerRolesForBDoc_OCSP_Exception() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/ocsp_cert_is_not_in_tsl.bdoc");
    List<Signature> signatures = container.getSignatures();
    Assert.assertNull(signatures.get(0).getOCSPCertificate());
  }

  @Test
  public void testGetSigningTimeForDDOC() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Signature signature = container.getSignatures().get(0);
    Assert.assertNotNull(signature.getClaimedSigningTime());
  }

  @Test
  public void testGetSigningTimeForBDoc() {
    Signature signature = this.createSignatureBy(Container.DocumentType.BDOC, this.pkcs12SignatureToken);
    Assert.assertTrue(DateUtils.isAlmostNow(signature.getClaimedSigningTime()));
  }

  @Test
  public void testGetIdForDDOC() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Signature signature = container.getSignatures().get(0);
    Assert.assertEquals("S0", signature.getId());
  }

  @Test
  public void testGetIdForBDoc() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/ocsp_cert_is_not_in_tsl.bdoc");
    Assert.assertEquals("id-99E491801522116744419D9357CEFCC5", container.getSignatures().get(0).getId());
  }

  @Test
  public void testGetNonce() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Signature signature = container.getSignatures().get(0);
    Assert.assertEquals(null, Base64.encodeBase64String(signature.getOCSPNonce())); //todo correct nonce is needed
  }

  @Test
  public void testGetOCSPCertificateForDDoc() throws CertificateEncodingException {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Signature signature = container.getSignatures().get(0);
    byte[] encoded = signature.getOCSPCertificate().getX509Certificate().getEncoded();
    Assert.assertEquals(Certificates.OCSP_CERTIFICATE, Base64.encodeBase64String(encoded));
  }

  @Test
  public void testGetOCSPCertificateForBDoc() throws CertificateEncodingException {
    Signature signature = this.createSignatureBy(Container.DocumentType.BDOC, this.pkcs12SignatureToken);
    byte[] encoded = signature.getOCSPCertificate().getX509Certificate().getEncoded();
    Assert.assertEquals(Certificates.OCSP_CERTIFICATE, Base64.encodeBase64String(encoded));
  }

  @Test
  public void testGetSignaturePolicyForDDoc() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Assert.assertEquals("", container.getSignatures().get(0).getPolicy());
  }

  @Test(expected = NotYetImplementedException.class)
  public void testGetSignaturePolicyForBDoc() throws Exception {
    Signature signature = this.createSignatureBy(Container.DocumentType.BDOC, this.pkcs12SignatureToken);
    Assert.assertEquals("", signature.getPolicy());
  }

  @Test
  public void testGetProducedAtForDDoc() {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Signature signature = container.getSignatures().get(0);
    Assert.assertNotNull(signature.getProducedAt());
  }

  @Test
  public void testGetProducedAtForBDoc() throws ParseException {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/ocsp_cert_is_not_in_tsl.bdoc");
    Date date = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z").parse("2014-07-08 12:51:16 +0000");
    Assert.assertEquals(date, container.getSignatures().get(0).getProducedAt());
  }

  @Test
  public void testValidationForDDoc() {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Assert.assertEquals(0, container.validate().getErrors().size());
  }

  @Test
  public void testValidationForBDocDefaultValidation() throws Exception {
    this.configuration = new Configuration(Configuration.Mode.TEST);
    TestTSLUtil.addSkTsaCertificateToTsl(this.configuration);
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/two_signatures.bdoc", this.configuration);
    Signature signature = container.getSignatures().get(0);
    Assert.assertEquals(0, signature.validateSignature().getErrors().size());
    signature = container.getSignatures().get(1);
    Assert.assertEquals(0, signature.validateSignature().getErrors().size());
  }

  @Test
  public void testValidationForBDocDefaultValidationWithFailure() throws Exception {
    Signature signature = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/ocsp_cert_is_not_in_tsl.bdoc").getSignatures().get(0);
    List<DigiDoc4JException> errors = signature.validateSignature().getErrors();
    TestAssert.assertContainsError("The reference data object is not intact!", errors);
    TestAssert.assertContainsError("Signature has an invalid timestamp", errors);
  }

  @Test
  public void testValidationForBDocDefaultValidationWithOneFailing() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/two_signatures_one_invalid.bdoc");
    Signature signature = container.getSignatures().get(0);
    Assert.assertEquals(0, signature.validateSignature().getErrors().size());
    signature = container.getSignatures().get(1);
    Assert.assertEquals(1, signature.validateSignature().getErrors().size());
    SignatureValidationResult validate = container.validate();
    Assert.assertEquals(1, validate.getErrors().size());
    String report = validate.getReport();
    Assert.assertTrue(report.contains("Id=\"S0\" SignatureFormat=\"XAdES-BASELINE-LT\""));
    Assert.assertTrue(report.contains("Id=\"S1\" SignatureFormat=\"XAdES-BASELINE-LT\""));
    Assert.assertTrue(report.contains("<Indication>TOTAL_PASSED</Indication>"));
    Assert.assertTrue(report.contains("<Indication>INDETERMINATE</Indication>"));
  }

  @Test
  public void testValidationWithInvalidDDoc() {
    Signature signature = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/changed_digidoc_test.ddoc").getSignatures().get(0);
    Assert.assertEquals(4, signature.validateSignature().getErrors().size());
  }

  @Test
  public void testGetSignaturePolicyURIForDDoc() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Assert.assertNull(container.getSignatures().get(0).getSignaturePolicyURI());
  }

  @Test(expected = NotYetImplementedException.class)
  public void testGetSignaturePolicyURIForBDoc() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/ocsp_cert_is_not_in_tsl.bdoc");
    Assert.assertEquals(new URI(""), container.getSignatures().get(0).getSignaturePolicyURI());
  }

  @Test
  public void testGetSignatureMethodDDoc() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Assert.assertEquals("http://www.w3.org/2000/09/xmldsig#rsa-sha1", container.getSignatures().get(0).getSignatureMethod());
  }

  @Test
  public void testGetSignatureMethodForBDoc() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/ocsp_cert_is_not_in_tsl.bdoc");
    Assert.assertEquals("http://www.w3.org/2001/04/xmlenc#sha256",
        container.getSignatures().get(0).getSignatureMethod());
  }

  @Test
  public void testGetProfileForDDoc() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Assert.assertEquals(SignatureProfile.LT_TM, container.getSignatures().get(0).getProfile());
  }

  @Test
  public void testGetProfileForBDoc_TS() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/ocsp_cert_is_not_in_tsl.bdoc");
    Assert.assertEquals(SignatureProfile.LT, container.getSignatures().get(0).getProfile());
  }

  @Test
  public void testGetProfileForBDoc_None() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/asics_for_testing.bdoc");
    Assert.assertEquals(SignatureProfile.B_BES, container.getSignatures().get(0).getProfile());
  }

  @Test(expected = NotYetImplementedException.class)
  public void testGetTimeStampTokenCertificateForDDoc() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    container.getSignatures().get(0).getTimeStampTokenCertificate();
  }

  @Test(expected = NotYetImplementedException.class)
  public void testGetNonceForBDoc() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/asics_for_testing.bdoc");
    container.getSignatures().get(0).getOCSPNonce();
  }

  @Test
  public void testGetSignaturesWhereNoSignaturePresent() throws Exception {
    Container container = new DDocOpener().open("src/test/resources/testFiles/invalid-containers/empty_container_no_signature.ddoc");
    Assert.assertTrue(container.getSignatures().isEmpty());
  }

  @Test
  public void testGetSignaturesWhereSignatureDoesNotHaveLastCertificate() throws Exception {
    Container container = new DDocOpener().open("src/test/resources/testFiles/invalid-containers/signature_without_last_certificate.ddoc");
    Assert.assertEquals(0, container.getSignatures().size());
  }

  @Test
  public void getSignatureXMLForBDOC() throws Exception {
    Container container = this.createNonEmptyContainer();
    Signature signature = this.createSignatureBy(container, this.pkcs12SignatureToken);
    container.saveAsFile("getSignatureXMLForBDOC.bdoc");
    String signatureFromContainer = Helper.extractSignature("getSignatureXMLForBDOC.bdoc", 0);
    Helper.deleteFile("getSignatureXMLForBDOC.bdoc");
    XMLAssert.assertXMLEqual(signatureFromContainer, new String(signature.getAdESSignature()));
  }

  @Test
  public void signature_withoutProductionPlace_shouldNotThrowException() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    this.assertProductionPlaceIsNull(container.getSignatures().get(0));
  }

  @Test
  public void bDocBESSignature_TrustedSigningTime_shouldReturnNull() throws Exception {
    Signature signature = this.createSignatureBy(Container.DocumentType.BDOC, SignatureProfile.B_BES, this.pkcs12SignatureToken);
    Assert.assertNull(signature.getTrustedSigningTime());
  }

  @Test
  public void dDocBESSignature_TrustedSigningTime_shouldReturnNull() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/B_BES-signature-profile.ddoc");
    Assert.assertNull(container.getSignatures().get(0).getTrustedSigningTime());
  }

  @Test
  public void bDocTimeMarkSignature_TrustedSigningTime_shouldReturnOCSPResponseCreationTime() throws Exception {
    Signature signature = this.createSignatureBy(Container.DocumentType.BDOC, SignatureProfile.LT_TM, this.pkcs12SignatureToken);
    Assert.assertNotNull(signature.getTrustedSigningTime());
    Assert.assertEquals(signature.getOCSPResponseCreationTime(), signature.getTrustedSigningTime());
  }

  @Test
  public void dDocTimeMarkSignature_TrustedSigningTime_shouldReturnOCSPResponseCreationTime() throws Exception {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Signature signature = container.getSignatures().get(0);
    Assert.assertNotNull(signature.getTrustedSigningTime());
    Assert.assertEquals(signature.getOCSPResponseCreationTime(), signature.getTrustedSigningTime());
  }

  @Test
  public void bDocTimeStampSignature_TrustedSigningTime_shouldReturnTimeStampCreationTime() throws Exception {
    Signature signature = this.createSignatureBy(Container.DocumentType.BDOC, SignatureProfile.LT, this.pkcs12SignatureToken);
    Assert.assertNotNull(signature.getTrustedSigningTime());
    Assert.assertEquals(signature.getTimeStampCreationTime(), signature.getTrustedSigningTime());
  }

  @Test
  public void bDocLTASignature_TrustedSigningTime_shouldReturnTimeStampCreationTime() throws Exception {
    Signature signature = this.createSignatureBy(Container.DocumentType.BDOC, SignatureProfile.LTA, this.pkcs12SignatureToken);
    Assert.assertNotNull(signature.getTrustedSigningTime());
    Assert.assertEquals(signature.getTimeStampCreationTime(), signature.getTrustedSigningTime());
  }

  @Test
  public void getSignatureSigningCertificateDetails() throws Exception {
    Container container = TestDataBuilderUtil.open("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc");
    Signature signature = container.getSignatures().get(0);
    X509Cert cert = signature.getSigningCertificate();
    Assert.assertEquals("11404176865", cert.getSubjectName(X509Cert.SubjectName.SERIALNUMBER));
    Assert.assertEquals("märü-lööz", cert.getSubjectName(X509Cert.SubjectName.GIVENNAME).toLowerCase());
    Assert.assertEquals("žõrinüwšky", cert.getSubjectName(X509Cert.SubjectName.SURNAME).toLowerCase());
  }

  @Test
  public void gettingOcspCertificate_whenTslIsNotLoaded() throws Exception {
    this.configuration = new Configuration(Configuration.Mode.TEST);
    TSLCertificateSource certificateSource = new TSLCertificateSourceImpl();
    this.configuration.setTSL(certificateSource);
    Container container = ContainerBuilder.aContainer().withConfiguration(this.configuration).
        fromExistingFile("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc").build();
    Signature signature = container.getSignatures().get(0);
    Assert.assertNotNull(signature.getOCSPCertificate());
  }

  @Test
  public void checkCertificateSSCDSupport() {
    this.configuration = new Configuration(Configuration.Mode.PROD);
    TslManager tslManager = new TslManager(this.configuration);
    TSLCertificateSource certificateSource = tslManager.getTsl();
    this.configuration.setTSL(certificateSource);
    DSSDocument document = new FileDocument("src/test/resources/prodFiles/valid-containers/valid_edoc2_lv-eId_sha256.edoc");
    SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
    SKCommonCertificateVerifier verifier = new SKCommonCertificateVerifier();
    OCSPSource ocspSource = OCSPSourceBuilder.anOcspSource().withConfiguration(this.configuration).build();
    verifier.setOcspSource(ocspSource);
    verifier.setTrustedCertSource(this.configuration.getTSL());
    verifier.setDataLoader(new CommonsDataLoader());
    validator.setCertificateVerifier(verifier);
    Reports reports = validator.validateDocument();
    boolean isValid = true;
    for (String signatureId : reports.getSimpleReport().getSignatureIdList()) {
      isValid = isValid && reports.getSimpleReport().isSignatureValid(signatureId);
    }
    Assert.assertTrue(isValid);
  }

  @Test
  public void signatureReportForTwoSignature() throws Exception {
    this.configuration = new Configuration(Configuration.Mode.PROD);
    Container container = this.openContainerByConfiguration(Paths.get("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc"), this.configuration);
    SignatureValidationResult result = container.validate();
    Assert.assertEquals(Indication.INDETERMINATE, result.getIndication("S0"));
    Assert.assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, result.getSubIndication("S0"));
    Assert.assertEquals(SignatureQualification.NA.getLabel(), result.getSignatureQualification("S0").getLabel());
    Assert.assertEquals(Indication.INDETERMINATE, result.getIndication("S1"));
    Assert.assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, result.getSubIndication("S1"));
    Assert.assertEquals(SignatureQualification.NA.getLabel(), result.getSignatureQualification("S1").getLabel());
    Assert.assertEquals(Indication.INDETERMINATE, result.getIndication(null));
    Assert.assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, result.getSubIndication(null));
    Assert.assertEquals(SignatureQualification.NA.getLabel(), result.getSignatureQualification(null).getLabel());
  }

  @Test
  public void signatureReportForOneSignature() throws Exception {
    this.configuration = new Configuration(Configuration.Mode.TEST);
    Container container = this.openContainerByConfiguration(Paths.get("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc"), this.configuration);
    SignatureValidationResult result = container.validate();
    for (SimpleReport signatureSimpleReport : result.getSimpleReports()) {
      for (String id : signatureSimpleReport.getSignatureIdList()) {
        //"id-6a5d6671af7a9e0ab9a5e4d49d69800d"
        Assert.assertEquals(Indication.TOTAL_PASSED, result.getIndication(id));
        Assert.assertEquals(null, result.getSubIndication(id));
        Assert.assertEquals(SignatureQualification.QESIG.getLabel(), result.getSignatureQualification(id).getLabel());
      }
    }
    Assert.assertEquals(Indication.TOTAL_PASSED, result.getIndication(null));
    Assert.assertEquals(null, result.getSubIndication(null));
    Assert.assertEquals(SignatureQualification.QESIG.getLabel(), result.getSignatureQualification(null).getLabel());
  }

  @Test
  public void signatureReportNoSignature() throws Exception {
    this.configuration = new Configuration(Configuration.Mode.TEST);
    Container container = this.openContainerByConfiguration(Paths.get("src/test/resources/testFiles/valid-containers/container_without_signatures.bdoc"), this.configuration);
    SignatureValidationResult result = container.validate();
    Assert.assertEquals(null, result.getIndication("S0"));
    Assert.assertEquals(null, result.getSubIndication("S0"));
    Assert.assertEquals(null, result.getSignatureQualification("S0"));
    Assert.assertEquals(null, result.getIndication(null));
    Assert.assertEquals(null, result.getSubIndication(null));
    Assert.assertEquals(null, result.getSignatureQualification(null));
  }

  @Test
  public void signatureReportOnlyOneSignatureValid() throws Exception {
    this.configuration = new Configuration(Configuration.Mode.TEST);
    Container container = this.openContainerByConfiguration(Paths.get("src/test/resources/testFiles/invalid-containers/two_signatures_one_invalid.bdoc"), this.configuration);
    SignatureValidationResult result = container.validate();
    //Signature with id "S1" is invalid
    Assert.assertEquals(Indication.INDETERMINATE, result.getIndication("S1"));
    Assert.assertEquals(SubIndication.NO_SIGNING_CERTIFICATE_FOUND, result.getSubIndication("S1"));
    Assert.assertEquals(SignatureQualification.NA.getLabel(), result.getSignatureQualification("S1").getLabel());
    //Signature with id "S0" is valid
    Assert.assertEquals(Indication.TOTAL_PASSED, result.getIndication(null));
    Assert.assertEquals(null, result.getSubIndication(null));
    Assert.assertEquals(SignatureQualification.QESIG.getLabel(), result.getSignatureQualification(null).getLabel());
  }

  /*
   * RESTRICTED METHODS
   */

  private void assertProductionPlaceIsNull(Signature signature) {
    Assert.assertEquals("", signature.getCity());
    Assert.assertEquals("", signature.getCountryName());
    Assert.assertEquals("", signature.getPostalCode());
    Assert.assertEquals("", signature.getStateOrProvince());
  }

}
