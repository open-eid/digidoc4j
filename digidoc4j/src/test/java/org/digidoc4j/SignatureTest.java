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

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.simplereport.SimpleReport;
import org.apache.commons.codec.binary.Base64;
import org.custommonkey.xmlunit.XMLAssert;
import org.digidoc4j.exceptions.CertificateNotFoundException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotYetImplementedException;
import org.digidoc4j.impl.Certificates;
import org.digidoc4j.impl.asic.tsl.TSLCertificateSourceImpl;
import org.digidoc4j.impl.ddoc.ConfigManagerInitializer;
import org.digidoc4j.impl.ddoc.DDocOpener;
import org.digidoc4j.test.TestAssert;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.digidoc4j.test.util.TestTSLUtil;
import org.digidoc4j.utils.DateUtils;
import org.digidoc4j.utils.Helper;
import org.junit.Assert;
import org.junit.Test;

import java.nio.file.Paths;
import java.security.cert.CertificateEncodingException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.Month;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.matchesRegex;

public class SignatureTest extends AbstractTest {

  @Test
  public void findOcspCertificateByHashkey() {
    Container container = openContainerByConfiguration(
        Paths.get("src/test/resources/testFiles/valid-containers/OCSPRigaTest.asice"), configuration);
    Signature signature = container.getSignatures().get(0);
    X509Cert cert = signature.getOCSPCertificate();
    Assert.assertNotNull(cert);
  }

  @Test
  public void testGetSigningCertificateForBDoc() throws Exception {
    Container container = ContainerOpener.open(
        "src/test/resources/testFiles/invalid-containers/asics_for_testing.bdoc");
    byte[] certificate = container.getSignatures().get(0).getSigningCertificate().getX509Certificate().getEncoded();
    Assert.assertEquals(Certificates.SIGNING_CERTIFICATE, Base64.encodeBase64String(certificate));
  }

  @Test
  public void testTimeStampCreationTimeForBDoc() throws ParseException {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/test.asice");
    Date timeStampCreationTime = container.getSignatures().get(0).getTimeStampCreationTime();
    Date expectedDate = Date.from(OffsetDateTime.of(
        LocalDate.of(2014, Month.NOVEMBER, 17),
        LocalTime.of(16, 11, 46),
        ZoneOffset.ofHours(2)).toInstant());
    Assert.assertEquals(expectedDate, timeStampCreationTime);
  }

  @Test
  public void testTimeStampCreationTimeForBDocWhereNotOCSP() {
    Signature signature = createSignatureBy(Container.DocumentType.BDOC, SignatureProfile.B_BES,
        pkcs12SignatureToken);
    Assert.assertNull(signature.getTimeStampCreationTime());
  }

  @Test
  public void testGetTimeStampTokenCertificateForBDoc() throws Exception {
    Signature signature = ContainerOpener.open(
        "src/test/resources/testFiles/invalid-containers/ocsp_cert_is_not_in_tsl.bdoc").getSignatures().get(0);
    byte[] certificate = signature.getTimeStampTokenCertificate().getX509Certificate().getEncoded();
    Assert.assertEquals(Certificates.TS_CERTIFICATE, Base64.encodeBase64String(certificate));
  }

  @Test
  public void testGetTimeStampTokenCertificateForBDocNoTimeStampExists() {
    Signature signature = ContainerOpener.open(
        "src/test/resources/testFiles/invalid-containers/asics_for_testing.bdoc").getSignatures().get(0);
    Assert.assertNull(signature.getTimeStampTokenCertificate());
  }

  @Test(expected = CertificateNotFoundException.class)
  public void testGetSignerRolesForBDoc_OCSP_Exception() {
    Container container = ContainerOpener.open(
        "src/test/resources/testFiles/invalid-containers/ocsp_cert_is_not_in_tsl.bdoc");
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
    Signature signature = createSignatureBy(Container.DocumentType.BDOC, pkcs12SignatureToken);
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
    Container container = ContainerOpener.open(
        "src/test/resources/testFiles/invalid-containers/ocsp_cert_is_not_in_tsl.bdoc");
    Assert.assertEquals("id-99E491801522116744419D9357CEFCC5", container.getSignatures().get(0).getId());
  }

  @Test
  public void testGetNonceForDDOC() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Signature signature = container.getSignatures().get(0);
    Assert.assertEquals("UR7APOIqSmZhuX/C+sqpqXP9sog=", Base64.encodeBase64String(signature.getOCSPNonce()));
  }


  @Test(expected = DigiDoc4JException.class)
  public void testGetNonceWithNonceParseErrorForDDOC() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/ddoc_with_corrupted_ocsp_response.ddoc");
    container.getSignatures().get(0).getOCSPNonce();
  }

  @Test
  public void testGetNonceWithNoOcspResponseForDDOC() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/ddoc_with_no_ocsp_response.ddoc");
    Assert.assertNull(container.getSignatures().get(0).getOCSPNonce());
  }

  @Test
  public void testGetOCSPCertificateForDDoc() throws CertificateEncodingException {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Signature signature = container.getSignatures().get(0);
    byte[] encoded = signature.getOCSPCertificate().getX509Certificate().getEncoded();
    Assert.assertEquals(Certificates.OCSP_CERTIFICATE, Base64.encodeBase64String(encoded));
  }

  @Test
  public void testGetOCSPCertificateForExistingBDoc() throws CertificateEncodingException {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/valid-bdoc-tm-newer.bdoc");
    Signature signature = container.getSignatures().get(0);
    byte[] encoded = signature.getOCSPCertificate().getX509Certificate().getEncoded();
    Assert.assertEquals(Certificates.OCSP_CERTIFICATE_2020, Base64.encodeBase64String(encoded));
  }

  @Test
  public void testGetOCSPCertificateForNewBDoc() {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    Signature signature = createSignatureBy(Container.DocumentType.BDOC, pkcs12SignatureToken, configuration);
    assertThat(
            signature.getOCSPCertificate().getSubjectName(X509Cert.SubjectName.CN),
            matchesRegex("DEMO of ESTEID-SK 2015 AIA OCSP RESPONDER 20[1-2][0-9]")
    );
  }

  @Test
  public void testGetProducedAtForDDoc() {
    configuration = Configuration.of(Configuration.Mode.TEST);
    ConfigManagerInitializer.forceInitConfigManager(configuration);
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Signature signature = container.getSignatures().get(0);
    Assert.assertNotNull(signature.getOCSPResponseCreationTime());
  }

  @Test
  public void testGetProducedAtForBDoc() throws ParseException {
    Container container = ContainerOpener.open(
        "src/test/resources/testFiles/invalid-containers/ocsp_cert_is_not_in_tsl.bdoc");
    Date date = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z").parse("2014-07-08 12:51:16 +0000");
    Assert.assertEquals(date, container.getSignatures().get(0).getOCSPResponseCreationTime());
  }

  @Test
  public void testValidationForDDoc() {
    configuration = Configuration.of(Configuration.Mode.TEST);
    ConfigManagerInitializer.forceInitConfigManager(configuration);
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Assert.assertEquals(0, container.validate().getErrors().size());
  }

  @Test
  public void testValidationForBDocDefaultValidation() {
    configuration = new Configuration(Configuration.Mode.TEST);
    TestTSLUtil.addSkTsaCertificateToTsl(configuration);
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/two_signatures.bdoc",
        configuration);
    Signature signature = container.getSignatures().get(0);
    Assert.assertEquals(0, signature.validateSignature().getErrors().size());
    signature = container.getSignatures().get(1);
    Assert.assertEquals(0, signature.validateSignature().getErrors().size());
  }

  @Test
  public void testValidationForBDocDefaultValidationWithFailure() {
    Signature signature = ContainerOpener.open(
        "src/test/resources/testFiles/invalid-containers/ocsp_cert_is_not_in_tsl.bdoc").getSignatures().get(0);
    List<DigiDoc4JException> errors = signature.validateSignature().getErrors();
    TestAssert.assertContainsError("The reference data object is not intact!", errors);
    TestAssert.assertContainsError("Signature has an invalid timestamp", errors);
  }

  @Test
  public void testValidationForBDocDefaultValidationWithOneFailing() {
    Container container = ContainerOpener.open(
        "src/test/resources/testFiles/invalid-containers/two_signatures_one_invalid.bdoc");
    Signature signature = container.getSignatures().get(0);
    Assert.assertEquals(0, signature.validateSignature().getErrors().size());
    signature = container.getSignatures().get(1);
    Assert.assertEquals(4, signature.validateSignature().getErrors().size());
    SignatureValidationResult validate = container.validate();
    Assert.assertEquals(4, validate.getErrors().size());
    String report = validate.getReport();
    Assert.assertTrue(report.contains("SignatureFormat=\"XAdES-BASELINE-LT\" Id=\"S0\""));
    Assert.assertTrue(report.contains("SignatureFormat=\"XAdES-BASELINE-LT\" Id=\"S1\""));
    Assert.assertTrue(report.contains("<Indication>TOTAL_PASSED</Indication>"));
    Assert.assertTrue(report.contains("<Indication>INDETERMINATE</Indication>"));
  }

  @Test
  public void testValidationWithInvalidDDoc() {
    Signature signature = ContainerOpener.open(
        "src/test/resources/testFiles/invalid-containers/changed_digidoc_test.ddoc").getSignatures().get(0);
    Assert.assertEquals(4, signature.validateSignature().getErrors().size());
  }

  @Test
  public void testGetSignatureMethodDDoc() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Assert.assertEquals("http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        container.getSignatures().get(0).getSignatureMethod());
  }

  @Test
  public void testGetSignatureMethodForBDoc() {
    Container container = ContainerOpener.open(
        "src/test/resources/testFiles/invalid-containers/ocsp_cert_is_not_in_tsl.bdoc");
    Assert.assertEquals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        container.getSignatures().get(0).getSignatureMethod());
  }

  @Test
  public void testGetProfileForDDoc() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Assert.assertEquals(SignatureProfile.LT_TM, container.getSignatures().get(0).getProfile());
  }

  @Test
  public void testGetProfileForBDoc_TS() {
    Container container = ContainerOpener.open(
        "src/test/resources/testFiles/invalid-containers/ocsp_cert_is_not_in_tsl.bdoc");
    Assert.assertEquals(SignatureProfile.LT, container.getSignatures().get(0).getProfile());
  }

  @Test
  public void testGetProfileForBDoc_None() {
    Container container = ContainerOpener.open(
        "src/test/resources/testFiles/invalid-containers/asics_for_testing.bdoc");
    Assert.assertEquals(SignatureProfile.B_BES, container.getSignatures().get(0).getProfile());
  }

  @Test(expected = NotYetImplementedException.class)
  public void testGetTimeStampTokenCertificateForDDoc() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    container.getSignatures().get(0).getTimeStampTokenCertificate();
  }

  @Test
  public void testGetNonceForBDoc() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc");
    String nonce = Base64.encodeBase64String(container.getSignatures().get(0).getOCSPNonce());
    Assert.assertEquals("MDEwDQYJYIZIAWUDBAIBBQAEIGYrFuVObKYFoA8P22TxZ8knTH4dLASQ2hEG5ejvV1gK", nonce);
  }

  @Test
  public void testGetNonceForAsiceWithoutNonce() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/LT_without_nonce.asice");
    Assert.assertNull(container.getSignatures().get(0).getOCSPNonce());
  }

  @Test
  public void testGetSignaturesWhereNoSignaturePresent() {
    Container container = new DDocOpener().open(
        "src/test/resources/testFiles/invalid-containers/empty_container_no_signature.ddoc");
    Assert.assertTrue(container.getSignatures().isEmpty());
  }

  @Test
  public void testGetSignaturesWhereSignatureDoesNotHaveLastCertificate() {
    Container container = new DDocOpener().open(
        "src/test/resources/testFiles/invalid-containers/signature_without_last_certificate.ddoc");
    Assert.assertEquals(0, container.getSignatures().size());
  }

  @Test
  public void getSignatureXMLForBDOC() throws Exception {
    Container container = createNonEmptyContainer();
    Signature signature = createSignatureBy(container, pkcs12SignatureToken);
    container.saveAsFile("getSignatureXMLForBDOC.bdoc");
    String signatureFromContainer = Helper.extractSignature("getSignatureXMLForBDOC.bdoc", 0);
    Helper.deleteFile("getSignatureXMLForBDOC.bdoc");
    XMLAssert.assertXMLEqual(signatureFromContainer, new String(signature.getAdESSignature()));
  }

  @Test
  public void signature_withoutProductionPlace_shouldNotThrowException() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    assertProductionPlaceIsNull(container.getSignatures().get(0));
  }

  @Test
  public void bDocBESSignature_TrustedSigningTime_shouldReturnNull() {
    Signature signature = createSignatureBy(Container.DocumentType.BDOC, SignatureProfile.B_BES,
        pkcs12SignatureToken);
    Assert.assertNull(signature.getTrustedSigningTime());
  }

  @Test
  public void dDocBESSignature_TrustedSigningTime_shouldReturnNull() {
    Container container = ContainerOpener.open(
        "src/test/resources/testFiles/invalid-containers/B_BES-signature-profile.ddoc");
    Assert.assertNull(container.getSignatures().get(0).getTrustedSigningTime());
  }

  @Test
  public void bDocTimeMarkSignature_TrustedSigningTime_shouldReturnOCSPResponseCreationTime() {
    configuration = Configuration.of(Configuration.Mode.TEST);
    ConfigManagerInitializer.forceInitConfigManager(configuration);
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc");
    Signature signature = container.getSignatures().get(0);
    Assert.assertNotNull(signature.getTrustedSigningTime());
    Assert.assertEquals(signature.getOCSPResponseCreationTime(), signature.getTrustedSigningTime());
  }

  @Test
  public void dDocTimeMarkSignature_TrustedSigningTime_shouldReturnOCSPResponseCreationTime() {
    configuration = Configuration.of(Configuration.Mode.TEST);
    ConfigManagerInitializer.forceInitConfigManager(configuration);
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Signature signature = container.getSignatures().get(0);
    Assert.assertNotNull(signature.getTrustedSigningTime());
    Assert.assertEquals(signature.getOCSPResponseCreationTime(), signature.getTrustedSigningTime());
  }

  @Test
  public void bDocTimeStampSignature_TrustedSigningTime_shouldReturnTimeStampCreationTime() {
    Signature signature = createSignatureBy(Container.DocumentType.BDOC, SignatureProfile.LT,
        pkcs12SignatureToken);
    Assert.assertNotNull(signature.getTrustedSigningTime());
    Assert.assertEquals(signature.getTimeStampCreationTime(), signature.getTrustedSigningTime());
  }

  @Test
  public void bDocLTASignature_TrustedSigningTime_shouldReturnTimeStampCreationTime() {
    Signature signature = createSignatureBy(Container.DocumentType.BDOC, SignatureProfile.LTA,
        pkcs12SignatureToken);
    Assert.assertNotNull(signature.getTrustedSigningTime());
    Assert.assertEquals(signature.getTimeStampCreationTime(), signature.getTrustedSigningTime());
  }

  @Test
  public void getSignatureSigningCertificateDetails() {
    Container container = TestDataBuilderUtil.open("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc");
    Signature signature = container.getSignatures().get(0);
    X509Cert cert = signature.getSigningCertificate();
    Assert.assertEquals("11404176865", cert.getSubjectName(X509Cert.SubjectName.SERIALNUMBER));
    Assert.assertEquals("märü-lööz", cert.getSubjectName(X509Cert.SubjectName.GIVENNAME).toLowerCase());
    Assert.assertEquals("žõrinüwšky", cert.getSubjectName(X509Cert.SubjectName.SURNAME).toLowerCase());
  }

  @Test
  public void gettingOcspCertificate_whenTslIsNotLoaded() {
    configuration = new Configuration(Configuration.Mode.TEST);
    TSLCertificateSource certificateSource = new TSLCertificateSourceImpl();
    configuration.setTSL(certificateSource);
    Container container = ContainerBuilder.aContainer().withConfiguration(configuration).
        fromExistingFile("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc").build();
    Signature signature = container.getSignatures().get(0);
    Assert.assertNotNull(signature.getOCSPCertificate());
  }

  @Test
  public void certificateContainsNotSupportedTssQcQualifier() {
    configuration = new Configuration(Configuration.Mode.PROD);
    Container container = openContainerByConfiguration(
        Paths.get("src/test/resources/prodFiles/invalid-containers/edoc2_lv-eId_sha256.edoc"),
        configuration);
    Assert.assertFalse(container.validate().isValid());
  }

  @Test
  public void signatureReportForTwoSignature() {
    configuration = new Configuration(Configuration.Mode.PROD);
    Container container = openContainerByConfiguration(
        Paths.get("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc"),
        configuration);
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
  public void signatureReportForOneSignature() {
    configuration = new Configuration(Configuration.Mode.TEST);
    Container container = openContainerByConfiguration(
        Paths.get("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc"), configuration);
    SignatureValidationResult result = container.validate();
    for (SimpleReport signatureSimpleReport : result.getSimpleReports()) {
      for (String id : signatureSimpleReport.getSignatureIdList()) {
        //"id-6a5d6671af7a9e0ab9a5e4d49d69800d"
        Assert.assertEquals(Indication.TOTAL_PASSED, result.getIndication(id));
        Assert.assertNull(result.getSubIndication(id));
        Assert.assertEquals(SignatureQualification.QESIG.getLabel(), result.getSignatureQualification(id).getLabel());
      }
    }
    Assert.assertEquals(Indication.TOTAL_PASSED, result.getIndication(null));
    Assert.assertNull(result.getSubIndication(null));
    Assert.assertEquals(SignatureQualification.QESIG.getLabel(), result.getSignatureQualification(null).getLabel());
  }

  @Test
  public void signatureReportNoSignature() {
    configuration = new Configuration(Configuration.Mode.TEST);
    Container container = openContainerByConfiguration(
        Paths.get("src/test/resources/testFiles/valid-containers/container_without_signatures.bdoc"),
        configuration);
    SignatureValidationResult result = container.validate();
    Assert.assertNull(result.getIndication("S0"));
    Assert.assertNull(result.getSubIndication("S0"));
    Assert.assertNull(result.getSignatureQualification("S0"));
    Assert.assertNull(result.getIndication(null));
    Assert.assertNull(result.getSubIndication(null));
    Assert.assertNull(result.getSignatureQualification(null));
  }

  @Test
  public void signatureReportOnlyOneSignatureValid() {
    configuration = new Configuration(Configuration.Mode.TEST);
    Container container = openContainerByConfiguration(
        Paths.get("src/test/resources/testFiles/invalid-containers/two_signatures_one_invalid.bdoc"),
        configuration);
    SignatureValidationResult result = container.validate();
    //Signature with id "S1" is invalid
    Assert.assertEquals(Indication.INDETERMINATE, result.getIndication("S1"));
    Assert.assertEquals(SubIndication.NO_SIGNING_CERTIFICATE_FOUND, result.getSubIndication("S1"));
    Assert.assertEquals(SignatureQualification.INDETERMINATE_QESIG.getLabel(), result.getSignatureQualification("S1").getLabel());
    //Signature with id "S0" is valid
    Assert.assertEquals(Indication.TOTAL_PASSED, result.getIndication(null));
    Assert.assertNull(result.getSubIndication(null));
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
