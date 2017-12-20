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

import static org.digidoc4j.SignatureProfile.LT;
import static org.digidoc4j.testutils.TestDataBuilder.createContainerWithFile;
import static org.digidoc4j.testutils.TestDataBuilder.createEmptyBDocContainer;
import static org.digidoc4j.testutils.TestDataBuilder.open;
import static org.digidoc4j.testutils.TestDataBuilder.signContainer;
import static org.digidoc4j.testutils.TestHelpers.containsErrorMessage;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.DataToSign;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.TSLCertificateSource;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.DuplicateDataFileException;
import org.digidoc4j.exceptions.InvalidTimestampException;
import org.digidoc4j.exceptions.TimestampAfterOCSPResponseTimeException;
import org.digidoc4j.exceptions.UnsupportedFormatException;
import org.digidoc4j.exceptions.UntrustedRevocationSourceException;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.digidoc4j.impl.asic.tsl.TSLCertificateSourceImpl;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.digidoc4j.testutils.TSLHelper;
import org.digidoc4j.testutils.TestSigningHelper;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import eu.europa.esig.dss.DSSUtils;

public class ValidationTests extends DigiDoc4JTestHelper {

  public static final Configuration PROD_CONFIGURATION = new Configuration(Configuration.Mode.PROD);
  public static final Configuration TEST_CONFIGURATION = new Configuration(Configuration.Mode.TEST);
  public static final Configuration PROD_CONFIGURATION_WITH_TEST_POLICY = new Configuration(Configuration.Mode.PROD);
  String testContainerPath;

  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();

  @Before
  public void setUp() throws Exception {
    testContainerPath = testFolder.newFile("container.bdoc").getPath();
  }

  @BeforeClass
  public static void setUpOnce() throws Exception {
    PROD_CONFIGURATION_WITH_TEST_POLICY.setValidationPolicy("conf/test_constraint.xml");
  }

  @Test
  public void testVerifySignedDocument() throws Exception {
    Container container = createSignedBDocDocument(testContainerPath);
    ValidationResult result = container.validate();
    assertTrue(result.isValid());
  }

  @Test
  public void testTestVerifyOnInvalidDocument() throws Exception {
    Container container = open("src/test/resources/testFiles/invalid-containers/invalid_container.bdoc");
    assertFalse(container.validate().isValid());
  }

  @Test
  public void testValidateEmptyDocument() {
    Container container = createEmptyBDocContainer();
    ValidationResult result = container.validate();
    assertTrue(result.isValid());
  }

  @Test
  public void testValidate() throws Exception {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    signContainer(container);
    ValidationResult validationResult = container.validate();
    assertEquals(0, validationResult.getErrors().size());
  }

  @Test(expected = UnsupportedFormatException.class)
  public void notBDocThrowsException() {
    open("src/test/resources/testFiles/invalid-containers/notABDoc.bdoc");
  }

  @Test(expected = UnsupportedFormatException.class)
  public void incorrectMimetypeThrowsException() {
    open("src/test/resources/testFiles/invalid-containers/incorrectMimetype.bdoc");
  }

  @Ignore("Unable to test if OCSP responds with unknown, because the signing certificate is expired")
  @Test(expected = Exception.class)
  public void testOCSPUnknown() {
    try {
      testSigningWithOCSPCheck("src/test/resources/testFiles/p12/20167000013.p12");
    } catch (Exception e) {
      assertTrue(e.getMessage().contains("UNKNOWN"));
      throw e;
    }
  }

  @Test(expected = Exception.class)
  public void testExpiredCertSign() {
    try {
      testSigningWithOCSPCheck("src/test/resources/testFiles/p12/expired_signer.p12");
    } catch (Exception e) {
      assertTrue(e.getMessage().contains("not in certificate validity range"));
      throw e;
    }
  }

  @Test
  public void signatureFileContainsIncorrectFileName() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/filename_mismatch_signature.asice", PROD_CONFIGURATION);
    ValidationResult validate = container.validate();
    List<DigiDoc4JException> errors = validate.getErrors();
    assertEquals(1, errors.size());
    assertContainsError("(Signature ID: S0) The reference data object(s) is not found!", errors);
  }

  @Test
  public void validateContainer_withChangedDataFileContent_isInvalid() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/invalid-data-file.bdoc");
    ValidationResult validate = container.validate();
    assertEquals(1, validate.getErrors().size());
    assertEquals("(Signature ID: S0) The reference data object(s) is not intact!", validate.getErrors().get(0).toString());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void secondSignatureFileContainsIncorrectFileName() throws IOException, CertificateException {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    TSLHelper.addSkTsaCertificateToTsl(configuration);
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/filename_mismatch_second_signature.asice", configuration);
    ValidationResult validate = container.validate();
    List<DigiDoc4JException> errors = validate.getErrors();
    assertEquals(3, errors.size());
    assertEquals("(Signature ID: S1) The reference data object(s) is not intact!", errors.get(0).toString());
    assertEquals("(Signature ID: S1) Manifest file has an entry for file test.txt with mimetype text/plain but the signature file for " +
        "signature S1 does not have an entry for this file", errors.get(1).toString());
    assertEquals("Container contains a file named test.txt which is not found in the signature file",
        errors.get(2).toString());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void manifestFileContainsIncorrectFileName() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/filename_mismatch_manifest.asice", PROD_CONFIGURATION_WITH_TEST_POLICY);
    ValidationResult validate = container.validate();
    assertEquals(2, validate.getErrors().size());
    assertEquals("(Signature ID: S0) Manifest file has an entry for file incorrect.txt with mimetype text/plain but the signature file " +
        "for signature S0 does not have an entry for this file", validate.getErrors().get(0).toString());
    assertEquals("(Signature ID: S0) The signature file for signature S0 has an entry for file RELEASE-NOTES.txt with mimetype " +
            "text/plain but the manifest file does not have an entry for this file",
        validate.getErrors().get(1).toString());
  }

  @Test
  public void container_withChangedDataFileName_shouldBeInvalid() throws Exception {
    Container container = open("src/test/resources/testFiles/invalid-containers/bdoc-tm-with-changed-data-file-name.bdoc");
    ValidationResult validate = container.validate();
    assertEquals(1, validate.getErrors().size());
  }

  @Test
  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  public void revocationAndTimeStampDifferenceTooLarge() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/revocation_timestamp_delta_26h.asice", PROD_CONFIGURATION);
    ValidationResult validate = container.validate();
    assertEquals(1, validate.getErrors().size());
    assertEquals("(Signature ID: S0) The difference between the OCSP response time and the signature time stamp is too large",
        validate.getErrors().get(0).toString());
  }

  @Test
  public void revocationAndTimeStampDifferenceNotTooLarge() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    int delta27Hours = 27 * 60;
    configuration.setRevocationAndTimestampDeltaInMinutes(delta27Hours);
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/revocation_timestamp_delta_26h.asice", configuration);
    ValidationResult validate = container.validate();
    assertEquals(0, validate.getErrors().size());
  }

  @Test
  public void signatureFileAndManifestFileContainDifferentMimeTypeForFile() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/mimetype_mismatch.asice", PROD_CONFIGURATION_WITH_TEST_POLICY);
    ValidationResult validate = container.validate();
    assertEquals(1, validate.getErrors().size());
    assertEquals("(Signature ID: S0) Manifest file has an entry for file RELEASE-NOTES.txt with mimetype application/pdf but the " +
        "signature file for signature S0 indicates the mimetype is text/plain", validate.getErrors().get(0).toString());
  }

  @Test(expected = DuplicateDataFileException.class)
  public void duplicateFileThrowsException() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/22902_data_files_with_same_names.bdoc");
    container.validate();
  }

  @Test(expected = DigiDoc4JException.class)
  public void duplicateSignatureFileThrowsException() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/22913_signatures_xml_double.bdoc");
    container.validate();
  }

  @Test
  public void missingManifestFile() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/missing_manifest.asice", PROD_CONFIGURATION);
    ValidationResult result = container.validate();
    assertFalse(result.isValid());
    assertEquals("Unsupported format: Container does not contain a manifest file", result.getErrors().get(0).getMessage());
  }

  @Test(expected = DigiDoc4JException.class)
  public void missingMimeTypeFile() {
    ContainerOpener.open("src/test/resources/testFiles/invalid-containers/missing_mimetype_file.asice");
  }

  @Test
  public void containerHasFileWhichIsNotInManifestAndNotInSignatureFile() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/extra_file_in_container.asice", PROD_CONFIGURATION_WITH_TEST_POLICY);
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(1, errors.size());
    assertEquals("Container contains a file named AdditionalFile.txt which is not found in the signature file",
        errors.get(0).getMessage());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void containerMissesFileWhichIsInManifestAndSignatureFile() {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    TSLHelper.addSkTsaCertificateToTsl(configuration);
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/zip_misses_file_which_is_in_manifest.asice");
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertContainsError("(Signature ID: S0) The reference data object(s) is not found!", errors);
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void containerMissingOCSPData() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/TS-06_23634_TS_missing_OCSP_adjusted.asice");
    ValidationResult validate = container.validate();
    System.out.println(validate.getReport());
    List<DigiDoc4JException> errors = validate.getErrors();

    assertEquals(LT, container.getSignatures().get(0).getProfile());
    assertContainsError("(Signature ID: S0) No revocation data for the certificate", errors);
    assertContainsError("(Signature ID: S0) Manifest file has an entry for file test.txt with mimetype text/plain but the signature file for signature S0 indicates the mimetype is application/octet-stream", errors);
  }

  @Ignore("This signature has two OCSP responses: one correct and one is technically corrupted. Opening a container should not throw an exception")
  @Test(expected = DigiDoc4JException.class)
  public void corruptedOCSPDataThrowsException() {
    ContainerOpener.open("src/test/resources/testFiles/invalid-containers/corrupted_ocsp_data.asice");
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void invalidNoncePolicyOid() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/23608_bdoc21-invalid-nonce-policy-oid.bdoc", PROD_CONFIGURATION);
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(1, errors.size());
    assertEquals("(Signature ID: S0) Wrong policy identifier: 1.3.6.1.4.1.10015.1000.3.4.3", errors.get(0).toString());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void badNonceContent() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/bdoc21-bad-nonce-content.bdoc", PROD_CONFIGURATION_WITH_TEST_POLICY);
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(1, errors.size());
    assertEquals("(Signature ID: S0) Nonce is invalid", errors.get(0).toString());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void noSignedPropRefTM() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/REF-03_bdoc21-TM-no-signedpropref.bdoc", PROD_CONFIGURATION_WITH_TEST_POLICY);
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(2, errors.size());
    assertContainsError("(Signature ID: S0) Signed properties missing", errors);
    assertContainsError("(Signature ID: S0) The reference data object(s) is not found!", errors);
    assertEquals(2, container.getSignatures().get(0).validateSignature().getErrors().size());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void noSignedPropRefTS() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/REF-03_bdoc21-TS-no-signedpropref.asice", PROD_CONFIGURATION_WITH_TEST_POLICY);
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(2, errors.size());
    assertContainsError("(Signature ID: S0) Signed properties missing", errors);
    assertContainsError("(Signature ID: S0) The reference data object(s) is not found!", errors);
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void multipleSignedProperties() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/multiple_signed_properties.asice");
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    containsErrorMessage(errors, "Multiple signed properties");
    containsErrorMessage(errors, "The signature is not intact!");
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void incorrectSignedPropertiesReference() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/signed_properties_reference_not_found.asice", PROD_CONFIGURATION_WITH_TEST_POLICY);
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(1, errors.size());
    assertEquals("(Signature ID: S0) The reference data object(s) is not found!", errors.get(0).toString());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void nonceIncorrectContent() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/nonce-vale-sisu.bdoc", PROD_CONFIGURATION_WITH_TEST_POLICY);
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(3, errors.size());
    assertEquals("(Signature ID: S0) Wrong policy identifier: 1.3.6.1.4.1.10015.1000.2.10.10", errors.get(0).toString());
    assertEquals("(Signature ID: S0) The signature policy is not available!", errors.get(1).toString());
    assertEquals("(Signature ID: S0) Nonce is invalid", errors.get(2).toString());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void badNoncePolicyOidQualifier() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/SP-03_bdoc21-bad-nonce-policy-oidasuri.bdoc", PROD_CONFIGURATION_WITH_TEST_POLICY);
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(1, errors.size());
    assertEquals("(Signature ID: S0) Wrong policy identifier qualifier: OIDAsURI", errors.get(0).toString());
    assertEquals(1, container.getSignatures().get(0).validateSignature().getErrors().size());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void invalidNonce() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/23200_weakdigest-wrong-nonce.asice");
    ValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(1, errors.size());
    assertEquals("(Signature ID: S0) Nonce is invalid", errors.get(0).toString());
  }

  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  @Test
  public void brokenTS() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/TS_broken_TS.asice");
    ValidationResult result = container.validate();

    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(1, errors.size());
    assertEquals("(Signature ID: S0) "+InvalidTimestampException.MESSAGE, errors.get(0).toString());
  }

  @Test
  public void asicValidationShouldFail_ifTimeStampHashDoesntMatchSignature() throws Exception {
    ValidationResult result = validateContainer("src/test/resources/testFiles/invalid-containers/TS-02_23634_TS_wrong_SignatureValue.asice");
    assertFalse(result.isValid());
    assertTrue(containsErrorMessage(result.getErrors(), InvalidTimestampException.MESSAGE));
  }

  @Ignore("This test is not usable anymore")
  @Test
  public void asicOcspTimeShouldBeAfterTimestamp() throws Exception {
    ValidationResult result = validateContainer("src/test/resources/testFiles/invalid-containers/TS-08_23634_TS_OCSP_before_TS.asice");
    assertFalse(result.isValid());
    assertTrue(result.getErrors().size() >= 1);
    assertTrue(containsErrorMessage(result.getErrors(), TimestampAfterOCSPResponseTimeException.MESSAGE));
  }

  @Test
  public void containerWithTMProfile_SignedWithExpiredCertificate_shouldBeInvalid() throws Exception {
    assertFalse(validateContainer("src/test/resources/testFiles/invalid-containers/invalid_bdoc_tm_old-sig-sigat-NOK-prodat-NOK.bdoc").isValid());
    assertFalse(validateContainer("src/test/resources/testFiles/invalid-containers/invalid_bdoc_tm_old-sig-sigat-OK-prodat-NOK.bdoc").isValid());
  }

  @Test
  public void containerWithTSProfile_SignedWithExpiredCertificate_shouldBeInvalid() throws Exception {
    ValidationResult result = validateContainer("src/test/resources/testFiles/invalid-containers/invalid_bdoc21-TS-old-cert.bdoc");
    assertFalse(result.isValid());
  }

  @Test
  public void bdocTM_signedWithValidCert_isExpiredByNow_shouldBeValid() throws Exception {
    String containerPath = "src/test/resources/testFiles/valid-containers/valid_bdoc_tm_signed_with_valid_cert_expired_by_now.bdoc";
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    TSLHelper.addCertificateFromFileToTsl(configuration, "src/test/resources/testFiles/certs/ESTEID-SK_2007_prod.pem.crt");
    Container container = ContainerBuilder.
        aContainer("BDOC").
        fromExistingFile(containerPath).
        withConfiguration(configuration).
        build();
    ValidationResult result = container.validate();
    assertTrue(result.isValid());
  }

  @Test
  public void signaturesWithCrlShouldBeInvalid() throws Exception {
    ValidationResult validationResult = validateContainer("src/test/resources/testFiles/invalid-containers/asic-with-crl-and-without-ocsp.asice", PROD_CONFIGURATION);
    assertFalse(validationResult.isValid());
    assertTrue(validationResult.getErrors().get(0) instanceof UntrustedRevocationSourceException);
  }

  @Test
  public void bDoc_withoutOcspResponse_shouldBeInvalid() throws Exception {
    assertFalse(validateContainer("src/test/resources/testFiles/invalid-containers/23608-bdoc21-no-ocsp.bdoc", PROD_CONFIGURATION).isValid());
  }

  @Test
  public void ocspResponseShouldNotBeTakenFromPreviouslyValidatedSignatures_whenOcspResponseIsMissing() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    assertFalse(validateContainer("src/test/resources/testFiles/invalid-containers/bdoc-tm-ocsp-revoked.bdoc", configuration).isValid());
    assertTrue(validateContainer("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc", configuration).isValid());
    assertFalse(validateContainer("src/test/resources/testFiles/invalid-containers/invalid-bdoc-tm-missing-revoked-ocsp.bdoc", configuration).isValid());
  }

  @Test
  public void validateContainerWithBomSymbolsInMimeType_shouldBeValid() throws Exception {
    assertTrue(validateContainer("src/test/resources/prodFiles/valid-containers/IB-4185_bdoc21_TM_mimetype_with_BOM_PROD.bdoc", PROD_CONFIGURATION).isValid());
  }

  @Test
  public void havingOnlyCaCertificateInTSL_shouldNotValidateOCSPResponse() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    TSLCertificateSourceImpl tsl = new TSLCertificateSourceImpl();
    configuration.setTSL(tsl);
    InputStream inputStream = getClass().getResourceAsStream("/certs/TEST ESTEID-SK 2011.crt");
    X509Certificate caCertificate = DSSUtils.loadCertificate(inputStream).getCertificate();
    tsl.addTSLCertificate(caCertificate);
    ValidationResult result = validateContainer("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc", configuration);
    assertFalse(result.isValid());
    assertTrue(containsErrorMessage(result.getErrors(), "The certificate chain for revocation data is not trusted, there is no trusted anchor."));
  }

  @Test
  public void mixTSLCertAndTSLOnlineSources_SignatureTypeLT_valid() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    PKCS12SignatureToken signatureToken = new PKCS12SignatureToken("src/test/resources/testFiles/p12/user_one.p12", "user_one".toCharArray());

    InputStream inputStream  = new FileInputStream("src/test/resources/testFiles/certs/exampleCA.cer");
    X509Certificate certificate = DSSUtils.loadCertificate(inputStream).getCertificate();
    configuration.getTSL().addTSLCertificate(certificate);

    inputStream  = new FileInputStream("src/test/resources/testFiles/certs/SK-OCSP-RESPONDER-2011_test.cer");
    certificate = DSSUtils.loadCertificate(inputStream).getCertificate();
    configuration.getTSL().addTSLCertificate(certificate);

    Container container = createSignedBDocDocumentWithConf(configuration, signatureToken);

    ValidationResult validationResult = container.validate();

    assertTrue(validationResult.isValid());
    assertEquals(0, validationResult.getErrors().size());

  }

  @Test
  public void mixTSLCertAndTSLOnlineSources_SignatureTypeLT_notValid() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    PKCS12SignatureToken signatureToken = new PKCS12SignatureToken("src/test/resources/testFiles/p12/user_one.p12", "user_one".toCharArray());

    TSLCertificateSource certificateSource = new TSLCertificateSourceImpl();

    InputStream inputStream  = new FileInputStream("src/test/resources/testFiles/certs/exampleCA.cer");
    X509Certificate certificate = DSSUtils.loadCertificate(inputStream).getCertificate();
    certificateSource.addTSLCertificate(certificate);

    inputStream  = new FileInputStream("src/test/resources/testFiles/certs/SK-OCSP-RESPONDER-2011_test.cer");
    certificate = DSSUtils.loadCertificate(inputStream).getCertificate();
    certificateSource.addTSLCertificate(certificate);

    configuration.setTSL(certificateSource);

    Container container = createSignedBDocDocumentWithConf(configuration, signatureToken);
    ValidationResult validationResult = container.validate();
    List<DigiDoc4JException> errors = validationResult.getErrors();

    List<Signature> signatureList = container.getSignatures();
    Signature signature = signatureList.get(0);
    String signatureId = signature.getId();

    assertFalse(validationResult.isValid());
    assertEquals(1, errors.size());
    assertEquals("(Signature ID: "+signatureId+") Signature has an invalid timestamp", errors.get(0).toString());
  }

  @Test
  public void validateAsiceContainer_getNotValid() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    assertFalse(validateContainer("src/test/resources/testFiles/invalid-containers/TM-16_unknown.4.asice", configuration).isValid());
  }


  @Test
  public void validateSpuriElement_UriIsvalid() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc", TEST_CONFIGURATION);
    ValidationResult result = container.validate();
    assertTrue(result.isValid());
  }

  @Test
  public void validateSpuriElement_UriIsMissing() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/23608_bdoc21-no-nonce-policy.bdoc", TEST_CONFIGURATION);
    ValidationResult result = container.validate();
    assertFalse(result.isValid());
    assertTrue(containsErrorMessage(result.getErrors(), "Error: The URL in signature policy is empty or not available"));

  }

  @Test
  public void validateSpuriElement_UriIsEmpty() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/SP-06_bdoc21-no-uri.bdoc", TEST_CONFIGURATION);
    ValidationResult result = container.validate();
    assertFalse(result.isValid());
    assertTrue(containsErrorMessage(result.getErrors(), "Error: The URL in signature policy is empty or not available"));
  }

  private void testSigningWithOCSPCheck(String unknownCert) {
    Container container = createEmptyBDocContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    X509Certificate signerCert = TestSigningHelper.getSigningCert(unknownCert, "test");
    DataToSign dataToSign = SignatureBuilder.
        aSignature(container).
        withSigningCertificate(signerCert).
        buildDataToSign();
    byte[] signature = TestSigningHelper.sign(dataToSign.getDataToSign(), dataToSign.getDigestAlgorithm());
    dataToSign.finalize(signature);
  }

  private void assertContainsError(String errorMsg, List<DigiDoc4JException> errors) {
    for (DigiDoc4JException e : errors) {
      if (StringUtils.equalsIgnoreCase(errorMsg, e.toString())) {
        return;
      }
    }
    assertFalse("Expected '" + errorMsg + "' was not found", true);
  }

  private Container createSignedBDocDocument(String fileName) {
    Container container = createContainerWithFile("src/test/resources/testFiles/helper-files/test.txt");
    signContainer(container);
    container.saveAsFile(fileName);
    return container;
  }

  private ValidationResult validateContainer(String containerPath) {
    Container container = openContainerBuilder(containerPath).
        build();
    return container.validate();
  }

  private ValidationResult validateContainer(String containerPath, Configuration configuration) {
    Container container = openContainerBuilder(containerPath).
        withConfiguration(configuration).
        build();
    return container.validate();
  }

  private ContainerBuilder openContainerBuilder(String containerPath) {
    return ContainerBuilder.
        aContainer("BDOC").
        fromExistingFile(containerPath);
  }

  private Container createSignedBDocDocumentWithConf(Configuration configuration, PKCS12SignatureToken signatureToken) {
    Container container = ContainerBuilder.
        aContainer().
        withDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/xml").
        withConfiguration(configuration).
        build();

    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureProfile(SignatureProfile.LT).
        withSignatureToken(signatureToken).
        invokeSigning();

    container.addSignature(signature);
    container.saveAsFile(testContainerPath);

    return container;
  }
}
