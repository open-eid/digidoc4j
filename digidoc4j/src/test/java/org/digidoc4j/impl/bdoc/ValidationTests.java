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

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.process.MessageTag;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.DataToSign;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.TSLCertificateSource;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.DuplicateDataFileException;
import org.digidoc4j.exceptions.InvalidTimestampException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.exceptions.UnsupportedFormatException;
import org.digidoc4j.exceptions.UntrustedRevocationSourceException;
import org.digidoc4j.impl.asic.tsl.TSLCertificateSourceImpl;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.digidoc4j.test.TestAssert;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.digidoc4j.test.util.TestIdUtil;
import org.digidoc4j.test.util.TestSigningUtil;
import org.digidoc4j.test.util.TestTSLUtil;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

public class ValidationTests extends AbstractTest {

  public static final Configuration PROD_CONFIGURATION = new Configuration(Configuration.Mode.PROD);
  public static final Configuration PROD_CONFIGURATION_WITH_TEST_POLICY = new Configuration(Configuration.Mode.PROD);

  @BeforeClass
  public static void setUpOnce() throws Exception {
    PROD_CONFIGURATION_WITH_TEST_POLICY.setValidationPolicy("conf/test_constraint.xml");
  }

  @Test
  public void validateProdBDocContainer_isValid() {
    Container container = ContainerBuilder.aContainer().
        fromExistingFile("src/test/resources/prodFiles/valid-containers/Baltic MoU digital signing_EST_LT_LV.bdoc").
        withConfiguration(Configuration.of(Configuration.Mode.PROD)).build();
    TestAssert.assertContainerIsValid(container);
  }

  @Test
  public void testUnknownOcspContainer() {
    Container container = this.openContainerBy(
        Paths.get("src/test/resources/testFiles/invalid-containers/unknown_ocsp.asice"));
    TestAssert.assertContainerIsInvalid(container);
  }

  @Test
  public void testVerifySignedDocument() throws Exception {
    Container container = this.createNonEmptyContainer();
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void testTestVerifyOnInvalidDocument() throws Exception {
    Container container = TestDataBuilderUtil.
        open("src/test/resources/testFiles/invalid-containers/invalid_container.bdoc");
    Assert.assertFalse(container.validate().isValid());
  }

  @Test
  public void testValidateEmptyDocument() {
    TestAssert.assertContainerIsValid(this.createEmptyContainerBy(Container.DocumentType.BDOC, Container.class));
  }

  @Test
  public void testValidate() throws Exception {
    Container container = this.createNonEmptyContainer();
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    Assert.assertEquals(0, container.validate().getErrors().size());
  }

  @Test(expected = UnsupportedFormatException.class)
  public void notBDocThrowsException() {
    TestDataBuilderUtil.open("src/test/resources/testFiles/invalid-containers/notABDoc.bdoc");
  }

  @Test(expected = UnsupportedFormatException.class)
  public void incorrectMimetypeThrowsException() {
    TestDataBuilderUtil.open("src/test/resources/testFiles/invalid-containers/incorrectMimetype.bdoc");
  }

  @Test(expected = Exception.class)
  public void testExpiredCertSign() {
    try {
      DataToSign dataToSign = SignatureBuilder
          .aSignature(this.createNonEmptyContainer())
          .withSigningCertificate(TestSigningUtil.getSigningCertificate(
              "src/test/resources/testFiles/p12/expired_signer.p12", "test"))
          .buildDataToSign();
      dataToSign.finalize(TestSigningUtil.sign(dataToSign.getDataToSign(), dataToSign.getDigestAlgorithm()));
    } catch (Exception e) {
      Assert.assertTrue(e.getMessage().contains("not in certificate validity range"));
      throw e;
    }
  }

  @Test
  public void signatureFileContainsIncorrectFileName() {
    Container container = ContainerOpener
        .open("src/test/resources/prodFiles/invalid-containers/filename_mismatch_signature.asice", PROD_CONFIGURATION);
    String signatureId = TestIdUtil.findExactlyOneSignatureByXmlDigitalSignatureId(container, "S0").getId();
    SignatureValidationResult validate = container.validate();
    List<DigiDoc4JException> errors = validate.getErrors();
    Assert.assertEquals(4, errors.size());
    TestAssert.assertContainsError("(Signature ID: " + signatureId + ") - The signature file for signature " + signatureId +
            " has an entry for file <0123456789~#%&()=`@{[]}'.txt> with mimetype <application/pdf> but the manifest file does not have an entry for this file", errors);
  }

  @Test
  public void containerFileContainsExtraFile() {
    Container container = ContainerOpener
        .open("src/test/resources/testFiles/invalid-containers/KS-18_lisatudfail.4.asice",
            this.configuration);
    SignatureValidationResult validate = container.validate();
    List<DigiDoc4JException> errors = validate.getErrors();
    Assert.assertEquals(1, errors.size());
    TestAssert.assertContainsError(
        "Container contains a file named <test1.txt> which is not found in the signature file", errors);
  }

  @Test
  public void containerFileAndManifestContainsExtraFile() {
    Container container = ContainerOpener
        .open("src/test/resources/testFiles/invalid-containers/KS-18_lisatudfilemanifest.4.asice", this.configuration);
    String signatureId = TestIdUtil.findExactlyOneSignatureByXmlDigitalSignatureId(container, "S0").getId();
    SignatureValidationResult validate = container.validate();
    List<DigiDoc4JException> errors = validate.getErrors();
    Assert.assertEquals(2, errors.size());
    TestAssert.assertContainsError(
        "(Signature ID: " + signatureId + ") - Manifest file has an entry for file <test1.txt> with mimetype "
            + "<application/octet-stream> but the signature file for signature " + signatureId + " does not have an entry for this "
            + "file", errors);
    TestAssert.assertContainsError(
        "Container contains a file named <test1.txt> which is not found in the signature file", errors);
  }

  @Test
  public void validateContainer_withChangedDataFileContent_isInvalid() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/invalid-data-file.bdoc");
    String signatureId = TestIdUtil.findExactlyOneSignatureByXmlDigitalSignatureId(container, "S0").getId();
    SignatureValidationResult validate = container.validate();
    Assert.assertEquals(1, validate.getErrors().size());
    Assert.assertEquals("(Signature ID: " + signatureId + ") - The result of the LTV validation process is not acceptable to continue the process!",
        validate.getErrors().get(0).toString());
  }

  @Test
  public void secondSignatureFileContainsIncorrectFileName() throws IOException, CertificateException {
    TestTSLUtil.addSkTsaCertificateToTsl(this.configuration);
    Container container = ContainerOpener.open(
        "src/test/resources/testFiles/invalid-containers/filename_mismatch_second_signature.asice",
        this.configuration);
    String signatureId = TestIdUtil.findExactlyOneSignatureByXmlDigitalSignatureId(container, "S1").getId();
    SignatureValidationResult validate = container.validate();
    List<DigiDoc4JException> errors = validate.getErrors();
    Assert.assertEquals(3, errors.size());
    Assert.assertEquals("(Signature ID: " + signatureId + ") - The result of the LTV validation process is not acceptable to continue the process!",
        errors.get(0).toString());
    Assert.assertEquals(
        "(Signature ID: " + signatureId + ") - Manifest file has an entry for file <test.txt> with mimetype <text/plain> but "
            + "the signature file for signature " + signatureId + " does not have an entry for this file",
        errors.get(1).toString());
    Assert.assertEquals("Container contains a file named <test.txt> which is not found in the signature file",
        errors.get(2).toString());
  }

  @Test
  public void manifestFileContainsIncorrectFileName() {
    Container container = ContainerOpener
        .open("src/test/resources/prodFiles/invalid-containers/filename_mismatch_manifest.asice", PROD_CONFIGURATION_WITH_TEST_POLICY);
    String signatureId = TestIdUtil.findExactlyOneSignatureByXmlDigitalSignatureId(container, "S0").getId();
    SignatureValidationResult validate = container.validate();
    Assert.assertEquals(2, validate.getErrors().size());
    Assert.assertEquals(
        "(Signature ID: " + signatureId + ") - Manifest file has an entry for file <incorrect.txt> with mimetype <text/plain> but "
            + "the signature file for signature " + signatureId + " does not have an entry for this file",
        validate.getErrors().get(0).toString());
    Assert.assertEquals(
        "(Signature ID: " + signatureId + ") - The signature file for signature " + signatureId + " has an entry for file <RELEASE-NOTES.txt> "
            + "with mimetype <text/plain> but the manifest file does not have an entry for this file",
        validate.getErrors().get(1).toString());
  }

  @Test
  public void container_withChangedDataFileName_shouldBeInvalid() throws Exception {
    Container container = ContainerOpener
        .open("src/test/resources/testFiles/invalid-containers/bdoc-tm-with-changed-data-file-name.bdoc");
    SignatureValidationResult result = container.validate();
    Assert.assertEquals(2, result.getErrors().size());
    Assert.assertEquals("Container contains a file named <test1.txt> which is not found in the signature file", result.getErrors().get(1).getMessage());
  }

  @Test
  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  public void revocationAndTimeStampDifferenceTooLarge() {
    Container container = ContainerOpener
        .open("src/test/resources/prodFiles/invalid-containers/revocation_timestamp_delta_26h.asice", PROD_CONFIGURATION);
    String signatureId = TestIdUtil.findExactlyOneSignatureByXmlDigitalSignatureId(container, "S0").getId();
    SignatureValidationResult validate = container.validate();
    Assert.assertEquals(1, validate.getErrors().size());
    Assert.assertEquals(
        "(Signature ID: " + signatureId + ") - The difference between the OCSP response time and the signature timestamp is too large",
        validate.getErrors().get(0).toString());
  }

  @Test
  public void revocationAndTimeStampDifferenceNotTooLarge() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    int delta27Hours = 27 * 60;
    configuration.setRevocationAndTimestampDeltaInMinutes(delta27Hours);
    SignatureValidationResult result = ContainerOpener
        .open("src/test/resources/prodFiles/invalid-containers/revocation_timestamp_delta_26h.asice", configuration)
        .validate();
    Assert.assertEquals(0, result.getErrors().size());
    Assert.assertEquals(2, result.getWarnings().size());
  }

  @Test
  public void signatureFileAndManifestFileContainDifferentMimeTypeForFile() {
    Container container = ContainerOpener
        .open("src/test/resources/prodFiles/invalid-containers/mimetype_mismatch.asice", PROD_CONFIGURATION_WITH_TEST_POLICY);
    String signatureId = TestIdUtil.findExactlyOneSignatureByXmlDigitalSignatureId(container, "S0").getId();
    SignatureValidationResult validate = container.validate();
    Assert.assertEquals(1, validate.getErrors().size());
    Assert.assertEquals(
        "(Signature ID: " + signatureId + ") - Manifest file has an entry for file <RELEASE-NOTES.txt> with mimetype "
            + "<application/pdf> but the signature file for signature " + signatureId + " indicates the mimetype is <text/plain>",
        validate.getErrors().get(0).toString());
  }

  @Test(expected = DuplicateDataFileException.class)
  public void duplicateFileThrowsException() {
    ContainerOpener
        .open("src/test/resources/testFiles/invalid-containers/22902_data_files_with_same_names.bdoc").validate();
  }

  @Test
  public void signaturesWithDuplicateId() {
    Container container = ContainerOpener
        .open("src/test/resources/testFiles/valid-containers/2_signatures_duplicate_id.asice");
    ValidationResult result = container.validate();
    Assert.assertTrue(result.isValid());
  }

  @Test
  public void missingManifestFile() {
    Container container = ContainerOpener
        .open("src/test/resources/prodFiles/invalid-containers/missing_manifest.asice", PROD_CONFIGURATION);
    SignatureValidationResult result = container.validate();
    Assert.assertFalse(result.isValid());
    Assert.assertEquals("Unsupported format: Container does not contain a manifest file",
        result.getErrors().get(0).getMessage());
  }

  @Test(expected = DigiDoc4JException.class)
  public void missingMimeTypeFile() {
    ContainerOpener.open("src/test/resources/testFiles/invalid-containers/missing_mimetype_file.asice");
  }

  @Test
  public void containerHasFileWhichIsNotInManifestAndNotInSignatureFile() {
    Container container = ContainerOpener.open(
        "src/test/resources/prodFiles/invalid-containers/extra_file_in_container.asice",
        PROD_CONFIGURATION_WITH_TEST_POLICY);
    SignatureValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    Assert.assertEquals(1, errors.size());
    Assert.assertEquals(
        "Container contains a file named <AdditionalFile.txt> which is not found in the signature file",
        errors.get(0).getMessage());
  }

  @Test
  public void containerMissesFileWhichIsInManifestAndSignatureFile() {
    TestTSLUtil.addSkTsaCertificateToTsl(this.configuration);
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/zip_misses_file_which_is_in_manifest.asice");
    String signatureId = TestIdUtil.findExactlyOneSignatureByXmlDigitalSignatureId(container, "S0").getId();
    SignatureValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    TestAssert.assertContainsError("(Signature ID: " + signatureId + ") - The certificate chain for timestamp is not trusted, there is no trusted anchor.", errors); // Timestamp issuer originates from PROD chain
  }

  @Test
  public void containerMissingOCSPData() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/TS-06_23634_TS_missing_OCSP_adjusted.asice");
    String signatureId = TestIdUtil.findExactlyOneSignatureByXmlDigitalSignatureId(container, "S0").getId();
    SignatureValidationResult validate = container.validate();
    List<DigiDoc4JException> errors = validate.getErrors();
    Assert.assertEquals(SignatureProfile.LT, container.getSignatures().get(0).getProfile());
    TestAssert.assertContainsError("(Signature ID: " + signatureId + ") - Signature has an invalid timestamp", errors); // Timestamp issuer originates from PROD chain
    TestAssert.assertContainsError(
        "(Signature ID: " + signatureId + ") - Manifest file has an entry for file <test.txt> with mimetype <text/plain> but "
            + "the signature file for signature " + signatureId + " indicates the mimetype is <application/octet-stream>", errors);
  }

  @Ignore("This signature has two OCSP responses: one correct and one is technically corrupted. Opening a container should not throw an exception")
  @Test(expected = DigiDoc4JException.class)
  public void corruptedOCSPDataThrowsException() {
    ContainerOpener.open("src/test/resources/testFiles/invalid-containers/corrupted_ocsp_data.asice");
  }

  @Test
  public void invalidNoncePolicyOid() {
    Container container = ContainerOpener
        .open("src/test/resources/prodFiles/invalid-containers/23608_bdoc21-invalid-nonce-policy-oid.bdoc", PROD_CONFIGURATION);
    String signatureId = TestIdUtil.findExactlyOneSignatureByXmlDigitalSignatureId(container, "S0").getId();
    SignatureValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    Assert.assertEquals(1, errors.size());
    Assert.assertEquals("(Signature ID: " + signatureId + ") - Wrong policy identifier: 1.3.6.1.4.1.10015.1000.3.4.3",
        errors.get(0).toString());
  }

  @Test
  public void badNonceContent() {
    Container container = ContainerOpener
        .open("src/test/resources/prodFiles/invalid-containers/bdoc21-bad-nonce-content.bdoc",
            PROD_CONFIGURATION_WITH_TEST_POLICY);
    String signatureId = TestIdUtil.findExactlyOneSignatureByXmlDigitalSignatureId(container, "S0").getId();
    SignatureValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    Assert.assertEquals(1, errors.size());
    Assert.assertEquals("(Signature ID: " + signatureId + ") - OCSP nonce is invalid", errors.get(0).toString());
  }

  @Test
  public void noSignedPropRefTM() {
    Container container = ContainerOpener
        .open("src/test/resources/prodFiles/invalid-containers/REF-03_bdoc21-TM-no-signedpropref.bdoc", PROD_CONFIGURATION_WITH_TEST_POLICY);
    String signatureId = TestIdUtil.findExactlyOneSignatureByXmlDigitalSignatureId(container, "S0").getId();
    SignatureValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    Assert.assertEquals(1, errors.size());
    TestAssert.assertContainsError("(Signature ID: " + signatureId + ") - SignedProperties Reference element is missing", errors);
    Assert.assertEquals(1, container.getSignatures().get(0).validateSignature().getErrors().size());
  }

  @Test
  public void noSignedPropRefTS() {
    Container container = ContainerOpener
        .open("src/test/resources/prodFiles/invalid-containers/REF-03_bdoc21-TS-no-signedpropref.asice", PROD_CONFIGURATION_WITH_TEST_POLICY);
    String signatureId = TestIdUtil.findExactlyOneSignatureByXmlDigitalSignatureId(container, "S0").getId();
    SignatureValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    Assert.assertEquals(1, errors.size());
    TestAssert.assertContainsError("(Signature ID: " + signatureId + ") - SignedProperties Reference element is missing", errors);
  }

  @Test
  public void multipleSignedProperties() {
    Container container = ContainerOpener
        .open("src/test/resources/testFiles/invalid-containers/multiple_signed_properties.asice");
    SignatureValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    TestAssert.assertContainsError("Multiple signed properties", errors);
    TestAssert.assertContainsError("ignature has an invalid timestamp", errors);
  }

  @Test
  public void incorrectSignedPropertiesReference() {
    Container container = ContainerOpener
        .open("src/test/resources/prodFiles/invalid-containers/signed_properties_reference_not_found.asice",
            PROD_CONFIGURATION_WITH_TEST_POLICY);
    SignatureValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    Assert.assertEquals(2, errors.size());
  }

  @Test
  public void nonceIncorrectContent() {
    Container container = ContainerOpener
        .open("src/test/resources/prodFiles/invalid-containers/nonce-vale-sisu.bdoc", PROD_CONFIGURATION_WITH_TEST_POLICY);
    String signatureId = TestIdUtil.findExactlyOneSignatureByXmlDigitalSignatureId(container, "S0").getId();
    SignatureValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    Assert.assertEquals(4, errors.size());
    Assert.assertEquals("(Signature ID: " + signatureId + ") - Wrong policy identifier: 1.3.6.1.4.1.10015.1000.2.10.10",
        errors.get(0).toString());
    Assert.assertEquals("(Signature ID: " + signatureId + ") - OCSP nonce is invalid", errors.get(2).toString());
  }

  @Test
  public void badNoncePolicyOidQualifier() {
    Container container = ContainerOpener
        .open("src/test/resources/prodFiles/invalid-containers/SP-03_bdoc21-bad-nonce-policy-oidasuri.bdoc",
            PROD_CONFIGURATION_WITH_TEST_POLICY);
    String signatureId = TestIdUtil.findExactlyOneSignatureByXmlDigitalSignatureId(container, "S0").getId();
    SignatureValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    Assert.assertEquals(1, errors.size());
    Assert.assertEquals("(Signature ID: " + signatureId + ") - Wrong policy identifier qualifier: OIDAsURI",
        errors.get(0).toString());
    Assert.assertEquals(1, container.getSignatures().get(0).validateSignature().getErrors().size());
  }

  @Test
  public void invalidNonce() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/23200_weakdigest-wrong-nonce.asice");
    String signatureId = TestIdUtil.findExactlyOneSignatureByXmlDigitalSignatureId(container, "S0").getId();
    SignatureValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    Assert.assertEquals(1, errors.size());
    Assert.assertEquals("(Signature ID: " + signatureId + ") - OCSP nonce is invalid", errors.get(0).toString());
  }

  @Test
  public void invalidWeakDigestUnknownCa() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/23200_weakdigest-unknown-ca.asice");
    String signatureId = TestIdUtil.findExactlyOneSignatureByXmlDigitalSignatureId(container, "S0").getId();
    SignatureValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    Assert.assertEquals(2, errors.size());
    Assert.assertEquals(
        "(Signature ID: " + signatureId + ") - The certificate path is not trusted!",
        errors.get(0).toString());
  }

  @Test
  public void invalidUnknownCa() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/SS-4_teadmataCA.4.asice");
    String signatureId = TestIdUtil.findExactlyOneSignatureByXmlDigitalSignatureId(container, "S0").getId();
    SignatureValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    Assert.assertEquals(2, errors.size());
    Assert.assertEquals(
        "(Signature ID: " + signatureId + ") - The certificate path is not trusted!",
        errors.get(0).toString());
  }

  @Test
  public void validBDocRsa2047_whenASN1UnsafeIntegerAllowed() {
    PROD_CONFIGURATION.setAllowASN1UnsafeInteger(true);
    Assert.assertEquals(true, PROD_CONFIGURATION.isASN1UnsafeIntegerAllowed());
    Container container = ContainerOpener
        .open("src/test/resources/prodFiles/valid-containers/IB-4183_3.4kaart_RSA2047.bdoc", PROD_CONFIGURATION);
    SignatureValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    Assert.assertEquals(0, errors.size());
    PROD_CONFIGURATION.setAllowASN1UnsafeInteger(false);
  }

  @Test
  public void validTSRsa2047_whenASN1UnsafeIntegerAllowed() {
    PROD_CONFIGURATION.setAllowASN1UnsafeInteger(true);
    Assert.assertEquals(true, PROD_CONFIGURATION.isASN1UnsafeIntegerAllowed());
    Container container = ContainerOpener
        .open("src/test/resources/prodFiles/valid-containers/IB-4183_3.4kaart_RSA2047_TS.asice", PROD_CONFIGURATION);
    SignatureValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    Assert.assertEquals(0, errors.size());
    PROD_CONFIGURATION.setAllowASN1UnsafeInteger(false);
  }

  @Test(expected = TechnicalException.class)
  public void invalidBDocRsa2047_whenASN1UnsafeIntegerNotAllowed() {
    PROD_CONFIGURATION.setAllowASN1UnsafeInteger(false);
    Assert.assertEquals(false, PROD_CONFIGURATION.isASN1UnsafeIntegerAllowed());
    Container container = ContainerOpener
            .open("src/test/resources/prodFiles/valid-containers/IB-4183_3.4kaart_RSA2047.bdoc", PROD_CONFIGURATION);
    container.validate();
  }

  @Test(expected = TechnicalException.class)
  public void invalidTSRsa2047_whenASN1UnsafeIntegerNotAllowed() {
    PROD_CONFIGURATION.setAllowASN1UnsafeInteger(false);
    Assert.assertEquals(false, PROD_CONFIGURATION.isASN1UnsafeIntegerAllowed());
    Container container = ContainerOpener
            .open("src/test/resources/prodFiles/valid-containers/IB-4183_3.4kaart_RSA2047_TS.asice", PROD_CONFIGURATION);
    container.validate();
  }

  @Test
  public void brokenTS() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/TS_broken_TS.asice");
    String signatureId = TestIdUtil.findExactlyOneSignatureByXmlDigitalSignatureId(container, "S0").getId();
    SignatureValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    Assert.assertEquals(3, errors.size());
    Assert.assertEquals("(Signature ID: " + signatureId + ") - The result of the timestamps validation process is not conclusive!",
        errors.get(0).toString());
    Assert.assertEquals("(Signature ID: " + signatureId + ") - " + InvalidTimestampException.MESSAGE, errors.get(2).toString());
  }

  @Test
  public void asicValidationShouldFail_ifTimeStampHashDoesntMatchSignature() throws Exception {
    SignatureValidationResult result = this.openContainerBy(
        Paths.get("src/test/resources/testFiles/invalid-containers/TS-02_23634_TS_wrong_SignatureValue.asice"))
        .validate();
    Assert.assertFalse(result.isValid());
    TestAssert.assertContainsError(InvalidTimestampException.MESSAGE, result.getErrors());
  }

  @Test
  public void containerWithTMProfile_SignedWithExpiredCertificate_shouldBeInvalid() throws Exception {
    Assert.assertFalse(this.openContainerBy(
        Paths.get("src/test/resources/testFiles/invalid-containers/invalid_bdoc_tm_old-sig-sigat-NOK-prodat-NOK.bdoc"))
        .validate().isValid());
    Assert.assertFalse(this.openContainerBy(
        Paths.get("src/test/resources/testFiles/invalid-containers/invalid_bdoc_tm_old-sig-sigat-OK-prodat-NOK.bdoc"))
        .validate().isValid());
  }

  @Test
  public void containerWithTSProfile_SignedWithExpiredCertificate_shouldBeInvalid() throws Exception {
    Assert.assertFalse(this.openContainerBy(
        Paths.get("src/test/resources/testFiles/invalid-containers/invalid_bdoc21-TS-old-cert.bdoc"))
        .validate().isValid());
  }

  @Test
  public void bdocTM_signedWithValidCert_isExpiredByNow_shouldBeValid() throws Exception {
    String containerPath =
        "src/test/resources/testFiles/valid-containers/valid_bdoc_tm_signed_with_valid_cert_expired_by_now.bdoc";
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    TestTSLUtil.addCertificateFromFileToTsl(configuration,
        "src/test/resources/testFiles/certs/ESTEID-SK_2007_prod.pem.crt");
    Container container = ContainerBuilder.aContainer().fromExistingFile(containerPath)
        .withConfiguration(configuration).build();
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void signaturesWithCrlShouldBeInvalid() throws Exception {
    SignatureValidationResult result = this.openContainerByConfiguration(
        Paths.get("src/test/resources/prodFiles/invalid-containers/asic-with-crl-and-without-ocsp.asice"),
        PROD_CONFIGURATION)
        .validate();
    Assert.assertFalse(result.isValid());
    Assert.assertTrue(result.getErrors().get(0) instanceof UntrustedRevocationSourceException);
  }

  @Test
  public void bDoc_withoutOcspResponse_shouldBeInvalid() throws Exception {
    Assert.assertFalse(this.openContainerByConfiguration(
        Paths.get("src/test/resources/prodFiles/invalid-containers/23608-bdoc21-no-ocsp.bdoc"),
        PROD_CONFIGURATION)
        .validate().isValid());
  }

  @Test
  public void bDoc_invalidOcspResponse() {
    try {
      this.openContainerByConfiguration(Paths.get("src/test/resources/prodFiles/invalid-containers/bdoc21-vigane-ocsp.bdoc"), PROD_CONFIGURATION);
      Assert.fail("Should not be able to successfully open container!");
    } catch (DSSException exception) {
      Assert.assertEquals("Cannot create the token reference. The element with local name [EncapsulatedOCSPValue] must contain an encapsulated base64 token value!", exception.getMessage());
    }
  }

  @Test
  public void ocspResponseShouldNotBeTakenFromPreviouslyValidatedSignatures_whenOcspResponseIsMissing() throws Exception {
    Assert.assertFalse(this.openContainerByConfiguration(
        Paths.get("src/test/resources/testFiles/invalid-containers/bdoc-tm-ocsp-revoked.bdoc"), this.configuration)
        .validate().isValid());
    Assert.assertTrue(this.openContainerByConfiguration(
        Paths.get("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc"), this.configuration)
        .validate().isValid());
    Assert.assertFalse(this.openContainerByConfiguration(
        Paths.get("src/test/resources/testFiles/invalid-containers/invalid-bdoc-tm-missing-revoked-ocsp.bdoc"),
        this.configuration)
        .validate().isValid());
  }

  @Test
  public void validateContainerWithBomSymbolsInMimeType_shouldBeValid() throws Exception {
    Assert.assertTrue(this.openContainerByConfiguration(
        Paths.get("src/test/resources/prodFiles/valid-containers/IB-4185_bdoc21_TM_mimetype_with_BOM_PROD.bdoc"),
        PROD_CONFIGURATION)
        .validate().isValid());
  }

  @Test
  public void containerValidation_withManuallyAddedTrustedCertificates_shouldSucceed() throws Exception {
    TSLCertificateSourceImpl tsl = new TSLCertificateSourceImpl();
    Configuration conf = Configuration.of(Configuration.Mode.PROD);
    conf.setAllowASN1UnsafeInteger(true);
    conf.setTSL(tsl);
    try (InputStream inputStream = new FileInputStream("src/test/resources/prodFiles/certs/ESTEID-SK_2011.pem.crt")) {
      tsl.addTSLCertificate(DSSUtils.loadCertificate(inputStream).getCertificate());
    }
    try (InputStream inputStream = new FileInputStream("src/test/resources/prodFiles/certs/SK_OCSP_RESPONDER_2011.pem.cer")) {
      tsl.addTSLCertificate(DSSUtils.loadCertificate(inputStream).getCertificate());
    }
    try (InputStream inputStream = new FileInputStream("src/test/resources/prodFiles/certs/SK_TSA.pem.crt")) {
      tsl.addTSLCertificate(DSSUtils.loadCertificate(inputStream).getCertificate());
    }
    SignatureValidationResult result = this.openContainerByConfiguration(
            Paths.get("src/test/resources/prodFiles/valid-containers/IB-4183_3.4kaart_RSA2047_TS.asice"), conf)
            .validate();
    Assert.assertTrue(result.isValid());
    Assert.assertEquals(0, result.getErrors().size());
    conf.setAllowASN1UnsafeInteger(false);
  }

  @Test
  public void havingOnlyCaCertificateInTSL_shouldNotValidateOCSPResponse() throws Exception {
    TSLCertificateSourceImpl tsl = new TSLCertificateSourceImpl();
    this.configuration.setTSL(tsl);
    try (InputStream inputStream = this.getClass().getResourceAsStream("/certs/TEST ESTEID-SK 2011.crt")) {
      tsl.addTSLCertificate(DSSUtils.loadCertificate(inputStream).getCertificate());
    }
    SignatureValidationResult result = this.openContainerByConfiguration(
        Paths.get("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc"), this.configuration)
        .validate();
    Assert.assertFalse(result.isValid());
  }

  @Test
  public void mixTSLCertAndTSLOnlineSources_SignatureTypeLT_valid() throws Exception {
    try (InputStream caStream = new FileInputStream("src/test/resources/testFiles/certs/exampleCA.cer")) {
      this.configuration.getTSL().addTSLCertificate(DSSUtils.loadCertificate(caStream).getCertificate());
      this.configuration.getTSL().addTSLCertificate(DSSUtils
          .loadCertificate(new FileInputStream("src/test/resources/testFiles/certs/SK-OCSP-RESPONDER-2011_test.cer"))
          .getCertificate());
    }
    Container container = this.createNonEmptyContainerByConfiguration();
    this.createSignatureBy(container, SignatureProfile.LT,
        new PKCS12SignatureToken("src/test/resources/testFiles/p12/user_one.p12", "user_one".toCharArray()));
    SignatureValidationResult result = container.validate();
    Assert.assertTrue(result.isValid());
    Assert.assertEquals(0, result.getErrors().size());
  }

  @Test
  public void mixTSLCertAndTSLOnlineSources_SignatureTypeLT_notValid() throws Exception {
    TSLCertificateSource certificateSource = new TSLCertificateSourceImpl();
    try (InputStream inputStream = new FileInputStream("src/test/resources/testFiles/certs/exampleCA.cer")) {
      X509Certificate certificate = DSSUtils.loadCertificate(inputStream).getCertificate();
      certificateSource.addTSLCertificate(certificate);
      certificateSource.addTSLCertificate(DSSUtils
          .loadCertificate(new FileInputStream("src/test/resources/testFiles/certs/SK-OCSP-RESPONDER-2011_test.cer"))
          .getCertificate());
    }
    this.configuration.setTSL(certificateSource);
    Container container = this.createNonEmptyContainerByConfiguration();
    this.createSignatureBy(container, SignatureProfile.LT,
        new PKCS12SignatureToken("src/test/resources/testFiles/p12/user_one.p12", "user_one".toCharArray()));
    SignatureValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    List<Signature> signatureList = container.getSignatures();
    Signature signature = signatureList.get(0);
    String signatureId = signature.getId();
    Assert.assertFalse(result.isValid());
    Assert.assertEquals(3, errors.size());
    Assert.assertEquals("(Signature ID: " + signatureId +
        ") - The result of the timestamps validation process is not conclusive!",
        errors.get(0).toString());
    Assert.assertEquals("(Signature ID: " + signatureId + ") - Signature has an invalid timestamp",
        errors.get(2).toString());
  }

  @Test
  public void validateAsiceContainer_getNotValid() throws Exception {
    Assert.assertFalse(this.openContainerByConfiguration(
        Paths.get("src/test/resources/testFiles/invalid-containers/TM-16_unknown.4.asice"), this.configuration)
        .validate().isValid());
  }

  @Test
  public void validateSpuriElement_UriIsvalid() throws Exception {
    Container container = ContainerOpener
        .open("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc", this.configuration);
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void validateBDocTs_Isvalid() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/prodFiles/invalid-containers/bdoc21-ts-ok.bdoc", PROD_CONFIGURATION);
    String signatureId = TestIdUtil.findExactlyOneSignatureByXmlDigitalSignatureId(container, "S0").getId();
    SignatureValidationResult result = container.validate();
    Assert.assertFalse(result.isValid());
    Assert.assertEquals(6, result.getErrors().size());
    TestAssert.assertContainsError(
        "(Signature ID: " + signatureId + ") - The result of the timestamps validation process is not conclusive!",
        result.getErrors());
    TestAssert.assertContainsError(
        "(Signature ID: " + signatureId + ") - Signature has an invalid timestamp", result.getErrors());
    TestAssert.assertContainsError(
        "(Signature ID: " + signatureId + ") - Manifest file has an entry for file <build.xml> with mimetype <text/xml> but the " +
            "signature file for signature " + signatureId + " indicates the mimetype is <>", result.getErrors());
  }

  @Test
  public void validateSpuriElement_UriIsMissing() throws Exception {
    Container container = ContainerOpener
        .open("src/test/resources/testFiles/valid-containers/23608_bdoc21-no-nonce-policy.bdoc", this.configuration);
    SignatureValidationResult result = container.validate();
    Assert.assertFalse(container.validate().isValid());
    TestAssert.assertContainsError("Error: The URL in signature policy is empty or not available", result.getErrors());
  }

  @Test
  public void validateSpuriElement_UriIsEmpty() throws Exception {
    Container container = ContainerOpener
        .open("src/test/resources/testFiles/valid-containers/SP-06_bdoc21-no-uri.bdoc", this.configuration);
    SignatureValidationResult result = container.validate();
    Assert.assertFalse(result.isValid());
    TestAssert.assertContainsError("The URL in signature policy is empty or not available", result.getErrors());
  }

  @Test
  public void invalidOcspResponder() {
    this.configuration.setAllowedOcspRespondersForTM("INVALID OCSP RESPONDER");
    Container container = ContainerOpener
            .open("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc", this.configuration);
    SignatureValidationResult result = container.validate();
    TestAssert.assertContainsError("OCSP Responder does not meet TM requirements", result.getErrors());
  }

  @Test
  public void sameCertAddedTwiceToTSL_containerValidationShouldSucceed() {
    Configuration conf = Configuration.of(Configuration.Mode.PROD);
    conf.setTSL(new TSLCertificateSourceImpl());
    conf.setAllowASN1UnsafeInteger(true);
    TestTSLUtil.addCertificateFromFileToTsl(conf, "src/test/resources/prodFiles/certs/ESTEID-SK_2011.pem.crt");
    TestTSLUtil.addCertificateFromFileToTsl(conf, "src/test/resources/prodFiles/certs/ESTEID-SK_2011.pem.crt");
    TestTSLUtil.addCertificateFromFileToTsl(conf, "src/test/resources/prodFiles/certs/SK_OCSP_RESPONDER_2011.pem.cer");
    TestTSLUtil.addCertificateFromFileToTsl(conf, "src/test/resources/prodFiles/certs/SK_TSA.pem.crt");
    SignatureValidationResult result = this.openContainerByConfiguration(
            Paths.get("src/test/resources/prodFiles/valid-containers/IB-4183_3.4kaart_RSA2047_TS.asice"), conf).validate();
    Assert.assertTrue(result.isValid());
    Assert.assertEquals(0, result.getErrors().size());
    conf.setAllowASN1UnsafeInteger(false);
  }

  @Test
  public void prodContainerWithSignatureWarningOfTrustedCertificateNotMatchingWithTrustService_warningIsRemoved() {
    Container container = ContainerBuilder.aContainer().
            fromExistingFile("src/test/resources/prodFiles/valid-containers/Baltic MoU digital signing_EST_LT_LV.bdoc").
            withConfiguration(PROD_CONFIGURATION).build();
    ContainerValidationResult validationResult = container.validate();
    Assert.assertTrue(validationResult.isValid());
    Assert.assertTrue(validationResult.getErrors().isEmpty());
    Assert.assertFalse(validationResult.getWarnings().contains(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2.getMessage()));
  }

  @Test
  public void testContainerWithSignatureWarningOfTrustedCertificateNotMatchingWithTrustService_warningIsRemoved() {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    Container container = ContainerBuilder.aContainer().
            fromExistingFile("src/test/resources/testFiles/valid-containers/valid_bdoc_tm_signed_with_valid_cert_expired_by_now.bdoc").
            withConfiguration(configuration)
            .build();
    TestTSLUtil.addCertificateFromFileToTsl(configuration, "src/test/resources/testFiles/certs/ESTEID-SK_2007_prod.pem.crt");
    ContainerValidationResult validationResult = container.validate();
    Assert.assertTrue(validationResult.isValid());
    Assert.assertTrue(validationResult.getErrors().isEmpty());
    Assert.assertFalse(validationResult.getWarnings().contains(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2.getMessage()));
  }

  @Test
  public void container_withTimestampTakenWhenSigningCertificateWasNotValid_shouldBeInvalid() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/signing_certificate_not_valid_during_timestamping.asice");
    SignatureValidationResult result = container.validate();
    Assert.assertFalse("Signature must not be valid when timestamp was taken while signing certificate was not valid", result.isValid());
    Assert.assertEquals(1, result.getErrors().size());
    Assert.assertEquals("Signature has been created with expired certificate", result.getErrors().get(0).getMessage());
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
  }

}
