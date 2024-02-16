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

import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSUtils;
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
import org.digidoc4j.exceptions.TimestampAfterOCSPResponseTimeException;
import org.digidoc4j.exceptions.UnsupportedFormatException;
import org.digidoc4j.exceptions.UntrustedRevocationSourceException;
import org.digidoc4j.impl.asic.tsl.TSLCertificateSourceImpl;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.digidoc4j.test.TestAssert;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.digidoc4j.test.util.TestSigningUtil;
import org.digidoc4j.test.util.TestTSLUtil;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.digidoc4j.test.matcher.IsDigiDoc4JException.digiDoc4JExceptionMessageContainsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThrows;

public class ValidationTest extends AbstractTest {

  public static final Configuration PROD_CONFIGURATION = new Configuration(Configuration.Mode.PROD);
  public static final Configuration PROD_CONFIGURATION_WITH_TEST_POLICY = new Configuration(Configuration.Mode.PROD);

  @BeforeClass
  public static void setUpOnce() throws Exception {
    PROD_CONFIGURATION_WITH_TEST_POLICY.setValidationPolicy("conf/test_constraint.xml");
  }

  @Test
  @Ignore("DD4J-978 Lithuanian trusted list is temporarily unusable")
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
    this.createSignatureBy(container, pkcs12SignatureToken);
    Assert.assertEquals(0, container.validate().getErrors().size());
  }

  @Test
  public void validCAServiceTypeIdentification() {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    TSLCertificateSource source = this.configuration.getTSL();
    Container container = ContainerBuilder.aContainer().
            fromExistingFile("src/test/resources/testFiles/valid-containers/valid-asice.asice").
            withConfiguration(this.configuration).build();
    this.addCertificateToTSL(Paths.get("src/test/resources/testFiles/certs/TEST_of_ESTEID-SK_2015.pem.crt"), source);
    this.addCertificateToTSL(Paths.get("src/test/resources/testFiles/certs/SK-OCSP-RESPONDER-2011_test.cer"), source);
    this.addCertificateToTSL(Paths.get("src/test/resources/testFiles/certs/DEMO_OF_SK_TSA_2014.cer"), source);
    ContainerValidationResult result = container.validate();
    Assert.assertTrue(result.isValid());
  }

  @Test
  public void testValidateBeforeAndAfterContainerChange() {
    Container container = this.createNonEmptyContainer();
    this.createSignatureBy(container, pkcs12SignatureToken);
    ContainerValidationResult result = container.validate();

    TestAssert.assertContainerIsValid(result);
    Assert.assertEquals(1, result.getReports().size());
    Assert.assertEquals("O’CONNEŽ-ŠUSLIK TESTNUMBER,MARY ÄNN,60001013739", result.getReports().get(0).getSignedBy());
    assertHasNoWarnings(result);

    this.createSignatureBy(container, pkcs12Esteid2018SignatureToken);
    result = container.validate();

    Assert.assertTrue(result.isValid());
    Assert.assertEquals(2, result.getReports().size());
    Assert.assertEquals("O’CONNEŽ-ŠUSLIK TESTNUMBER,MARY ÄNN,60001013739", result.getReports().get(0).getSignedBy());
    Assert.assertEquals("JÕEORG,JAAK-KRISTJAN,38001085718", result.getReports().get(1).getSignedBy());
    assertHasNoWarnings(result);
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
      Assert.assertTrue(e.getMessage().contains("is expired at signing time"));
      throw e;
    }
  }

  @Test
  public void signatureFileContainsIncorrectFileName() {
    Container container = ContainerOpener
        .open("src/test/resources/prodFiles/invalid-containers/filename_mismatch_signature.asice", PROD_CONFIGURATION);
    SignatureValidationResult validate = container.validate();
    List<DigiDoc4JException> errors = validate.getErrors();
    TestAssert.assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(errors, 7,
            "(Signature ID: S0) - The signature file for signature S0 has an entry for file <0123456789~#%&()=`@{[]}'.txt> with mimetype <application/pdf> but the manifest file does not have an entry for this file"
    );
  }

  @Test
  public void signaturePolicyIsPolicyImplied(){
    Container container = ContainerOpener
            .open("src/test/resources/testFiles/valid-containers/policyImplied.asice",
                    this.configuration);
    SignatureValidationResult validationResult = container.validate();
    Assert.assertTrue(validationResult.isValid());
    Assert.assertEquals(2, validationResult.getWarnings().size());
    Assert.assertEquals("Signature created with implied policy, additional conditions may apply!", validationResult.getWarnings().get(0).getMessage());
    Assert.assertEquals("The authority info access is not present!", validationResult.getWarnings().get(1).getMessage());
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
    SignatureValidationResult validate = container.validate();
    List<DigiDoc4JException> errors = validate.getErrors();
    Assert.assertEquals(2, errors.size());
    TestAssert.assertContainsError(
        "(Signature ID: S0) - Manifest file has an entry for file <test1.txt> with mimetype "
            + "<application/octet-stream> but the signature file for signature S0 does not have an entry for this "
            + "file", errors);
    TestAssert.assertContainsError(
        "Container contains a file named <test1.txt> which is not found in the signature file", errors);
  }

  @Test
  public void validateContainer_withChangedDataFileContent_isInvalid() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/invalid-data-file.bdoc");
    SignatureValidationResult validate = container.validate();
    TestAssert.assertContainsExactSetOfErrors(validate.getErrors(),
            "(Signature ID: S0) - The reference data object is not intact!",
            "(Signature ID: S0) - The current time is not in the validity range of the signer's certificate!",
            "(Signature ID: S0) - The certificate validation is not conclusive!"
    );
  }

  @Test
  public void secondSignatureFileContainsIncorrectFileName() {
    TestTSLUtil.addSkTsaCertificateToTsl(this.configuration);
    Container container = ContainerOpener.open(
        "src/test/resources/testFiles/invalid-containers/filename_mismatch_second_signature.asice",
        this.configuration);
    SignatureValidationResult validate = container.validate();
    TestAssert.assertContainsExactSetOfErrors(validate.getErrors(),
            "(Signature ID: S1) - The reference data object is not intact!",
            "(Signature ID: S1) - Manifest file has an entry for file <test.txt> with mimetype <text/plain> but "
                    + "the signature file for signature S1 does not have an entry for this file",
            "Container contains a file named <test.txt> which is not found in the signature file",
            "The current time is not in the validity range of the signer's certificate!",
            "The certificate validation is not conclusive!"
    );
  }

  @Test
  public void manifestFileContainsIncorrectFileName() {
    Container container = ContainerOpener
        .open("src/test/resources/prodFiles/invalid-containers/filename_mismatch_manifest.asice", PROD_CONFIGURATION_WITH_TEST_POLICY);
    SignatureValidationResult validate = container.validate();
    TestAssert.assertContainsExactSetOfErrors(validate.getErrors(),
            "(Signature ID: S0) - Manifest file has an entry for file <incorrect.txt> with mimetype <text/plain> but "
                    + "the signature file for signature S0 does not have an entry for this file",
            "(Signature ID: S0) - The signature file for signature S0 has an entry for file <RELEASE-NOTES.txt> "
                    + "with mimetype <text/plain> but the manifest file does not have an entry for this file"
    );
  }

  @Test
  public void container_withChangedDataFileName_shouldBeInvalid() throws Exception {
    Container container = ContainerOpener
        .open("src/test/resources/testFiles/invalid-containers/bdoc-tm-with-changed-data-file-name.bdoc");
    SignatureValidationResult result = container.validate();
    TestAssert.assertContainsExactSetOfErrors(result.getErrors(),
            "(Signature ID: S0) - The reference data object has not been found!",
            "Container contains a file named <test1.txt> which is not found in the signature file",
            "The current time is not in the validity range of the signer's certificate!",
            "The certificate validation is not conclusive!"
    );
  }

  @Test
  @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
  public void revocationAndTimeStampDifferenceTooLarge() {
    Container container = ContainerOpener
        .open("src/test/resources/prodFiles/invalid-containers/revocation_timestamp_delta_26h.asice", PROD_CONFIGURATION);
    SignatureValidationResult validate = container.validate();
    TestAssert.assertContainsExactSetOfErrors(validate.getErrors(),
            "(Signature ID: S0) - The difference between the OCSP response time and the signature timestamp is too large"
    );
  }

  @Test
  public void revocationAndTimeStampDifferenceNotTooLarge() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    int delta27Hours = 27 * 60;
    configuration.setRevocationAndTimestampDeltaInMinutes(delta27Hours);
    ContainerValidationResult result = ContainerOpener
        .open("src/test/resources/prodFiles/invalid-containers/revocation_timestamp_delta_26h.asice", configuration)
        .validate();
    TestAssert.assertContainerIsValid(result);
    TestAssert.assertContainsExactSetOfErrors(result.getWarnings(),
            "The difference between the OCSP response time and the signature timestamp is in allowable range",
            "The authority info access is not present!"
    );
  }

  @Test
  public void signatureFileAndManifestFileContainDifferentMimeTypeForFile() {
    Container container = ContainerOpener
        .open("src/test/resources/prodFiles/invalid-containers/mimetype_mismatch.asice", PROD_CONFIGURATION_WITH_TEST_POLICY);
    ContainerValidationResult result = container.validate();
    TestAssert.assertContainsExactSetOfErrors(result.getErrors(),
            "(Signature ID: S0) - Manifest file has an entry for file <RELEASE-NOTES.txt> with mimetype "
                    + "<application/pdf> but the signature file for signature S0 indicates the mimetype is <text/plain>"
    );
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
    TestAssert.assertContainsExactSetOfErrors(result.getErrors(),
            "Unsupported format: Container does not contain a manifest file"
    );
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
    TestAssert.assertContainsExactSetOfErrors(result.getErrors(),
            "Container contains a file named <AdditionalFile.txt> which is not found in the signature file"
    );
  }

  @Test
  public void containerMissesFileWhichIsInManifestAndSignatureFile() {
    TestTSLUtil.addSkTsaCertificateToTsl(this.configuration);
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/zip_misses_file_which_is_in_manifest.asice");
    SignatureValidationResult result = container.validate();
    TestAssert.assertContainsErrors(result.getErrors(),
            "The reference data object has not been found!",
            "Signature has an invalid timestamp" // Timestamp issuer originates from PROD chain
    );
  }

  @Test
  public void containerMissingOCSPData() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/TS-06_23634_TS_missing_OCSP_adjusted.asice");
    SignatureValidationResult validate = container.validate();
    List<DigiDoc4JException> errors = validate.getErrors();
    Assert.assertEquals(SignatureProfile.LT, container.getSignatures().get(0).getProfile());
    TestAssert.assertContainsError("(Signature ID: S0) - Signature has an invalid timestamp", errors); // Timestamp issuer originates from PROD chain
    TestAssert.assertContainsError(
        "(Signature ID: S0) - Manifest file has an entry for file <test.txt> with mimetype <text/plain> but "
            + "the signature file for signature S0 indicates the mimetype is <application/octet-stream>", errors);
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
    SignatureValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    TestAssert.assertContainsExactSetOfErrors(errors,
            "Wrong policy identifier: 1.3.6.1.4.1.10015.1000.3.4.3",
            "The certificate is not related to a qualified certificate issuing trust service with valid status!",
            "The current time is not in the validity range of the signer's certificate!",
            "The certificate validation is not conclusive!",
            "The best-signature-time is not before the expiration date of the signing certificate!",
            "The past signature validation is not conclusive!"
    );
  }

  @Test
  public void badNonceContent() {
    Container container = ContainerOpener
        .open("src/test/resources/prodFiles/invalid-containers/bdoc21-bad-nonce-content.bdoc",
            PROD_CONFIGURATION_WITH_TEST_POLICY);
    SignatureValidationResult result = container.validate();
    TestAssert.assertContainsExactSetOfErrors(result.getErrors(),
            "(Signature ID: S0) - OCSP nonce is invalid"
    );
  }

  @Test
  public void noSignedPropRefTM() {
    Container container = ContainerOpener
        .open("src/test/resources/prodFiles/invalid-containers/REF-03_bdoc21-TM-no-signedpropref.bdoc", PROD_CONFIGURATION_WITH_TEST_POLICY);
    SignatureValidationResult result = container.validate();
    TestAssert.assertContainsExactSetOfErrors(result.getErrors(),
            "(Signature ID: S0) - SignedProperties Reference element is missing",
            "(Signature ID: S0) - The signed qualifying property: neither 'message-digest' nor 'SignedProperties' is present!",
            "(Signature ID: S0) - The current time is not in the validity range of the signer's certificate!",
            "(Signature ID: S0) - The certificate validation is not conclusive!"
    );
    Assert.assertEquals(4, container.getSignatures().get(0).validateSignature().getErrors().size());
  }

  @Test
  public void noSignedPropRefTS() {
    Container container = ContainerOpener
        .open("src/test/resources/prodFiles/invalid-containers/REF-03_bdoc21-TS-no-signedpropref.asice", PROD_CONFIGURATION_WITH_TEST_POLICY);
    SignatureValidationResult result = container.validate();
    TestAssert.assertContainsExactSetOfErrors(result.getErrors(),
            "(Signature ID: S0) - SignedProperties Reference element is missing",
            "(Signature ID: S0) - The signed qualifying property: neither 'message-digest' nor 'SignedProperties' is present!",
            "(Signature ID: S0) - The current time is not in the validity range of the signer's certificate!",
            "(Signature ID: S0) - The certificate validation is not conclusive!"
    );
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
    TestAssert.assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(result.getErrors(), 3,
            "The reference data object has not been found!"
    );
  }

  @Test
  public void nonceIncorrectContent() {
    Container container = ContainerOpener
        .open("src/test/resources/prodFiles/invalid-containers/nonce-vale-sisu.bdoc", PROD_CONFIGURATION_WITH_TEST_POLICY);
    SignatureValidationResult result = container.validate();
    TestAssert.assertContainsExactSetOfErrors(result.getErrors(),
            "OCSP nonce is invalid",
            "Wrong policy identifier: 1.3.6.1.4.1.10015.1000.2.10.10",
            "The certificate is not related to a qualified certificate issuing trust service with valid status!",
            "The signature policy is not available!",
            "The reference data object has not been found!",
            "The signature file for signature S0 has an entry for file <META-INF/manifest.xml> with mimetype "
                    + "<application/xml> but the manifest file does not have an entry for this file",
            "The current time is not in the validity range of the signer's certificate!",
            "The certificate validation is not conclusive!"
    );
  }

  @Test
  public void badNoncePolicyOidQualifier() {
    Container container = ContainerOpener
        .open("src/test/resources/prodFiles/invalid-containers/SP-03_bdoc21-bad-nonce-policy-oidasuri.bdoc",
            PROD_CONFIGURATION_WITH_TEST_POLICY);
    SignatureValidationResult result = container.validate();
    TestAssert.assertContainsExactSetOfErrors(result.getErrors(),
            "(Signature ID: S0) - Wrong policy identifier qualifier: OIDAsURI"
    );
    Assert.assertEquals(1, container.getSignatures().get(0).validateSignature().getErrors().size());
  }

  @Test
  public void invalidNonce() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/23200_weakdigest-wrong-nonce.asice");
    SignatureValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    Assert.assertEquals(1, errors.size());
    Assert.assertEquals("(Signature ID: S0) - OCSP nonce is invalid", errors.get(0).toString());
  }

  @Test
  public void invalidWeakDigestUnknownCa() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/23200_weakdigest-unknown-ca.asice");
    SignatureValidationResult result = container.validate();
    TestAssert.assertContainsExactSetOfErrors(result.getErrors(),
            "(Signature ID: S0) - Unable to build a certificate chain up to a trusted list!",
            "The certificate chain for signature is not trusted, it does not contain a trust anchor."
    );
  }

  @Test
  public void invalidUnknownCa() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/SS-4_teadmataCA.4.asice");
    SignatureValidationResult result = container.validate();
    TestAssert.assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(result.getErrors(), 2,
            "(Signature ID: S0) - Unable to build a certificate chain up to a trusted list!"
    );
  }

  @Test
  public void validBDocRsa2047_whenASN1UnsafeIntegerAllowed() {
    PROD_CONFIGURATION.setAllowASN1UnsafeInteger(true);
    Assert.assertTrue(PROD_CONFIGURATION.isASN1UnsafeIntegerAllowed());
    Container container = ContainerOpener
        .open("src/test/resources/prodFiles/valid-containers/IB-4183_3.4kaart_RSA2047.bdoc", PROD_CONFIGURATION);
    ContainerValidationResult result = container.validate();
    TestAssert.assertContainerIsValid(result);
    PROD_CONFIGURATION.setAllowASN1UnsafeInteger(false);
  }

  @Test
  public void validTSRsa2047_whenASN1UnsafeIntegerAllowed() {
    PROD_CONFIGURATION.setAllowASN1UnsafeInteger(true);
    Assert.assertTrue(PROD_CONFIGURATION.isASN1UnsafeIntegerAllowed());
    Container container = ContainerOpener
        .open("src/test/resources/prodFiles/valid-containers/IB-4183_3.4kaart_RSA2047_TS.asice", PROD_CONFIGURATION);
    ContainerValidationResult result = container.validate();
    TestAssert.assertContainerIsValid(result);
    PROD_CONFIGURATION.setAllowASN1UnsafeInteger(false);
  }

  @Test
  public void invalidBDocRsa2047_whenASN1UnsafeIntegerNotAllowed() {
    PROD_CONFIGURATION.setAllowASN1UnsafeInteger(false);
    Assert.assertFalse(PROD_CONFIGURATION.isASN1UnsafeIntegerAllowed());
    Container container = ContainerOpener
            .open("src/test/resources/prodFiles/valid-containers/IB-4183_3.4kaart_RSA2047.bdoc", PROD_CONFIGURATION);
    ContainerValidationResult result = container.validate();
    TestAssert.assertContainsErrors(result.getErrors(),
            "There is no candidate for the signing certificate!"
    );
  }

  @Test(expected = TechnicalException.class)
  public void invalidTSRsa2047_whenASN1UnsafeIntegerNotAllowed() {
    PROD_CONFIGURATION.setAllowASN1UnsafeInteger(false);
    Assert.assertFalse(PROD_CONFIGURATION.isASN1UnsafeIntegerAllowed());
    Container container = ContainerOpener
            .open("src/test/resources/prodFiles/valid-containers/IB-4183_3.4kaart_RSA2047_TS.asice", PROD_CONFIGURATION);
    container.validate();
  }

  @Test
  public void brokenTS() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/TS_broken_TS.asice");
    SignatureValidationResult result = container.validate();
    TestAssert.assertContainsExactSetOfErrors(result.getErrors(),
            "(Signature ID: S0) - The certificate chain for time-stamp is not trusted, it does not contain a trust anchor.",
            "(Signature ID: S0) - Unable to build a certificate chain up to a trusted list!",
            "(Signature ID: S0) - " + InvalidTimestampException.MESSAGE,
            "(Signature ID: S0) - The current time is not in the validity range of the signer's certificate!",
            "(Signature ID: S0) - The certificate validation is not conclusive!",
            "(Signature ID: S0) - The best-signature-time is not before the expiration date of the signing certificate!",
            "(Signature ID: S0) - The past signature validation is not conclusive!"
    );
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
    ContainerValidationResult test = container.validate();
    Assert.assertTrue(test.isValid());
  }

  @Test
  public void bdocTM_noOcspCertificateInSignature_OcspCertificateInOcspToken_shouldBeValid() {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    Container container = ContainerBuilder.aContainer().
            fromExistingFile("src/test/resources/testFiles/valid-containers/NoAdditionalOcspCertificate.bdoc").
            withConfiguration(configuration)
            .build();
    ContainerValidationResult test = container.validate();
    Assert.assertTrue(test.isValid());
  }

  @Test
  public void bdocTM_noOcspCertificateInSignatureNorInOcspToken_shouldBeInvalid() {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    Container container = ContainerBuilder.aContainer().
            fromExistingFile("src/test/resources/testFiles/invalid-containers/NoOcspCertificateAnywhere.bdoc").
            withConfiguration(configuration)
            .build();
    ContainerValidationResult test = container.validate();
    Assert.assertFalse(test.isValid());
    Assert.assertEquals(0, test.getContainerErrors().size());
    Assert.assertEquals(1, test.getErrors().size());
    TestAssert.assertContainsError("OCSP Responder does not meet TM requirements", test.getErrors());
  }

  @Test
  public void asiceLT_noAdditionalCertificatesInSignature_shouldBeValid() {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    Container container = ContainerBuilder.aContainer().
            fromExistingFile("src/test/resources/testFiles/valid-containers/NoAdditionalCertificates_LT.asice").
            withConfiguration(configuration)
            .build();
    ContainerValidationResult result = container.validate();
    TestAssert.assertContainerIsValid(result);
    assertHasNoWarnings(result);
  }

  @Test
  public void asiceLT_noOcspCertificateInSignatureNorInOcspTokenButInTsl_shouldBeValid() {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    addCertificateToTSL(Paths.get("src/test/resources/testFiles/certs/SK_TSA.pem.crt"), configuration.getTSL());
    Container container = ContainerBuilder.aContainer().
            fromExistingFile("src/test/resources/testFiles/valid-containers/NoOcspCertificateAnywhere_LT_liveTS.asice").
            withConfiguration(configuration)
            .build();
    ContainerValidationResult test = container.validate();
    Assert.assertTrue(test.isValid());
  }

  @Test
  public void signaturesWithCrlShouldBeInvalid() throws Exception {
    SignatureValidationResult result = this.openContainerByConfiguration(
        Paths.get("src/test/resources/prodFiles/invalid-containers/asic-with-crl-and-without-ocsp.asice"),
        PROD_CONFIGURATION)
        .validate();
    Assert.assertFalse(result.isValid());
    TestAssert.assertContainsError(UntrustedRevocationSourceException.class, result.getErrors());
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
    Container container = openContainerByConfiguration(Paths.get("src/test/resources/prodFiles/invalid-containers/bdoc21-vigane-ocsp.bdoc"), PROD_CONFIGURATION);
    ContainerValidationResult result = container.validate();
    TestAssert.assertContainsExactSetOfErrors(result.getErrors(),
            "The certificate validation is not conclusive!",
            "No revocation data found for the certificate!",
            "The certificate is not related to a qualified certificate issuing trust service with valid status!"
    );
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
    TestAssert.assertContainerIsValid(this.openContainerByConfiguration(
        Paths.get("src/test/resources/prodFiles/valid-containers/IB-4185_bdoc21_TM_mimetype_with_BOM_PROD.bdoc"),
        PROD_CONFIGURATION));
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
    TestAssert.assertContainerIsValid(container);
  }

  @Test
  public void mixTSLCertAndTSLOnlineSources_SignatureTypeLT_notValid() throws Exception {
    TSLCertificateSource certificateSource = new TSLCertificateSourceImpl();
    try (InputStream inputStream = new FileInputStream("src/test/resources/testFiles/certs/exampleCA.cer")) {
      X509Certificate certificate = DSSUtils.loadCertificate(inputStream).getCertificate();
      certificateSource.addTSLCertificate(certificate);
      certificateSource.addTSLCertificate(DSSUtils
          .loadCertificate(new FileInputStream("src/test/resources/testFiles/certs/TEST_of_SK_OCSP_RESPONDER_2020.der.cer"))
          .getCertificate());
    }
    this.configuration.setTSL(certificateSource);
    Container container = this.createNonEmptyContainerByConfiguration();
    this.createSignatureBy(container, SignatureProfile.LT,
        new PKCS12SignatureToken("src/test/resources/testFiles/p12/user_one.p12", "user_one".toCharArray()));
    SignatureValidationResult result = container.validate();
    List<Signature> signatureList = container.getSignatures();
    Signature signature = signatureList.get(0);
    String signatureId = signature.getId();
    Assert.assertFalse(result.isValid());
    TestAssert.assertContainsExactSetOfErrors(result.getErrors(),
            "(Signature ID: " + signatureId + ") - The certificate chain for time-stamp is not trusted, it does not contain a trust anchor.",
            "(Signature ID: " + signatureId + ") - Unable to build a certificate chain up to a trusted list!",
            "(Signature ID: " + signatureId + ") - Signature has an invalid timestamp"
    );
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
  public void validateBDocTs_Invalid() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/prodFiles/invalid-containers/bdoc21-ts-ok.bdoc", PROD_CONFIGURATION);
    SignatureValidationResult result = container.validate();
    Assert.assertFalse(result.isValid());
    TestAssert.assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(result.getErrors(), 8,
            "The certificate chain for time-stamp is not trusted, it does not contain a trust anchor.",
            "Signature has an invalid timestamp",
            "The certificate validation is not conclusive!",
            "The certificate is not related to a qualified certificate issuing trust service with valid status!",
            "No revocation data found for the certificate!",
            "The time-stamp message imprint is not intact!",
            "Unable to build a certificate chain up to a trusted list!",
            "Manifest file has an entry for file <build.xml> with mimetype <text/xml> but the " +
            "signature file for signature S0 indicates the mimetype is <>"
    );
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
  @Ignore("DD4J-978 Lithuanian trusted list is temporarily unusable")
  public void prodContainerWithSignatureWarningOfTrustedCertificateNotMatchingWithTrustService_warningIsRemoved() {
    Container container = ContainerBuilder.aContainer().
            fromExistingFile("src/test/resources/prodFiles/valid-containers/Baltic MoU digital signing_EST_LT_LV.bdoc").
            withConfiguration(PROD_CONFIGURATION).build();
    ContainerValidationResult validationResult = container.validate();
    TestAssert.assertContainerIsValid(validationResult);
    I18nProvider i18nProvider = new I18nProvider();
    assertThat(validationResult.getWarnings(), not(hasItem(
            digiDoc4JExceptionMessageContainsString(i18nProvider.getMessage(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1))
    )));
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
    TestAssert.assertContainerIsValid(validationResult);
    I18nProvider i18nProvider = new I18nProvider();
    assertThat(validationResult.getWarnings(), not(hasItem(
            digiDoc4JExceptionMessageContainsString(i18nProvider.getMessage(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2))
    )));
  }

  @Test
  public void container_withTimestampTakenWhenSigningCertificateWasNotValid_shouldBeInvalid() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/signing_certificate_not_valid_during_timestamping.asice");
    SignatureValidationResult result = container.validate();
    Assert.assertFalse("Signature must not be valid when timestamp was taken while signing certificate was not valid", result.isValid());
    TestAssert.assertContainsExactSetOfErrors(result.getErrors(),
            "The best-signature-time is not before the expiration date of the signing certificate!",
            "The past signature validation is not conclusive!",
            "The current time is not in the validity range of the signer's certificate!",
            "The certificate validation is not conclusive!"
    );
  }

  @Test
  public void container_withOcspBeforeTS_shouldBeInvalid() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/TS-08_23634_TS_OCSP_before_TS.asice");
    SignatureValidationResult result = container.validate();
    Assert.assertFalse("Signature must not be valid when OCSP was taken before timestamp", result.isValid());
    Assert.assertTrue("Result errors must contain " + TimestampAfterOCSPResponseTimeException.class.getSimpleName(),
            result.getErrors().stream().anyMatch(e -> e instanceof TimestampAfterOCSPResponseTimeException));
  }

  @Test
  public void container_withPssSignature_shouldBeValid(){
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/PSS-signature.asice");
    TestAssert.assertContainerIsValid(container);
  }

  @Test
  public void container_withExpiredAIAOCSP_LT_shouldBeInvalid() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/esteid2018signerAiaOcspLT.asice");
    ContainerValidationResult validationResult = container.validate();
    Assert.assertFalse("Signature must not be valid when AIA OCSP expired", validationResult.isValid());
    TestAssert.assertContainsErrors(validationResult.getErrors(),
            "The certificate validation is not conclusive!",
            "No acceptable revocation data for the certificate!",
            "The revocation data is not consistent!"
    );
    TestAssert.assertContainsExactSetOfErrors(validationResult.getWarnings(),
            "The signature/seal is an INDETERMINATE AdES digital signature!"
    );
  }

  @Test
  public void container_withExpiredAIAOCSP_LTA_shouldBeInvalid() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/invalid-containers/esteid2018signerAiaOcspLTA.asice");
    ContainerValidationResult validationResult = container.validate();
    Assert.assertFalse("Signature must not be valid when AIA OCSP expired", validationResult.isValid());
    TestAssert.assertContainsExactSetOfErrors(validationResult.getErrors(),
            "The certificate validation is not conclusive!",
            "No acceptable revocation data for the certificate!",
            "The revocation data is not consistent!"
    );
    TestAssert.assertContainsExactSetOfErrors(validationResult.getWarnings(),
            "The signature/seal is an INDETERMINATE AdES digital signature!"
    );
  }

  @Test
  public void container_withMultipleEncapsulatedTimestampsInSingleSignatureTimeStamp_shouldBeInvalid() {
    DSSException caughtException = assertThrows(
            DSSException.class,
            () -> ContainerOpener.open("src/test/resources/testFiles/invalid-containers/multiple_EncapsulatedTimeStamp_elements_in_single_SignatureTimeStamp.asice", configuration)
    );
    Assert.assertEquals(
            "More than one result for XPath: ./xades132:EncapsulatedTimeStamp",
            caughtException.getMessage()
    );
  }

  @Test
  public void container_withMultipleEncapsulatedTimestampsInSecondSignatureTimeStamp_shouldBeInvalid() {
    DSSException caughtException = assertThrows(
            DSSException.class,
            () -> ContainerOpener.open("src/test/resources/testFiles/invalid-containers/multiple_EncapsulatedTimeStamp_elements_in_second_SignatureTimeStamp.asice", configuration)
    );
    Assert.assertEquals(
            "More than one result for XPath: ./xades132:EncapsulatedTimeStamp",
            caughtException.getMessage()
    );
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
  }

}
