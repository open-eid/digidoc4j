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

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.OCSPSourceFactory;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.impl.CommonOCSPSource;
import org.digidoc4j.impl.OcspDataLoaderFactory;
import org.digidoc4j.impl.SKOnlineOCSPSource;
import org.digidoc4j.impl.asic.AsicContainer;
import org.digidoc4j.impl.asic.AsicSignature;
import org.digidoc4j.test.TestAssert;
import org.digidoc4j.test.util.DssContainerSigner;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static java.lang.Thread.sleep;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.anEmptyMap;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;

class ExtendingAsicContainerTest extends AbstractTest {

  private static final String B_EPES_CONTAINER_PATH = "src/test/resources/testFiles/valid-containers/bdoc-with-b-epes-signature.bdoc";
  private static final String LT_TM_CONTAINER_PATH = "src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc";
  private static final String ASICE_LTA_CONTAINER_PATH = "src/test/resources/testFiles/valid-containers/valid-asice-lta.asice";
  private static final String ASICE_LT_2_SIGNATURES_CONTAINER_PATH = "src/test/resources/testFiles/valid-containers/2_signatures_duplicate_id.asice";
  private static final String ASICE_LTA_2_SIGNATURES_CONTAINER_PATH = "src/test/resources/testFiles/valid-containers/2_signatures_duplicate_id_lta.asice";
  private static final String ASICE_LT_WITH_EXPIRED_SIGNER_AND_TS_AND_OCSP = "src/test/resources/testFiles/valid-containers/asice_single_signature_with_expired_signer_and_ts_and_ocsp_certificates.asice";

  private String containerLocation;

  @Test
  void validate_WhenNonEstonianSignatureExtendedFromTToLTAfter24h_WarningIsRaised() {
    configuration = createLatvianSignatureConfiguration();
    configuration.setExtendingOcspSourceFactory(this::getOcspSource);

    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/latvian_T_signature.asice",
            configuration);

    validateAndExtend(container, SignatureProfile.LT);

    assertEquals(1, container.getSignatures().size());
    Signature signature = container.getSignatures().get(0);

    assertNotNull(signature.getOCSPCertificate());
    assertEquals(SignatureProfile.LT, signature.getProfile());
    ContainerValidationResult validationResult = container.validate();
    assertTrue(validationResult.isValid());
    assertEquals(0, validationResult.getErrors().size());
    TestAssert.assertContainsExactSetOfErrors(validationResult.getWarnings(),
            "The time difference between the signature timestamp and the OCSP response exceeds 15 minutes, rendering the OCSP response not 'fresh'."
    );
  }

  @Test
  void extendEstonianSignatureFromTToLT_After24h_ExtensionSucceedsWithValidationWarning() {
    setupCustomConfigurationWithExtendingOcspSourceFactory();

    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/signature-level-T.asice",
            configuration);

    validateAndExtend(container, SignatureProfile.LT);

    assertEquals(1, container.getSignatures().size());
    Signature signature = container.getSignatures().get(0);
    assertNotNull(signature.getOCSPCertificate());
    assertEquals(SignatureProfile.LT, signature.getProfile());
    ContainerValidationResult validationResult = container.validate();
    TestAssert.assertContainerIsValid(container);
    TestAssert.assertContainsExactSetOfErrors(validationResult.getWarnings(),
            "(Signature ID: id-aa0954fdd331fdf45324f117e2453a1e) - The time difference between the signature timestamp and the OCSP response exceeds 15 minutes, rendering the OCSP response not 'fresh'."
    );
  }

  @Test
  void extendFromB_BESToLT_OcspSourceFactoryDefinedInConf_Success() {
    setupCustomConfigurationWithExtendingOcspSourceFactory();

    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);
    container.saveAsFile(containerLocation);

    assertEquals(1, container.getSignatures().size());
    assertNull(container.getSignatures().get(0).getOCSPCertificate());

    container = TestDataBuilderUtil.open(containerLocation, configuration);
    validateAndExtend(container, SignatureProfile.LT);
    container.saveAsFile(getFileBy("bdoc"));

    assertEquals(1, container.getSignatures().size());
    Signature signature = container.getSignatures().get(0);

    assertNotNull(signature.getOCSPCertificate());
    assertEquals(SignatureProfile.LT, signature.getProfile());
    assertTrue(container.validate().isValid());
  }

  @Test
  void extendFromB_BESToLT_OcspSourceFactoryDefinedInConf_OcspUnset() {
    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);
    container.saveAsFile(containerLocation);

    assertEquals(1, container.getSignatures().size());
    assertNull(container.getSignatures().get(0).getOCSPCertificate());

    container = TestDataBuilderUtil.open(containerLocation, configuration);
    validateAndExtend(container, SignatureProfile.LT);
    container.saveAsFile(getFileBy("bdoc"));

    assertEquals(1, container.getSignatures().size());
    assertNull(container.getSignatures().get(0).getOCSPCertificate());

    SignatureValidationResult result = container.validate();
    assertFalse(result.isValid());
    TestAssert.assertContainsErrors(result.getErrors(),
            "The certificate validation is not conclusive!",
            "No revocation data found for the certificate!"
    );
  }

  @Test
  void extendFromB_BESToLTA_OcspSourceFactoryDefinedInConf_Success() {
    setupCustomConfigurationWithExtendingOcspSourceFactory();

    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);
    container.saveAsFile(containerLocation);

    assertEquals(1, container.getSignatures().size());
    assertNull(container.getSignatures().get(0).getOCSPCertificate());

    container = TestDataBuilderUtil.open(containerLocation, configuration);
    validateAndExtend(container, SignatureProfile.LTA);
    container.saveAsFile(getFileBy("bdoc"));

    assertEquals(1, container.getSignatures().size());
    assertNotNull(container.getSignatures().get(0).getOCSPCertificate());
    List<TimestampToken> archiveTimestamps = getSignatureArchiveTimestamps(container, 0);
    assertEquals(1, archiveTimestamps.size(), "The signature must contain 1 archive timestamp");
  }

  @Test
  void extendFromB_BESToLTA_OcspSourceFactoryDefinedInConf_OcspUnset() {
    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);
    container.saveAsFile(containerLocation);

    assertEquals(1, container.getSignatures().size());
    assertNull(container.getSignatures().get(0).getOCSPCertificate());

    container = TestDataBuilderUtil.open(containerLocation, configuration);
    validateAndExtend(container, SignatureProfile.LTA);
    container.saveAsFile(getFileBy("bdoc"));

    assertEquals(1, container.getSignatures().size());
    assertNull(container.getSignatures().get(0).getOCSPCertificate());

    SignatureValidationResult result = container.validate();
    assertFalse(result.isValid());
    TestAssert.assertContainsErrors(result.getErrors(),
            "The certificate validation is not conclusive!",
            "No revocation data found for the certificate!"
    );
  }

  @Test
  void extendFromTToLT_OcspSourceFactoryDefinedInConf_Success() {
    setupCustomConfigurationWithExtendingOcspSourceFactory();

    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.T, pkcs12SignatureToken);
    container.saveAsFile(containerLocation);

    assertEquals(1, container.getSignatures().size());
    assertNull(container.getSignatures().get(0).getOCSPCertificate());

    container = TestDataBuilderUtil.open(containerLocation, configuration);
    validateAndExtend(container, SignatureProfile.LT);
    container.saveAsFile(getFileBy("bdoc"));

    assertEquals(1, container.getSignatures().size());
    Signature signature = container.getSignatures().get(0);

    assertNotNull(signature.getOCSPCertificate());
    assertEquals(SignatureProfile.LT, signature.getProfile());
    assertTrue(container.validate().isValid());
  }

  @Test
  void extendFromTToLT_OcspSourceFactoryUnsetInConf_OcspUnset() {
    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.T, pkcs12SignatureToken);
    container.saveAsFile(containerLocation);

    assertEquals(1, container.getSignatures().size());
    assertNull(container.getSignatures().get(0).getOCSPCertificate());

    container = TestDataBuilderUtil.open(containerLocation);
    validateAndExtend(container, SignatureProfile.LT);
    container.saveAsFile(getFileBy("bdoc"));

    assertEquals(1, container.getSignatures().size());
    assertNull(container.getSignatures().get(0).getOCSPCertificate());

    SignatureValidationResult result = container.validate();
    assertFalse(result.isValid());
    TestAssert.assertContainsErrors(result.getErrors(),
        "The certificate validation is not conclusive!",
        "No revocation data found for the certificate!"
    );
  }

  @Test
  void extendFromB_BESToLT_TM_ThrowsException() {
    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> validateAndExtend(container, SignatureProfile.LT_TM)
    );

    assertThat(caughtException.getMessage(), containsString(
            "It is not possible to extend B_BES signature to LT_TM"
    ));
  }

  @Test
  void extendFromB_EPESToLT_TM_ThrowsException() {
    Container container = ContainerOpener.open(B_EPES_CONTAINER_PATH, Configuration.of(Configuration.Mode.TEST));

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> validateAndExtend(container, SignatureProfile.LT_TM)
    );

    assertThat(caughtException.getMessage(), containsString(
            "It is not possible to extend B_EPES signature to LT_TM"
    ));
  }

  @Test
  void extendFromB_EPESToLT_ThrowsException() {
    Container container = ContainerOpener.open(B_EPES_CONTAINER_PATH, Configuration.of(Configuration.Mode.TEST));

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> validateAndExtend(container, SignatureProfile.LT)
    );

    assertThat(caughtException.getMessage(), containsString(
            "It is not possible to extend B_EPES signature to LT"
    ));
  }

  @Test
  void extendFromB_EPESToLTA_ThrowsException() {
    Container container = ContainerOpener.open(B_EPES_CONTAINER_PATH, Configuration.of(Configuration.Mode.TEST));

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> validateAndExtend(container, SignatureProfile.LTA)
    );

    assertThat(caughtException.getMessage(), containsString(
            "It is not possible to extend B_EPES signature to LTA"
    ));
  }

  @Test
  void extendFromLTToLT_TM_ThrowsException() {
    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> validateAndExtend(container, SignatureProfile.LT_TM)
    );

    assertThat(caughtException.getMessage(), containsString(
            "It is not possible to extend LT signature to LT_TM"
    ));
  }

  @Test
  void extendFromLTAToLT_TM_ThrowsException() {
    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.LTA, pkcs12SignatureToken);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> validateAndExtend(container, SignatureProfile.LT_TM)
    );

    assertThat(caughtException.getMessage(), containsString(
            "It is not possible to extend LTA signature to LT_TM"
    ));
  }

  @Test
  void extendFromLTToB_BES_ThrowsException() {
    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> validateAndExtend(container, SignatureProfile.B_BES)
    );

    assertThat(caughtException.getMessage(), containsString(
            "It is not possible to extend LT signature to B_BES"
    ));
  }

  @Test
  void extendFromLTToB_EPES_ThrowsException() {
    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> validateAndExtend(container, SignatureProfile.B_EPES)
    );

    assertThat(caughtException.getMessage(), containsString(
            "It is not possible to extend LT signature to B_EPES"
    ));
  }

  @Test
  void extendFromLT_TMToLT_ThrowsException() {
    Container container = ContainerOpener.open(LT_TM_CONTAINER_PATH, Configuration.of(Configuration.Mode.TEST));

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> validateAndExtend(container, SignatureProfile.LT)
    );

    assertThat(caughtException.getMessage(), containsString(
            "It is not possible to extend LT_TM signature to LT"
    ));
  }

  @Test
  void extendFromLT_TMToLTA_ThrowsException() {
    Container container = ContainerOpener.open(LT_TM_CONTAINER_PATH, Configuration.of(Configuration.Mode.TEST));

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> validateAndExtend(container, SignatureProfile.LTA)
    );

    assertThat(caughtException.getMessage(), containsString(
            "It is not possible to extend LT_TM signature to LTA"
    ));
  }

  @Test
  void extendToWhenConfirmationAlreadyExists() {
    setupCustomConfigurationWithExtendingOcspSourceFactory();

    Container initialContainer = createNonEmptyContainer();
    createSignatureBy(initialContainer, SignatureProfile.B_BES, pkcs12SignatureToken);
    initialContainer.saveAsFile(containerLocation);

    assertEquals(1, initialContainer.getSignatures().size());
    assertNull(initialContainer.getSignatures().get(0).getOCSPCertificate());

    Container deserializedContainer = TestDataBuilderUtil.open(containerLocation, configuration);
    deserializedContainer.extendSignatureProfile(SignatureProfile.LT);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> validateAndExtend(deserializedContainer, SignatureProfile.LT)
    );

    assertThat(caughtException.getMessage(), containsString(
            "It is not possible to extend LT signature to LT"
    ));
  }

  @Test
  void extendToWithMultipleSignatures() {
    setupCustomConfigurationWithExtendingOcspSourceFactory();

    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);
    createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);
    container.saveAsFile(containerLocation);

    assertEquals(2, container.getSignatures().size());
    assertNull(container.getSignatures().get(0).getOCSPCertificate());
    assertNull(container.getSignatures().get(1).getOCSPCertificate());

    container = TestDataBuilderUtil.open(containerLocation, configuration);
    validateAndExtend(container, SignatureProfile.LT);
    String containerPath = getFileBy("bdoc");
    container.saveAsFile(containerPath);

    container = TestDataBuilderUtil.open(containerPath);

    assertEquals(2, container.getSignatures().size());
    assertNotNull(container.getSignatures().get(0).getOCSPCertificate());
    assertNotNull(container.getSignatures().get(1).getOCSPCertificate());
    assertTrue(container.validate().isValid());
  }

  @Test
  void extendToWithMultipleSignaturesAndMultipleFiles() {
    setupCustomConfigurationWithExtendingOcspSourceFactory();

    Container container = createNonEmptyContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.xml", "text/xml");
    createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);
    createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);
    container.saveAsFile(containerLocation);

    assertEquals(2, container.getSignatures().size());
    assertEquals(2, container.getDataFiles().size());
    assertNull(container.getSignatures().get(0).getOCSPCertificate());
    assertNull(container.getSignatures().get(1).getOCSPCertificate());

    container = TestDataBuilderUtil.open(containerLocation, configuration);
    validateAndExtend(container, SignatureProfile.LT);
    container.saveAsFile(getFileBy("bdoc"));

    assertEquals(2, container.getSignatures().size());
    assertEquals(2, container.getDataFiles().size());
    assertNotNull(container.getSignatures().get(0).getOCSPCertificate());
    assertNotNull(container.getSignatures().get(1).getOCSPCertificate());
    assertTrue(container.validate().isValid());
  }

  @Test
  void testContainerExtensionFromNewLTtoLTA() throws InterruptedException {
    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken);
    sleep(1100);

    validateAndExtend(container, SignatureProfile.LTA);

    assertNotNull(container.getSignatures().get(0).getOCSPCertificate());
    TestAssert.assertContainerIsValid(container);
    List<TimestampToken> archiveTimestamps = getSignatureArchiveTimestamps(container, 0);
    assertEquals(1, archiveTimestamps.size(), "The signature must contain 1 archive timestamp");
  }

  @Test
  void testContainerExtensionFromExistingLTtoLTA() {
    Container container = ContainerOpener
            .open("src/test/resources/testFiles/valid-containers/valid-asice-esteid2018.asice");

    validateAndExtend(container, SignatureProfile.LTA);

    assertNotNull(container.getSignatures().get(0).getOCSPCertificate());
    TestAssert.assertContainerIsValid(container);
    List<TimestampToken> archiveTimestamps = getSignatureArchiveTimestamps(container, 0);
    assertEquals(1, archiveTimestamps.size(), "The signature must contain 1 archive timestamp");
  }

  @Test
  void testContainerExtensionFromExpiredLTtoLTAFails() {
    Container container = ContainerOpener
            .open("src/test/resources/testFiles/valid-containers/valid-asice.asice");

    AlertException caughtException = assertThrows(
            AlertException.class,
            () -> validateAndExtend(container, SignatureProfile.LTA)
    );

    assertThat(caughtException.getMessage(), containsString("Expired signature found"));
    TestAssert.assertContainerIsValid(container);
    List<TimestampToken> archiveTimestamps = getSignatureArchiveTimestamps(container, 0);
    assertEquals(0, archiveTimestamps.size(), "The signature must contain no archive timestamp");
  }

  @Test
  void testExtendingExpiredSignaturesFromLTtoLTAFails() {
    Container container = ContainerOpener.open(ASICE_LT_WITH_EXPIRED_SIGNER_AND_TS_AND_OCSP, Configuration.of(Configuration.Mode.TEST));
    Signature signature1 = container.getSignatures().get(0);

    AlertException caughtException = assertThrows(
            AlertException.class,
            () -> validateAndExtend(container, SignatureProfile.LTA, signature1)
    );

    assertThat(caughtException.getMessage(), containsString("Expired signature found"));
    TestAssert.assertContainerIsValid(container);
    List<TimestampToken> archiveTimestamps = getSignatureArchiveTimestamps(container, 0);
    assertEquals(0, archiveTimestamps.size(), "The signature must contain no archive timestamp");
  }

  @Test
  void testExtendingSignatureWithInvalidDatafileReferenceFromLTtoLTAFails() {
    Container container = ContainerOpener.open(ASICE_INVALID_SIGNATURE_DOES_NOT_COVER_DATAFILE, Configuration.of(Configuration.Mode.TEST));
    Signature signature = container.getSignatures().get(0);

    AlertException caughtException = assertThrows(
            AlertException.class,
            () -> validateAndExtend(container, SignatureProfile.LTA, signature)
    );

    assertThat(caughtException.getMessage(), containsString("Error on signature augmentation."));
    assertThat(caughtException.getMessage(),
            containsString("Cryptographic signature verification has failed / Signature verification failed against the best candidate."));
    TestAssert.assertContainerIsInvalid(container);
    List<TimestampToken> archiveTimestamps = getSignatureArchiveTimestamps(container, 0);
    assertEquals(0, archiveTimestamps.size(), "The signature must contain no archive timestamp");
  }

  @Test
  void testContainerExtensionFromLTAtoLTA() {
    Container container = ContainerOpener.open(ASICE_LTA_CONTAINER_PATH, Configuration.of(Configuration.Mode.TEST));

    validateAndExtend(container, SignatureProfile.LTA);

    TestAssert.assertContainerIsValid(container);
    assertEquals(1, container.getSignatures().size());
    List<TimestampToken> archiveTimestamps = getSignatureArchiveTimestamps(container, 0);
    assertEquals(2, archiveTimestamps.size(), "The signature must contain 2 archive timestamps");
  }

  @Test
  void testExtendingSelectedSignaturesFromLTtoLTA() {
    Container container = ContainerOpener.open(ASICE_LT_2_SIGNATURES_CONTAINER_PATH, Configuration.of(Configuration.Mode.TEST));
    Signature signature1 = container.getSignatures().get(0);

    validateAndExtend(container, SignatureProfile.LTA, singletonList(signature1));

    TestAssert.assertContainerIsValid(container);
    assertEquals(2, container.getSignatures().size());
    assertEquals(SignatureProfile.LTA, container.getSignatures().get(0).getProfile(), "1st signature's profile must be LTA");
    assertEquals(SignatureProfile.LT, container.getSignatures().get(1).getProfile(), "2nd signature's profile must be LT");
    List<TimestampToken> signature1Timestamps = getSignatureArchiveTimestamps(container, 0);
    assertEquals(1, signature1Timestamps.size(), "The 1st signature must contain 1 archive timestamp");
    List<TimestampToken> signature2Timestamps = getSignatureArchiveTimestamps(container, 1);
    assertEquals(0, signature2Timestamps.size(), "The 2nd signature must not contain any archive timestamps");
  }

  @Test
  void testSelectAllSignaturesForExtendingFromLTtoLTA() {
    Container container = ContainerOpener.open(ASICE_LT_2_SIGNATURES_CONTAINER_PATH, Configuration.of(Configuration.Mode.TEST));
    Signature signature1 = container.getSignatures().get(0);
    Signature signature2 = container.getSignatures().get(1);

    validateAndExtend(container, SignatureProfile.LTA, Arrays.asList(signature1, signature2));

    TestAssert.assertContainerIsValid(container);
    assertEquals(2, container.getSignatures().size());
    assertEquals(SignatureProfile.LTA, container.getSignatures().get(0).getProfile(), "1st signature's profile must be LTA");
    assertEquals(SignatureProfile.LTA, container.getSignatures().get(1).getProfile(), "2nd signature's profile must be LTA");
    List<TimestampToken> signature1Timestamps = getSignatureArchiveTimestamps(container, 0);
    assertEquals(1, signature1Timestamps.size(), "The 1st signature must contain 1 archive timestamp");
    List<TimestampToken> signature2Timestamps = getSignatureArchiveTimestamps(container, 1);
    assertEquals(1, signature2Timestamps.size(), "The 2nd signature must contain 1 archive timestamp");
  }

  private static void validateAndExtend(Container container, SignatureProfile targetProfile) {
    validateAndExtend(container, targetProfile, container.getSignatures());
  }

  private static void validateAndExtend(Container container, SignatureProfile targetProfile, Signature signature) {
    validateAndExtend(container, targetProfile, singletonList(signature));
  }

  private static void validateAndExtend(Container container, SignatureProfile targetProfile, List<Signature> signatures) {
    // Validate and save exceptions to map
    Map<String, DigiDoc4JException> validationErrors = ((AsicContainer) container).getExtensionValidationErrors(targetProfile, signatures);
    try {
      // Try real extending and catch the exception if thrown
      container.extendSignatureProfile(targetProfile, signatures);
    } catch (Exception e) {
      Throwable firstValidationError = findFirstValidationError(validationErrors, signatures);
      // Ensure the thrown exception is the same which was returned by validation of the first signature
      assertEquals(firstValidationError.getClass(), e.getClass(), "The cause of the validation exception must be of the same type as the exception thrown on extending");
      assertEquals(firstValidationError.getMessage(), e.getMessage(), "The cause of the validation exception must have the same error message as the exception thrown on extending");
      throw e;
    }
    assertThat("Validation returned exceptions, but extension succeeded", validationErrors, is(anEmptyMap()));
  }

  private static Throwable findFirstValidationError(Map<String, DigiDoc4JException> validationErrors, List<Signature> signatures) {
    for (Signature signature : signatures) {
      DigiDoc4JException signatureException = validationErrors.get(signature.getUniqueId());
      if (signatureException == null) {
        continue;
      }
      // If profile extendability validation failed, NotSupportedException is thrown,
      // which is not further wrapped into DigiDoc4JException
      if (signatureException instanceof NotSupportedException) {
        return signatureException;
      } else {
        // If DSS validation failed, AlertException is thrown,
        // which is wrapped into DigiDoc4JException as its cause
        return signatureException.getCause();
      }
    }
    throw new RuntimeException("Error: Could not find the first validation error");
  }

  @Test
  void testExtendingSelectedSignaturesFromLTAtoLTA() {
    Container container = ContainerOpener.open(ASICE_LTA_2_SIGNATURES_CONTAINER_PATH, Configuration.of(Configuration.Mode.TEST));
    Signature signature2 = container.getSignatures().get(1);

    validateAndExtend(container, SignatureProfile.LTA, singletonList(signature2));

    TestAssert.assertContainerIsValid(container);
    assertEquals(2, container.getSignatures().size());
    List<TimestampToken> signature1Timestamps = getSignatureArchiveTimestamps(container, 0);
    assertEquals(1, signature1Timestamps.size(), "The 1st signature must contain 1 archive timestamp");
    List<TimestampToken> signature2Timestamps = getSignatureArchiveTimestamps(container, 1);
    assertEquals(2, signature2Timestamps.size(), "The 2nd signature must contain 2 archive timestamps");
  }

  @Test
  void extensionNotPossibleFromLTtoLT() {
    Container container = createNonEmptyContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> validateAndExtend(container, SignatureProfile.LT)
    );

    assertThat(caughtException.getMessage(), containsString(
            "It is not possible to extend LT signature to LT"
    ));
  }

  @Test
  void testCustomOcspSourceUsedForExtendingSignature() {
    configuration = Configuration.of(Configuration.Mode.TEST);
    SKOnlineOCSPSource sourceSpy = (SKOnlineOCSPSource) Mockito.spy(getOcspSource());
    OCSPSourceFactory ocspSourceFactoryMock = Mockito.mock(OCSPSourceFactory.class);
    Mockito.doReturn(sourceSpy).when(ocspSourceFactoryMock).create();
    configuration.setExtendingOcspSourceFactory(ocspSourceFactoryMock);

    Container container = createNonEmptyContainerByConfiguration();
    createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);
    validateAndExtend(container, SignatureProfile.LT);

    assertValidSignature(container.getSignatures().get(0));
    Mockito.verify(ocspSourceFactoryMock, Mockito.times(1)).create();
    Mockito.verifyNoMoreInteractions(ocspSourceFactoryMock);
    Mockito.verify(sourceSpy, Mockito.atLeast(1))
            .getRevocationToken(any(CertificateToken.class), any(CertificateToken.class));
  }

  @Test
  void extendAsicsContainerFromLTtoLTA() {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    DssContainerSigner containerSigner = new DssContainerSigner(configuration);
    DSSDocument dataFile = new InMemoryDocument(
            "This is a test file.".getBytes(StandardCharsets.UTF_8),
            "test.txt",
            MimeTypeEnum.TEXT
    );
    DSSDocument dssContainer = containerSigner.createSignedContainer(
            ASiCContainerType.ASiC_S,
            Collections.singletonList(dataFile),
            SignatureLevel.XAdES_BASELINE_LT,
            pkcs12Esteid2018SignatureToken
    );
    Container container = ContainerOpener.open(dssContainer.openStream(), configuration);

    validateAndExtend(container, SignatureProfile.LTA);

    assertNotNull(container.getSignatures().get(0).getOCSPCertificate());
    ContainerValidationResult validationResult = container.validate();
    TestAssert.assertContainerIsValid(validationResult);
    assertThat(validationResult.getErrors(), empty());
    assertThat(validationResult.getContainerErrors(), empty());
    assertThat(validationResult.getWarnings(), empty());
    assertThat(validationResult.getContainerWarnings(), empty());
    List<TimestampToken> archiveTimestamps = getSignatureArchiveTimestamps(container, 0);
    assertEquals(1, archiveTimestamps.size(), "The signature must contain 1 archive timestamp");
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    containerLocation = getFileBy("bdoc");
  }

  private void setupCustomConfigurationWithExtendingOcspSourceFactory() {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    configuration.setExtendingOcspSourceFactory(this::getOcspSource);
    this.configuration = configuration;
  }

  private OCSPSource getOcspSource() {
    SKOnlineOCSPSource source = new CommonOCSPSource(configuration);
    DataLoader loader = new OcspDataLoaderFactory(configuration).create();
    source.setDataLoader(loader);
    return source;
  }

  private List<TimestampToken> getSignatureArchiveTimestamps(Container container, int signatureIndex) {
    return ((AsicSignature) container.getSignatures().get(signatureIndex)).getOrigin().getDssSignature().getArchiveTimestamps();
  }

}
