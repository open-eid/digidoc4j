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
import org.junit.Assert;
import org.junit.Test;
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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;

public class ExtendingAsicContainerTest extends AbstractTest {

  private static final String B_EPES_CONTAINER_PATH = "src/test/resources/testFiles/valid-containers/bdoc-with-b-epes-signature.bdoc";
  private static final String LT_TM_CONTAINER_PATH = "src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc";
  private static final String ASICE_LTA_CONTAINER_PATH = "src/test/resources/testFiles/valid-containers/valid-asice-lta.asice";
  private static final String ASICE_LT_2_SIGNATURES_CONTAINER_PATH = "src/test/resources/testFiles/valid-containers/2_signatures_duplicate_id.asice";
  private static final String ASICE_LTA_2_SIGNATURES_CONTAINER_PATH = "src/test/resources/testFiles/valid-containers/2_signatures_duplicate_id_lta.asice";
  private static final String ASICE_LT_WITH_EXPIRED_SIGNER_AND_TS_AND_OCSP = "src/test/resources/testFiles/valid-containers/asice_single_signature_with_expired_signer_and_ts_and_ocsp_certificates.asice";

  private String containerLocation;

  @Test
  public void extendNonEstonianSignatureFromTToLT_After24h_ExtensionAndValidationSucceed() {
    configuration = createLatvianSignatureConfiguration();
    configuration.setExtendingOcspSourceFactory(this::getOcspSource);

    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/latvian_T_signature.asice",
            configuration);

    validateAndExtend(container, SignatureProfile.LT);

    Assert.assertEquals(1, container.getSignatures().size());
    Signature signature = container.getSignatures().get(0);

    Assert.assertNotNull(signature.getOCSPCertificate());
    Assert.assertEquals(SignatureProfile.LT, signature.getProfile());
    ContainerValidationResult validationResult = container.validate();
    Assert.assertTrue(validationResult.isValid());
    Assert.assertEquals(0, validationResult.getErrors().size());
    Assert.assertEquals(0, validationResult.getWarnings().size());
  }

  @Test
  public void extendEstonianSignatureFromTToLT_After24h_ExtensionSucceedsButValidationFails() {
    setupCustomConfigurationWithExtendingOcspSourceFactory();

    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/signature-level-T.asice",
            configuration);

    validateAndExtend(container, SignatureProfile.LT);

    Assert.assertEquals(1, container.getSignatures().size());
    Signature signature = container.getSignatures().get(0);
    Assert.assertNotNull(signature.getOCSPCertificate());
    Assert.assertEquals(SignatureProfile.LT, signature.getProfile());
    ContainerValidationResult validationResult = container.validate();
    Assert.assertFalse(validationResult.isValid());
    Assert.assertEquals(0, validationResult.getWarnings().size());
    Assert.assertEquals(1, validationResult.getErrors().size());
    Assert.assertEquals("(Signature ID: id-aa0954fdd331fdf45324f117e2453a1e) - The difference between the OCSP response time and the signature timestamp is too large", validationResult.getErrors().get(0).toString());
  }

  @Test
  public void extendFromB_BESToLT_OcspSourceFactoryDefinedInConf_Success() {
    setupCustomConfigurationWithExtendingOcspSourceFactory();

    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);
    container.saveAsFile(containerLocation);

    Assert.assertEquals(1, container.getSignatures().size());
    Assert.assertNull(container.getSignatures().get(0).getOCSPCertificate());

    container = TestDataBuilderUtil.open(containerLocation, configuration);
    validateAndExtend(container, SignatureProfile.LT);
    container.saveAsFile(getFileBy("bdoc"));

    Assert.assertEquals(1, container.getSignatures().size());
    Signature signature = container.getSignatures().get(0);

    Assert.assertNotNull(signature.getOCSPCertificate());
    Assert.assertEquals(SignatureProfile.LT, signature.getProfile());
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void extendFromB_BESToLT_OcspSourceFactoryDefinedInConf_OcspUnset() {
    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);
    container.saveAsFile(containerLocation);

    Assert.assertEquals(1, container.getSignatures().size());
    Assert.assertNull(container.getSignatures().get(0).getOCSPCertificate());

    container = TestDataBuilderUtil.open(containerLocation, configuration);
    validateAndExtend(container, SignatureProfile.LT);
    container.saveAsFile(getFileBy("bdoc"));

    Assert.assertEquals(1, container.getSignatures().size());
    Assert.assertNull(container.getSignatures().get(0).getOCSPCertificate());

    SignatureValidationResult result = container.validate();
    Assert.assertFalse(result.isValid());
    TestAssert.assertContainsErrors(result.getErrors(),
            "The certificate validation is not conclusive!",
            "No revocation data found for the certificate!"
    );
  }

  @Test
  public void extendFromB_BESToLTA_OcspSourceFactoryDefinedInConf_Success() {
    setupCustomConfigurationWithExtendingOcspSourceFactory();

    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);
    container.saveAsFile(containerLocation);

    Assert.assertEquals(1, container.getSignatures().size());
    Assert.assertNull(container.getSignatures().get(0).getOCSPCertificate());

    container = TestDataBuilderUtil.open(containerLocation, configuration);
    validateAndExtend(container, SignatureProfile.LTA);
    container.saveAsFile(getFileBy("bdoc"));

    Assert.assertEquals(1, container.getSignatures().size());
    Assert.assertNotNull(container.getSignatures().get(0).getOCSPCertificate());
    List<TimestampToken> archiveTimestamps = getSignatureArchiveTimestamps(container, 0);
    assertEquals("The signature must contain 1 archive timestamp", 1, archiveTimestamps.size());
  }

  @Test
  public void extendFromB_BESToLTA_OcspSourceFactoryDefinedInConf_OcspUnset() {
    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);
    container.saveAsFile(containerLocation);

    Assert.assertEquals(1, container.getSignatures().size());
    Assert.assertNull(container.getSignatures().get(0).getOCSPCertificate());

    container = TestDataBuilderUtil.open(containerLocation, configuration);
    validateAndExtend(container, SignatureProfile.LTA);
    container.saveAsFile(getFileBy("bdoc"));

    Assert.assertEquals(1, container.getSignatures().size());
    Assert.assertNull(container.getSignatures().get(0).getOCSPCertificate());

    SignatureValidationResult result = container.validate();
    Assert.assertFalse(result.isValid());
    TestAssert.assertContainsErrors(result.getErrors(),
            "The certificate validation is not conclusive!",
            "No revocation data found for the certificate!"
    );
  }

  @Test
  public void extendFromTToLT_OcspSourceFactoryDefinedInConf_Success() {
    setupCustomConfigurationWithExtendingOcspSourceFactory();

    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.T, pkcs12SignatureToken);
    container.saveAsFile(containerLocation);

    Assert.assertEquals(1, container.getSignatures().size());
    Assert.assertNull(container.getSignatures().get(0).getOCSPCertificate());

    container = TestDataBuilderUtil.open(containerLocation, configuration);
    validateAndExtend(container, SignatureProfile.LT);
    container.saveAsFile(getFileBy("bdoc"));

    Assert.assertEquals(1, container.getSignatures().size());
    Signature signature = container.getSignatures().get(0);

    Assert.assertNotNull(signature.getOCSPCertificate());
    Assert.assertEquals(SignatureProfile.LT, signature.getProfile());
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void extendFromTToLT_OcspSourceFactoryUnsetInConf_OcspUnset() {
    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.T, pkcs12SignatureToken);
    container.saveAsFile(containerLocation);

    Assert.assertEquals(1, container.getSignatures().size());
    Assert.assertNull(container.getSignatures().get(0).getOCSPCertificate());

    container = TestDataBuilderUtil.open(containerLocation);
    validateAndExtend(container, SignatureProfile.LT);
    container.saveAsFile(getFileBy("bdoc"));

    Assert.assertEquals(1, container.getSignatures().size());
    Assert.assertNull(container.getSignatures().get(0).getOCSPCertificate());

    SignatureValidationResult result = container.validate();
    Assert.assertFalse(result.isValid());
    TestAssert.assertContainsErrors(result.getErrors(),
        "The certificate validation is not conclusive!",
        "No revocation data found for the certificate!"
    );
  }

  @Test
  public void extendFromB_BESToLT_TM_ThrowsException() {
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
  public void extendFromB_EPESToLT_TM_ThrowsException() {
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
  public void extendFromB_EPESToLT_ThrowsException() {
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
  public void extendFromB_EPESToLTA_ThrowsException() {
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
  public void extendFromLTToLT_TM_ThrowsException() {
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
  public void extendFromLTAToLT_TM_ThrowsException() {
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
  public void extendFromLTToB_BES_ThrowsException() {
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
  public void extendFromLTToB_EPES_ThrowsException() {
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
  public void extendFromLT_TMToLT_ThrowsException() {
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
  public void extendFromLT_TMToLTA_ThrowsException() {
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
  public void extendToWhenConfirmationAlreadyExists() {
    setupCustomConfigurationWithExtendingOcspSourceFactory();

    Container initialContainer = createNonEmptyContainer();
    createSignatureBy(initialContainer, SignatureProfile.B_BES, pkcs12SignatureToken);
    initialContainer.saveAsFile(containerLocation);

    Assert.assertEquals(1, initialContainer.getSignatures().size());
    Assert.assertNull(initialContainer.getSignatures().get(0).getOCSPCertificate());

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
  public void extendToWithMultipleSignatures() {
    setupCustomConfigurationWithExtendingOcspSourceFactory();

    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);
    createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);
    container.saveAsFile(containerLocation);

    Assert.assertEquals(2, container.getSignatures().size());
    Assert.assertNull(container.getSignatures().get(0).getOCSPCertificate());
    Assert.assertNull(container.getSignatures().get(1).getOCSPCertificate());

    container = TestDataBuilderUtil.open(containerLocation, configuration);
    validateAndExtend(container, SignatureProfile.LT);
    String containerPath = getFileBy("bdoc");
    container.saveAsFile(containerPath);

    container = TestDataBuilderUtil.open(containerPath);

    Assert.assertEquals(2, container.getSignatures().size());
    Assert.assertNotNull(container.getSignatures().get(0).getOCSPCertificate());
    Assert.assertNotNull(container.getSignatures().get(1).getOCSPCertificate());
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void extendToWithMultipleSignaturesAndMultipleFiles() {
    setupCustomConfigurationWithExtendingOcspSourceFactory();

    Container container = createNonEmptyContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.xml", "text/xml");
    createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);
    createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);
    container.saveAsFile(containerLocation);

    Assert.assertEquals(2, container.getSignatures().size());
    Assert.assertEquals(2, container.getDataFiles().size());
    Assert.assertNull(container.getSignatures().get(0).getOCSPCertificate());
    Assert.assertNull(container.getSignatures().get(1).getOCSPCertificate());

    container = TestDataBuilderUtil.open(containerLocation, configuration);
    validateAndExtend(container, SignatureProfile.LT);
    container.saveAsFile(getFileBy("bdoc"));

    Assert.assertEquals(2, container.getSignatures().size());
    Assert.assertEquals(2, container.getDataFiles().size());
    Assert.assertNotNull(container.getSignatures().get(0).getOCSPCertificate());
    Assert.assertNotNull(container.getSignatures().get(1).getOCSPCertificate());
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void testContainerExtensionFromNewLTtoLTA() throws InterruptedException {
    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken);
    sleep(1100);

    validateAndExtend(container, SignatureProfile.LTA);

    Assert.assertNotNull(container.getSignatures().get(0).getOCSPCertificate());
    TestAssert.assertContainerIsValid(container);
    List<TimestampToken> archiveTimestamps = getSignatureArchiveTimestamps(container, 0);
    assertEquals("The signature must contain 1 archive timestamp", 1, archiveTimestamps.size());
  }

  @Test
  public void testContainerExtensionFromExistingLTtoLTA() {
    Container container = ContainerOpener
            .open("src/test/resources/testFiles/valid-containers/valid-asice-esteid2018.asice");

    validateAndExtend(container, SignatureProfile.LTA);

    Assert.assertNotNull(container.getSignatures().get(0).getOCSPCertificate());
    TestAssert.assertContainerIsValid(container);
    List<TimestampToken> archiveTimestamps = getSignatureArchiveTimestamps(container, 0);
    assertEquals("The signature must contain 1 archive timestamp", 1, archiveTimestamps.size());
  }

  @Test
  public void testContainerExtensionFromExpiredLTtoLTAFails() {
    Container container = ContainerOpener
            .open("src/test/resources/testFiles/valid-containers/valid-asice.asice");

    AlertException caughtException = assertThrows(
            AlertException.class,
            () -> validateAndExtend(container, SignatureProfile.LTA)
    );

    assertThat(caughtException.getMessage(), containsString("Expired signature found"));
    TestAssert.assertContainerIsValid(container);
    List<TimestampToken> archiveTimestamps = getSignatureArchiveTimestamps(container, 0);
    assertEquals("The signature must contain no archive timestamp", 0, archiveTimestamps.size());
  }

  @Test
  public void testExtendingExpiredSignaturesFromLTtoLTAFails() {
    Container container = ContainerOpener.open(ASICE_LT_WITH_EXPIRED_SIGNER_AND_TS_AND_OCSP, Configuration.of(Configuration.Mode.TEST));
    Signature signature1 = container.getSignatures().get(0);

    AlertException caughtException = assertThrows(
            AlertException.class,
            () -> validateAndExtend(container, SignatureProfile.LTA, signature1)
    );

    assertThat(caughtException.getMessage(), containsString("Expired signature found"));
    TestAssert.assertContainerIsValid(container);
    List<TimestampToken> archiveTimestamps = getSignatureArchiveTimestamps(container, 0);
    assertEquals("The signature must contain no archive timestamp", 0, archiveTimestamps.size());
  }

  @Test
  public void testContainerExtensionFromLTAtoLTA() {
    Container container = ContainerOpener.open(ASICE_LTA_CONTAINER_PATH, Configuration.of(Configuration.Mode.TEST));

    validateAndExtend(container, SignatureProfile.LTA);

    TestAssert.assertContainerIsValid(container);
    Assert.assertEquals(1, container.getSignatures().size());
    List<TimestampToken> archiveTimestamps = getSignatureArchiveTimestamps(container, 0);
    assertEquals("The signature must contain 2 archive timestamps", 2, archiveTimestamps.size());
  }

  @Test
  public void testExtendingSelectedSignaturesFromLTtoLTA() {
    Container container = ContainerOpener.open(ASICE_LT_2_SIGNATURES_CONTAINER_PATH, Configuration.of(Configuration.Mode.TEST));
    Signature signature1 = container.getSignatures().get(0);

    validateAndExtend(container, SignatureProfile.LTA, singletonList(signature1));

    TestAssert.assertContainerIsValid(container);
    Assert.assertEquals(2, container.getSignatures().size());
    assertEquals("1st signature's profile must be LTA", SignatureProfile.LTA, container.getSignatures().get(0).getProfile());
    assertEquals("2nd signature's profile must be LT", SignatureProfile.LT, container.getSignatures().get(1).getProfile());
    List<TimestampToken> signature1Timestamps = getSignatureArchiveTimestamps(container, 0);
    assertEquals("The 1st signature must contain 1 archive timestamp", 1, signature1Timestamps.size());
    List<TimestampToken> signature2Timestamps = getSignatureArchiveTimestamps(container, 1);
    assertEquals("The 2nd signature must not contain any archive timestamps", 0, signature2Timestamps.size());
  }

  @Test
  public void testSelectAllSignaturesForExtendingFromLTtoLTA() {
    Container container = ContainerOpener.open(ASICE_LT_2_SIGNATURES_CONTAINER_PATH, Configuration.of(Configuration.Mode.TEST));
    Signature signature1 = container.getSignatures().get(0);
    Signature signature2 = container.getSignatures().get(1);

    validateAndExtend(container, SignatureProfile.LTA, Arrays.asList(signature1, signature2));

    TestAssert.assertContainerIsValid(container);
    Assert.assertEquals(2, container.getSignatures().size());
    assertEquals("1st signature's profile must be LTA", SignatureProfile.LTA, container.getSignatures().get(0).getProfile());
    assertEquals("2nd signature's profile must be LTA", SignatureProfile.LTA, container.getSignatures().get(1).getProfile());
    List<TimestampToken> signature1Timestamps = getSignatureArchiveTimestamps(container, 0);
    assertEquals("The 1st signature must contain 1 archive timestamp", 1, signature1Timestamps.size());
    List<TimestampToken> signature2Timestamps = getSignatureArchiveTimestamps(container, 1);
    assertEquals("The 2nd signature must contain 1 archive timestamp", 1, signature2Timestamps.size());
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
      assertEquals("The cause of the validation exception must be of the same type as the exception thrown on extending", firstValidationError.getClass(), e.getClass());
      assertEquals("The cause of the validation exception must have the same error message as the exception thrown on extending", firstValidationError.getMessage(), e.getMessage());
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
  public void testExtendingSelectedSignaturesFromLTAtoLTA() {
    Container container = ContainerOpener.open(ASICE_LTA_2_SIGNATURES_CONTAINER_PATH, Configuration.of(Configuration.Mode.TEST));
    Signature signature2 = container.getSignatures().get(1);

    validateAndExtend(container, SignatureProfile.LTA, singletonList(signature2));

    TestAssert.assertContainerIsValid(container);
    Assert.assertEquals(2, container.getSignatures().size());
    List<TimestampToken> signature1Timestamps = getSignatureArchiveTimestamps(container, 0);
    assertEquals("The 1st signature must contain 1 archive timestamp", 1, signature1Timestamps.size());
    List<TimestampToken> signature2Timestamps = getSignatureArchiveTimestamps(container, 1);
    assertEquals("The 2nd signature must contain 2 archive timestamps", 2, signature2Timestamps.size());
  }

  @Test
  public void extensionNotPossibleFromLTtoLT() {
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
  public void testCustomOcspSourceUsedForExtendingSignature() {
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
  public void extendAsicsContainerFromLTtoLTA() {
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

    Assert.assertNotNull(container.getSignatures().get(0).getOCSPCertificate());
    ContainerValidationResult validationResult = container.validate();
    TestAssert.assertContainerIsValid(validationResult);
    assertThat(validationResult.getErrors(), empty());
    assertThat(validationResult.getContainerErrors(), empty());
    assertThat(validationResult.getWarnings(), empty());
    assertThat(validationResult.getContainerWarnings(), empty());
    List<TimestampToken> archiveTimestamps = getSignatureArchiveTimestamps(container, 0);
    assertEquals("The signature must contain 1 archive timestamp", 1, archiveTimestamps.size());
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
