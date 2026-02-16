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

import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.model.tsl.ConditionForQualifiers;
import eu.europa.esig.dss.model.tsl.TrustProperties;
import eu.europa.esig.dss.model.tsl.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.model.x509.CertificateToken;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.exceptions.ConfigurationException;
import org.digidoc4j.exceptions.LotlTrustStoreNotFoundException;
import org.digidoc4j.exceptions.TslCertificateSourceInitializationException;
import org.digidoc4j.exceptions.TslRefreshException;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainer;
import org.digidoc4j.impl.asic.tsl.TSLCertificateSourceImpl;
import org.digidoc4j.impl.asic.tsl.TslLoader;
import org.digidoc4j.test.MockTSLRefreshCallback;
import org.digidoc4j.test.TestAssert;
import org.digidoc4j.test.util.TestCommonUtil;
import org.digidoc4j.test.util.TestFileUtil;
import org.digidoc4j.test.util.TestTSLUtil;
import org.digidoc4j.utils.Helper;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileTime;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.digidoc4j.test.TestConstants.DEFAULT_SUPPORTED_TLS_CIPHER_SUITES;
import static org.digidoc4j.test.TestConstants.DEFAULT_SUPPORTED_TLS_PROTOCOLS;
import static org.digidoc4j.test.TestConstants.DEFAULT_TLS_PROTOCOL;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ConfigurationTest extends AbstractTest {

  private final Logger log = LoggerFactory.getLogger(ConfigurationTest.class);
  private static final String SIGN_OCSP_REQUESTS = "SIGN_OCSP_REQUESTS";
  private static final String OCSP_PKCS12_CONTAINER = "DIGIDOC_PKCS12_CONTAINER";
  private static final String OCSP_PKCS_12_PASSWD = "DIGIDOC_PKCS12_PASSWD";

  @Test
  public void getLotlLocationWhenNotFileURL() {
    String lotlLocation = "URL:test";
    configuration.setLotlLocation(lotlLocation);
    assertEquals(lotlLocation, configuration.getLotlLocation());
    assertEquals(lotlLocation, configuration.getTslLocation());
  }

  @Test
  public void lotlLocationAndTslLocationReferToTheSameValue() {
    String lotlLocation = "URL:test";
    configuration.setLotlLocation(lotlLocation);
    assertEquals(lotlLocation, configuration.getLotlLocation());
    assertEquals(lotlLocation, configuration.getTslLocation());
    String tslLocation = "URL:test2";
    configuration.setTslLocation(tslLocation);
    assertEquals(tslLocation, configuration.getLotlLocation());
    assertEquals(tslLocation, configuration.getTslLocation());
  }

  @Test
  public void TSLIsLoadedOnlyOnceForGlobalConfiguration() {
    TSLCertificateSource tsl = configuration.getTSL();
    assertEquals(tsl, configuration.getTSL());
  }

  @Test
  public void addTSL()  {
    TSLCertificateSource source = configuration.getTSL();
    int numberOfTSLCertificates = source.getCertificates().size();
    addCertificateToTSL(Paths.get("src/test/resources/testFiles/certs/Juur-SK.pem.crt"), source);
    assertEquals(numberOfTSLCertificates + 1, configuration.getTSL().getCertificates().size());
  }

  @Test
  public void addingCertificateToTsl() {
    TSLCertificateSource source = new TSLCertificateSourceImpl();
    addCertificateToTSL(Paths.get("src/test/resources/testFiles/certs/Juur-SK.pem.crt"), source);
    CertificateToken certificateToken = source.getCertificates().get(0);
    assertThat(certificateToken.getKeyUsageBits(), hasItem(KeyUsageBit.NON_REPUDIATION));
    assertTrue(certificateToken.checkKeyUsage(KeyUsageBit.NON_REPUDIATION));
    List<TrustProperties> associatedTSPS = source.getTrustServices(certificateToken);
    TrustProperties trustProperties = associatedTSPS.iterator().next();
    TrustServiceStatusAndInformationExtensions informationExtensions = trustProperties.getTrustService().getLatest();
    assertEquals("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision", informationExtensions.getStatus());
    assertEquals("http://uri.etsi.org/TrstSvc/Svctype/CA/QC", informationExtensions.getType());
    assertNotNull(informationExtensions.getStartDate());
    List<ConditionForQualifiers> qualifiersAndConditions = informationExtensions.getConditionsForQualifiers();
    assertTrue(qualifiersAndConditions.get(0).getQualifiers().contains("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD"));
  }

  @Test
  public void addingSameCertificateToTSLMultipleTimes_certNumberRemainsSameButServiceInfoIsDuplicated() {
    Path certificatePath = Paths.get("src/test/resources/testFiles/certs/Juur-SK.pem.crt");
    TSLCertificateSource source = new TSLCertificateSourceImpl();

    addCertificateToTSL(certificatePath, source);
    assertSame(1, source.getCertificates().size());
    CertificateToken certificateToken = source.getCertificates().get(0);
    assertSame(1, source.getTrustServices(certificateToken).size());

    addCertificateToTSL(certificatePath, source);
    assertSame(1, source.getCertificates().size());
    certificateToken = source.getCertificates().get(0);
    assertSame(2, source.getTrustServices(certificateToken).size());

    addCertificateToTSL(certificatePath, source);
    assertSame(1, source.getCertificates().size());
    certificateToken = source.getCertificates().get(0);
    assertSame(3, source.getTrustServices(certificateToken).size());
  }

  @Test
  public void clearTSLLoadsFromConfiguration() {
    TSLCertificateSource tsl = configuration.getTSL();
    int numberOfTSLCertificates = tsl.getCertificates().size();
    configuration.setTSL(null);
    assertEquals(numberOfTSLCertificates, configuration.getTSL().getCertificates().size());
  }

  @Test
  public void setTSL() throws IOException, CertificateException {
    TSLCertificateSource source = new TSLCertificateSourceImpl();
    addCertificateToTSL(Paths.get("src/test/resources/testFiles/certs/Juur-SK.pem.crt"), source);
    configuration.setTSL(source);
    assertEquals(1, configuration.getTSL().getCertificates().size());
  }

  @SuppressWarnings("ConstantConditions")
  @Disabled("Ignored till problem with file times are solved")
  @Test
  public void clearTSLCache() throws Exception {
    // TODO: find out why file times are equal; till then ignore
    File fileCacheDirectory = TslLoader.fileCacheDirectory;
    if (fileCacheDirectory.exists()) {
      FileUtils.cleanDirectory(fileCacheDirectory);
    }
    TSLCertificateSource tslCertificateSource = configuration.getTSL();
    tslCertificateSource.refresh();
    TestCommonUtil.sleepInSeconds(1);
    File oldCachedFile = fileCacheDirectory.listFiles()[0];
    FileTime oldCachedFileDate = (FileTime) Files.getAttribute(oldCachedFile.toPath(),
        "basic:creationTime");

    tslCertificateSource.invalidateCache();
    configuration.setTSL(null);
    tslCertificateSource = configuration.getTSL();
    tslCertificateSource.refresh();
    File newCachedFile = fileCacheDirectory.listFiles()[0];
    FileTime newCachedFileDate = TestFileUtil.creationTime(newCachedFile.toPath());
    assertTrue(newCachedFileDate.compareTo(oldCachedFileDate) > 0);
  }

  @Test
  public void getTsl_whenCacheIsNotExpired_shouldUseCachedTsl() {
    TestTSLUtil.evictCache();
    configuration.setTslCacheExpirationTime(10000L);
    TSLCertificateSource tsl1 = configuration.getTSL();
    tsl1.refresh();
    long lastModified1 = TestTSLUtil.getCacheLastModified();
    TestCommonUtil.sleepInSeconds(1);
    TSLCertificateSource tsl2 = configuration.getTSL();
    tsl2.refresh();
    assertEquals(lastModified1, TestTSLUtil.getCacheLastModified());
    assertSame(tsl1, tsl2);
  }

  @Test
  public void getTsl_whenCacheIsExpired_shouldDownloadNewTsl() {
    TestTSLUtil.evictCache();
    configuration.setTslCacheExpirationTime(500L);
    TSLCertificateSource tsl = configuration.getTSL();
    tsl.refresh();
    long lastModified = TestTSLUtil.getCacheLastModified();
    TestCommonUtil.sleepInSeconds(1);
    TSLCertificateSource newTsl = configuration.getTSL();
    newTsl.refresh();
    long newModificationTime = TestTSLUtil.getCacheLastModified();
    assertTrue(lastModified < newModificationTime);
    assertSame(tsl, newTsl);
  }

  @Test
  public void lotlValidationFailsWithWrongCertsInTruststore() {
    configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setLotlTruststorePath("truststores/test-lotl-truststore.p12");
    try {
      configuration.getTSL();
    } catch (TslCertificateSourceInitializationException e) {
      assertEquals("Not ETSI compliant signature. The signature is not valid.", e.getMessage());
    }
  }

  @Test
  public void lotlLoadingWithNoLotlSslCertificateInTruststoreUsingDefaultTslCallback() {
    configuration.setSslTruststorePath("classpath:testFiles/truststores/empty-truststore.p12");
    configuration.setSslTruststorePassword("digidoc4j-password");
    configuration.setSslTruststoreType("PKCS12");
    evictTSLCache();

    assertThrows(
            TslRefreshException.class,
            () -> configuration.getTSL().refresh()
    );
  }

  @Test
  public void lotlLoadingWithNoLotlSslCertificateInTruststoreUsingCustomTslCallback() {
    configuration.setSslTruststorePath("classpath:testFiles/truststores/empty-truststore.p12");
    configuration.setSslTruststorePassword("digidoc4j-password");
    configuration.setSslTruststoreType("PKCS12");
    evictTSLCache();
    configuration.setTslRefreshCallback(new MockTSLRefreshCallback(true));
    ValidationResult validationResult = ContainerOpener.open("src/test/resources/prodFiles/valid-containers/valid_prod_bdoc_eid.bdoc", configuration).validate();
    TestAssert.assertContainsErrors(validationResult.getErrors(), "The certificate chain for signature is not trusted, it does not contain a trust anchor.");
  }

  @Test
  public void eeTlLoadingFailsWithNoEeTlSslCertificateInTruststore() {
    Configuration configuration = Configuration.of(Configuration.Mode.PROD);
    configuration.setSslTruststorePathFor(ExternalConnectionType.TSL, "src/test/resources/testFiles/truststores/lotl-ssl-only-truststore.p12");
    configuration.setSslTruststorePasswordFor(ExternalConnectionType.TSL, "digidoc4j-password");
    configuration.setSslTruststoreTypeFor(ExternalConnectionType.TSL, "PKCS12");
    configuration.setTslRefreshCallback(new MockTSLRefreshCallback(true));
    evictTSLCache();
    ValidationResult validationResult = ContainerOpener.open("src/test/resources/prodFiles/valid-containers/valid_prod_bdoc_eid.bdoc", configuration).validate();
    assertTrue(validationResult.getErrors().stream()
            .anyMatch(e -> "The certificate chain for signature is not trusted, it does not contain a trust anchor.".equals(e.getMessage())), "Certificate path should not be trusted");
  }

  @Test
  public void addedTSLIsValid() {
    TSLCertificateSource source = configuration.getTSL();
    addCertificateToTSL(Paths.get("src/test/resources/testFiles/certs/Juur-SK.pem.crt"), source);
    addCertificateToTSL(Paths.get("src/test/resources/testFiles/certs/EE_Certification_Centre_Root_CA.pem.crt"), source);
    addCertificateToTSL(Paths.get("src/test/resources/testFiles/certs/ESTEID-SK_2011.pem.crt"), source);
    addCertificateToTSL(Paths.get("src/test/resources/testFiles/certs/SK_OCSP_RESPONDER_2011.pem.cer"), source);
    addCertificateToTSL(Paths.get("src/test/resources/testFiles/certs/SK_TSA.pem.crt"), source);
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/test.asice", configuration);
    assertTrue(container.validate().isValid());
  }

  @Test
  public void policyFileIsReadFromNonDefaultFileLocation() {
    configuration.setValidationPolicy("src/test/resources/testFiles/constraints/moved_constraint.xml");
    ContainerOpener.open("src/test/resources/testFiles/invalid-containers/asics_for_testing.bdoc", configuration);
  }

  @Test
  public void tslIsLoadedAfterSettingNewLotlLocation() throws Exception {
    configuration.setLotlLocation("https://open-eid.github.io/test-TL/tl-mp-test-EE.xml");
    BDocContainer container = (BDocContainer) ContainerBuilder.aContainer(Container.DocumentType.BDOC)
        .withConfiguration(configuration).build();
    container.getConfiguration().getTSL();
    assertEquals(32, container.getConfiguration().getTSL().getCertificates().size());

    int tenSeconds = 10000;
    String lotlHost = "10.0.25.57";
    if (InetAddress.getByName(lotlHost).isReachable(tenSeconds)) {
      configuration.setLotlLocation("http://" + lotlHost + "/tsl/trusted-test-mp.xml");
      container = (BDocContainer) ContainerBuilder.aContainer(Container.DocumentType.BDOC).
          withConfiguration(configuration).build();
      assertNotEquals(5, container.getConfiguration().getTSL().getCertificates().size());
    } else {
      log.error("Host <{}> is unreachable", lotlHost);
    }
  }

  @Test
  public void LOTLFileNotFoundThrowsNoException() {
    configuration.setLotlLocation("file:test-lotl/NotExisting.xml");
    configuration.setTslRefreshCallback(new MockTSLRefreshCallback(true));
    BDocContainer container = (BDocContainer) ContainerBuilder.
        aContainer(Container.DocumentType.BDOC).
        withConfiguration(configuration).
        build();
    container.getConfiguration().getTSL().refresh();
    assertEquals(0, configuration.getTSL().getCertificates().size());
  }

  @Test
  public void LOTLConnectionFailureThrowsNoException() {
    configuration.setLotlLocation("http://127.0.0.1/lotl/incorrect.xml");
    configuration.setTslRefreshCallback(new MockTSLRefreshCallback(true));
    BDocContainer container = (BDocContainer) ContainerBuilder.
        aContainer(Container.DocumentType.BDOC).
        withConfiguration(configuration).
        build();
    container.getConfiguration().getTSL().refresh();
    assertEquals(0, configuration.getTSL().getCertificates().size());
  }

  @Test
  public void testLoadConfiguration() {
    BDocContainer container = (BDocContainer) ContainerBuilder.
        aContainer(Container.DocumentType.BDOC).
        withConfiguration(configuration).
        build();
    assertTrue(container.getConfiguration().storeDataFilesOnlyInMemory());
    container.getConfiguration().loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    assertFalse(container.getConfiguration().storeDataFilesOnlyInMemory());
    assertEquals(8192, container.getConfiguration().getMaxDataFileCachedInMB());
  }

  @Test
  public void whenLOTLLocationIsMalformedURLNoErrorIsRaisedAndThisSameValueIsReturned() {
    String lotlLocation = "file://C:\\";
    configuration.setLotlLocation(lotlLocation);
    assertEquals(lotlLocation, configuration.getLotlLocation());
  }

  @Test
  public void getLOTLLocationFileDoesNotExistReturnsUrlPath() {
    String lotlLocation = ("file:conf/does-not-exist.xml");
    configuration.setLotlLocation(lotlLocation);
    assertEquals(lotlLocation, configuration.getLotlLocation());
  }

  @Test
  public void setLotlLocation() {
    configuration.setLotlLocation("lotlLocation");
    assertEquals("lotlLocation", configuration.getLotlLocation());
    assertEquals("lotlLocation", configuration.getTslLocation());
  }

  @Test
  public void setTslLocation() {
    configuration.setTslLocation("tslLocation");
    assertEquals("tslLocation", configuration.getLotlLocation());
    assertEquals("tslLocation", configuration.getTslLocation());
  }

  @Test
  public void getLotlLocationFromConfigurationFile() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    assertEquals("TEST_LOTL_LOCATION", configuration.getLotlLocation());
    assertEquals("TEST_LOTL_LOCATION", configuration.getTslLocation());
  }

  @Test
  public void getTslLocationFromConfigurationFile() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_tsl_location_and_keystore.yaml");
    assertEquals("file:conf/test_TSLLocation", configuration.getLotlLocation());
    assertEquals("file:conf/test_TSLLocation", configuration.getTslLocation());
  }

  @Test
  public void setLotlLocationOverwritesConfigurationFile() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    configuration.setLotlLocation("lotlLocation");
    assertEquals("lotlLocation", configuration.getLotlLocation());
    assertEquals("lotlLocation", configuration.getTslLocation());
  }

  @Test
  public void setTspSource() {
    configuration.setTspSource("tspSource");
    assertEquals("tspSource", configuration.getTspSource());
    assertEquals("tspSource", configuration.getTspSourceForArchiveTimestamps());
  }

  @Test
  public void setTspSourceForArchiveTimestamps() {
    String tspSource = configuration.getTspSource();
    configuration.setTspSourceForArchiveTimestamps("tspSourceForArchiveTimestamps");
    assertEquals("tspSourceForArchiveTimestamps", configuration.getTspSourceForArchiveTimestamps());
    assertEquals(tspSource, configuration.getTspSource());
  }

  @Test
  public void setValidationPolicy() {
    configuration.setValidationPolicy("policy");
    assertEquals("policy", configuration.getValidationPolicy());
  }

  @Test
  public void setOcspSource() {
    configuration.setOcspSource("ocsp_source");
    assertEquals("ocsp_source", configuration.getOcspSource());
  }

  @Test
  public void setUseOcspNonce() {
    assertTrue(configuration.isOcspNonceUsed());
    configuration.setUseOcspNonce(false);
    assertFalse(configuration.isOcspNonceUsed());
  }

  @Test
  public void defaultOCSPAccessCertificateFile() {
    assertEquals("", configuration.getOCSPAccessCertificateFileName());
    assertEquals("", getDDoc4JConfigurationValue(OCSP_PKCS12_CONTAINER));
  }

  @Test
  public void getOCSPAccessCertificateFileFromConfigurationFile() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    assertEquals("conf/OCSP_access_certificate_test_file_name", configuration.getOCSPAccessCertificateFileName());
    assertEquals("conf/OCSP_access_certificate_test_file_name", getDDoc4JConfigurationValue(OCSP_PKCS12_CONTAINER));
  }

  @Test
  public void getOCSPAccessCertificateFileFromStream() throws Exception {
    try (InputStream inputStream = new FileInputStream("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml")) {
      configuration.loadConfiguration(inputStream);
    }
    assertEquals("conf/OCSP_access_certificate_test_file_name", configuration.getOCSPAccessCertificateFileName());
    assertEquals("conf/OCSP_access_certificate_test_file_name", getDDoc4JConfigurationValue(OCSP_PKCS12_CONTAINER));
  }

  @Test
  public void setOCSPAccessCertificateFileNameOverwritesConfigurationFile() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    configuration.setOCSPAccessCertificateFileName("New File");
    assertEquals("New File", configuration.getOCSPAccessCertificateFileName());
    assertEquals("New File", getDDoc4JConfigurationValue(OCSP_PKCS12_CONTAINER));
  }

  @Test
  public void defaultOCSPAccessCertificatePassword() {
    assertEquals(0, configuration.getOCSPAccessCertificatePassword().length);
    assertNull(getDDoc4JConfigurationValue(OCSP_PKCS_12_PASSWD));
  }

  @Test
  public void getOCSPAccessCertificatePasswordFromConfigurationFile() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    assertArrayEquals("OCSP_test_password".toCharArray(), configuration.getOCSPAccessCertificatePassword());
    assertEquals("OCSP_test_password", getDDoc4JConfigurationValue(OCSP_PKCS_12_PASSWD));
  }

  @Test
  public void setOCSPAccessCertificatePasswordOverwritesConfigurationFile() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    char[] newPassword = "New password".toCharArray();
    configuration.setOCSPAccessCertificatePassword(newPassword);
    assertArrayEquals(newPassword, configuration.getOCSPAccessCertificatePassword());
    assertEquals("New password", getDDoc4JConfigurationValue(OCSP_PKCS_12_PASSWD));
  }

  @Test
  public void signingOcspRequest_ShouldBeDisabled_InProdByDefault() {
    configuration = Configuration.of(Configuration.Mode.PROD);
    assertFalse(configuration.hasToBeOCSPRequestSigned());
    assertEquals("false", getDDoc4JConfigurationValue(SIGN_OCSP_REQUESTS));
  }

  @Test
  public void signingOcspRequest_ShouldBeDisabled_InTestByDefault() {
    assertFalse(configuration.hasToBeOCSPRequestSigned());
    assertEquals("false", getDDoc4JConfigurationValue(SIGN_OCSP_REQUESTS));
  }

  @Test
  public void disableSigningOcspRequestsInProd() {
    configuration = Configuration.of(Configuration.Mode.PROD);
    configuration.setSignOCSPRequests(false);
    assertFalse(configuration.hasToBeOCSPRequestSigned());
    assertEquals("false", getDDoc4JConfigurationValue(SIGN_OCSP_REQUESTS));
  }

  @Test
  public void enableSigningOcspRequestsInTest() {
    configuration.setSignOCSPRequests(true);
    assertTrue(configuration.hasToBeOCSPRequestSigned());
    assertEquals("true", getDDoc4JConfigurationValue(SIGN_OCSP_REQUESTS));
  }

  @Test
  public void loadDisableSigningOcspRequestFromConfFileInProd() {
    configuration = Configuration.of(Configuration.Mode.PROD);
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    assertFalse(configuration.hasToBeOCSPRequestSigned());
    assertEquals("false", getDDoc4JConfigurationValue(SIGN_OCSP_REQUESTS));
  }

  @Test
  public void loadDisableSigningOcspRequestFromConfFile() {
    configuration.loadConfiguration(generateConfigurationByParameter("SIGN_OCSP_REQUESTS: false").getPath());
    assertFalse(configuration.hasToBeOCSPRequestSigned());
    assertEquals("false", getDDoc4JConfigurationValue(SIGN_OCSP_REQUESTS));
  }

  @Test
  public void loadEnableSigningOcspRequestFromConfFile() {
    configuration.loadConfiguration(generateConfigurationByParameter("SIGN_OCSP_REQUESTS: true").getPath());
    assertTrue(configuration.hasToBeOCSPRequestSigned());
    assertEquals("true", getDDoc4JConfigurationValue(SIGN_OCSP_REQUESTS));
  }

  @Test
  public void defaultOcspSource() {
    assertEquals("http://demo.sk.ee/ocsp", configuration.getOcspSource());
  }

  @Test
  public void defaultProductionConfiguration() {
    configuration = Configuration.of(Configuration.Mode.PROD);
    assertEquals("https://ec.europa.eu/tools/lotl/eu-lotl.xml",
        configuration.getLotlLocation());
  }

  @Test
  public void defaultConstructorWithSetSystemProperty() {
    configuration = new Configuration();
    assertEquals("https://open-eid.github.io/test-TL/tl-mp-test-EE.xml", configuration.getLotlLocation());
  }

  @Test
  public void setMaxDataFileCached() {
    long maxDataFileCached = 12345;
    configuration.setMaxFileSizeCachedInMemoryInMB(maxDataFileCached);
    assertEquals(maxDataFileCached, configuration.getMaxDataFileCachedInMB());
    assertEquals(maxDataFileCached * Constant.ONE_MB_IN_BYTES, configuration.getMaxDataFileCachedInBytes());
  }

  @Test
  public void setMaxDataFileCachedToNoCaching() {
    long maxDataFileCached = Constant.CACHE_NO_DATA_FILES;
    configuration.setMaxFileSizeCachedInMemoryInMB(maxDataFileCached);
    assertEquals(Constant.CACHE_NO_DATA_FILES, configuration.getMaxDataFileCachedInMB());
    assertEquals(Constant.CACHE_NO_DATA_FILES, configuration.getMaxDataFileCachedInBytes());
  }

  @Test
  public void setMaxDataFileCachedToAllCaching() {
    long maxDataFileCached = Constant.CACHE_ALL_DATA_FILES;
    configuration.setMaxFileSizeCachedInMemoryInMB(maxDataFileCached);
    assertEquals(Constant.CACHE_ALL_DATA_FILES, configuration.getMaxDataFileCachedInMB());
    assertEquals(Constant.CACHE_ALL_DATA_FILES, configuration.getMaxDataFileCachedInBytes());
  }

  @Test
  public void maxDataFileCachedNotAllowedValue() {
    long oldValue = 4096;
    configuration.setMaxFileSizeCachedInMemoryInMB(oldValue);
    configuration.setMaxFileSizeCachedInMemoryInMB(-2);
    assertEquals(oldValue, configuration.getMaxDataFileCachedInMB());
  }

  @Test
  public void maxDataFileCachedNotAllowedValueFromFile() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_max_datafile_cached_invalid.yaml";
    String excpectedErrorMessage = "Configuration parameter DIGIDOC_MAX_DATAFILE_CACHED should be greater or equal " +
            "-1 but the actual value is: -2.";

    ConfigurationException exception = assertThrows(
            ConfigurationException.class,
            () -> configuration.loadConfiguration(fileName)
    );

    assertThat(exception.getMessage(), containsString(excpectedErrorMessage));
  }

  @Test
  public void defaultConstructorWithUnSetSystemProperty() {
    clearGlobalMode();
    configuration = new Configuration();
    assertEquals("https://ec.europa.eu/tools/lotl/eu-lotl.xml",
            configuration.getLotlLocation());
  }

  @Test
  public void generateDDoc4JConfig() {
    Hashtable<String, String> ddoc4jConf = configuration.loadConfiguration("src/main/resources/digidoc4j.yaml");
    configuration.getDDoc4JConfiguration();
    assertEquals("jar://certs/ESTEID-SK.crt", ddoc4jConf.get("DIGIDOC_CA_1_CERT2"));
    assertEquals("jar://certs/KLASS3-SK OCSP 2006.crt", ddoc4jConf.get("DIGIDOC_CA_1_OCSP2_CERT_1"));
    assertEquals("jar://certs/EID-SK OCSP 2006.crt", ddoc4jConf.get("DIGIDOC_CA_1_OCSP13_CERT_1"));
    assertEquals("jar://certs/TEST Juur-SK.crt", ddoc4jConf.get("DIGIDOC_CA_1_CERT19"));
    assertEquals(Constant.DDoc4J.SECURITY_PROVIDER, ddoc4jConf.get("DIGIDOC_SECURITY_PROVIDER"));
    assertEquals(Constant.DDoc4J.SECURITY_PROVIDER_NAME, ddoc4jConf.get("DIGIDOC_SECURITY_PROVIDER_NAME"));
    assertEquals("false", ddoc4jConf.get("DATAFILE_HASHCODE_MODE"));
    assertEquals(Constant.DDoc4J.CANONICALIZATION_FACTORY_IMPLEMENTATION, ddoc4jConf.get("CANONICALIZATION_FACTORY_IMPL"));
    assertEquals("-1", ddoc4jConf.get("DIGIDOC_MAX_DATAFILE_CACHED"));
    assertEquals("false", ddoc4jConf.get(SIGN_OCSP_REQUESTS));
    assertEquals("jar://certs/KLASS3-SK OCSP.crt", ddoc4jConf.get("DIGIDOC_CA_1_OCSP2_CERT"));
  }

  @Test
  public void loadsDDoc4JSecurityProviderFromFile() {
    Hashtable<String, String> ddoc4jConf = configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    assertEquals("org.bouncycastle.jce.provider.BouncyCastleProvider1", ddoc4jConf.get("DIGIDOC_SECURITY_PROVIDER"));
  }

  @Test
  public void loadsDDoc4JCacheDirectoryFromFile() {
    Hashtable<String, String> ddoc4jConf = configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    assertEquals("/test_cache_dir", ddoc4jConf.get("DIGIDOC_DF_CACHE_DIR"));
  }

  @Test
  public void defaultDDoc4JCacheDirectory() {
    Hashtable<String, String> ddoc4jConf =
            configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_without_cache_dir.yaml");
    assertNull(ddoc4jConf.get("DIGIDOC_DF_CACHE_DIR"));
  }

  @Test
  public void loadsMaxDataFileCachedFromFile() {
    Hashtable<String, String> ddoc4jConf = configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    assertEquals("8192", ddoc4jConf.get("DIGIDOC_MAX_DATAFILE_CACHED"));
    assertEquals(8192, configuration.getMaxDataFileCachedInMB());
    assertEquals(8192 * Constant.ONE_MB_IN_BYTES, configuration.getMaxDataFileCachedInBytes());
  }

  @Test
  public void settingNonExistingConfigurationFileThrowsError() {
    ConfigurationException exception = assertThrows(
            ConfigurationException.class,
            () -> configuration.loadConfiguration("src/test/resources/testFiles/not_exists.yaml")
    );

    assertThat(exception.getMessage(), equalTo("File src/test/resources/testFiles/not_exists.yaml not found in classpath."));
  }

  @Test
  public void digiDocSecurityProviderDefaultValue() {
    Hashtable<String, String> ddoc4jConf = configuration.loadConfiguration("src/main/resources/digidoc4j.yaml");
    assertEquals(Constant.DDoc4J.SECURITY_PROVIDER, ddoc4jConf.get("DIGIDOC_SECURITY_PROVIDER"));
  }

  @Test
  public void digiDocSecurityProviderDefaultName() {
    Hashtable<String, String> ddoc4jConf = configuration.loadConfiguration("src/main/resources/digidoc4j.yaml");
    assertEquals(Constant.DDoc4J.SECURITY_PROVIDER_NAME, ddoc4jConf.get("DIGIDOC_SECURITY_PROVIDER_NAME"));
  }

  @Test
  public void asksValueOfNonExistingParameter() {
    Hashtable<String, String> ddoc4jConf = configuration.loadConfiguration("src/main/resources/digidoc4j.yaml");
    assertNull(ddoc4jConf.get("DIGIDOC_PROXY_HOST"));
  }

  @Test
  public void digidocMaxDataFileCachedParameterIsNotANumber() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_invalid_max_data_file_cached.yaml";
    String expectedErrorMessage = "Configuration parameter DIGIDOC_MAX_DATAFILE_CACHED" +
        " should have an integer value but the actual value is: 8192MB.";

    ConfigurationException exception = assertThrows(
            ConfigurationException.class,
            () -> configuration.loadConfiguration(fileName)
    );

    assertThat(exception.getMessage(), containsString(expectedErrorMessage));
  }

  @Test
  public void digidocSignOcspRequestIsNotABoolean() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_invalid_sign_ocsp_request.yaml";
    String expectedErrorMessage = "Configuration parameter SIGN_OCSP_REQUESTS should be set to true or false" +
        " but the actual value is: NonBooleanValue.";

    ConfigurationException exception = assertThrows(
            ConfigurationException.class,
            () -> configuration.loadConfiguration(fileName)
    );

    assertThat(exception.getMessage(), containsString(expectedErrorMessage));
  }

  @Test
  public void digidocKeyUsageCheckIsNotABoolean() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_invalid_key_usage.yaml";
    String expectedErrorMessage = "Configuration parameter KEY_USAGE_CHECK should be set to true or false" +
            " but the actual value is: NonBooleanValue.";

    ConfigurationException exception = assertThrows(
            ConfigurationException.class,
            () -> configuration.loadConfiguration(fileName)
    );

    assertThat(exception.getMessage(), containsString(expectedErrorMessage));
  }

  @Test
  public void digidocUseLocalTslIsNotABoolean() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_invalid_use_local_tsl.yaml";
    String expectedErrorMessage = "Configuration parameter DIGIDOC_USE_LOCAL_TSL should be set to true or false" + 
            " but the actual value is: NonBooleanValue.";

    ConfigurationException exception = assertThrows(
            ConfigurationException.class,
            () -> configuration.loadConfiguration(fileName)
    );

    assertThat(exception.getMessage(), containsString(expectedErrorMessage));
  }

  @Test
  public void digidocDataFileHashcodeModeIsNotABoolean() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_invalid_datafile_hashcode_mode.yaml";
    String expectedErrorMessage = "Configuration parameter DATAFILE_HASHCODE_MODE should be set to true or false" +
        " but the actual value is: NonBooleanValue.";

    ConfigurationException exception = assertThrows(
            ConfigurationException.class,
            () -> configuration.loadConfiguration(fileName)
    );

    assertThat(exception.getMessage(), containsString(expectedErrorMessage));
  }

  @Test
  public void missingOCSPSEntryThrowsException() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_ocsps_no_entry.yaml";
    configuration.loadConfiguration(fileName);

    ConfigurationException exception = assertThrows(
            ConfigurationException.class,
            () -> configuration.getDDoc4JConfiguration()
    );

    assertThat(exception.getMessage(), containsString("No OCSPS entry found or OCSPS entry is empty. Configuration from: " + fileName));
  }

  @Test
  public void emptyOCSPSEntryThrowsException() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_ocsps_empty.yaml";
    configuration.loadConfiguration(fileName);

    ConfigurationException exception = assertThrows(
            ConfigurationException.class,
            () -> configuration.getDDoc4JConfiguration()
    );

    assertThat(exception.getMessage(), containsString("No OCSPS entry found or OCSPS entry is empty. Configuration from: " + fileName));
  }

  @Test
  public void OCSPWithoutCaCnValueThrowsException() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_ocsps_no_ca_cn.yaml";
    String expectedErrorMessage = "Configuration from " + fileName + " contains error(s):\n" +
        "OCSPS list entry 2 does not have an entry for CA_CN or the entry is empty\n";
    configuration.loadConfiguration(fileName);

    ConfigurationException exception = assertThrows(
            ConfigurationException.class,
            () -> configuration.getDDoc4JConfiguration()
    );

    assertThat(exception.getMessage(), equalTo(expectedErrorMessage));
  }

  @Test
  public void OCSPWithEmptySubEntriesThrowsException() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_ocsps_empty_sub_entries.yaml";
    String expectedErrorMessage = "Configuration from " + fileName + " contains error(s):\n" +
        "OCSPS list entry 3 does not have an entry for CA_CN or the entry is empty\n" +
        "OCSPS list entry 4 does not have an entry for CA_CERT or the entry is empty\n" +
        "OCSPS list entry 5 does not have an entry for CN or the entry is empty\n" +
        "OCSPS list entry 8 does not have an entry for URL or the entry is empty\n";
    configuration.loadConfiguration(fileName);

    ConfigurationException exception = assertThrows(
            ConfigurationException.class,
            () -> configuration.getDDoc4JConfiguration()
    );

    assertThat(exception.getMessage(), equalTo(expectedErrorMessage));
  }

  @Test
  public void OCSPWithMissingSubEntriesThrowsException() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_ocsps_missing_sub_entries.yaml";
    String expectedErrorMessage = "Configuration from " + fileName + " contains error(s):\n" +
        "OCSPS list entry 3 does not have an entry for CN or the entry is empty\n" +
        "OCSPS list entry 4 does not have an entry for URL or the entry is empty\n" +
        "OCSPS list entry 5 does not have an entry for CA_CERT or the entry is empty\n" +
        "OCSPS list entry 8 does not have an entry for CA_CN or the entry is empty\n";
    configuration.loadConfiguration(fileName);

    ConfigurationException exception = assertThrows(
            ConfigurationException.class,
            () -> configuration.getDDoc4JConfiguration()
    );

    assertThat(exception.getMessage(), equalTo(expectedErrorMessage));
  }

  @Test
  public void OCSPWithMissingOcspsCertsEntryThrowsException() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_ocsps_missing_certs_entry.yaml";
    String expectedErrorMessage = "Configuration from " + fileName + " contains error(s):\n" +
        "OCSPS list entry 3 does not have an entry for CERTS or the entry is empty\n";
    configuration.loadConfiguration(fileName);

    ConfigurationException exception = assertThrows(
            ConfigurationException.class,
            () -> configuration.getDDoc4JConfiguration()
    );

    assertThat(exception.getMessage(), equalTo(expectedErrorMessage));
  }

  @Test
  public void OCSPWithEmptyOcspsCertsEntryThrowsException() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_ocsps_empty_certs_entry.yaml";
    String expectedErrorMessage = "Configuration from " + fileName + " contains error(s):\n" +
        "OCSPS list entry 2 does not have an entry for CERTS or the entry is empty\n";
    configuration.loadConfiguration(fileName);

    ConfigurationException exception = assertThrows(
            ConfigurationException.class,
            () -> configuration.getDDoc4JConfiguration()
    );

    assertThat(exception.getMessage(), equalTo(expectedErrorMessage));
  }

  @Test
  public void configurationFileIsNotYamlFormatThrowsException() {
    String fileName = "src/test/resources/testFiles/helper-files/test.txt";
    String expectedErrorMessage = "Configuration from " + fileName + " is not correctly formatted";
    ConfigurationException exception = assertThrows(
            ConfigurationException.class,
            () -> configuration.loadConfiguration(fileName)
    );

    assertThat(exception.getMessage(), equalTo(expectedErrorMessage));
  }

  @Test
  public void configurationStreamIsNotYamlFormatThrowsException() {
    String fileName = "src/test/resources/testFiles/helper-files/test.txt";
    String expectedErrorMessage = "Configuration from stream is not correctly formatted";

    ConfigurationException exception = assertThrows(ConfigurationException.class, () -> {
      try (InputStream inputStream = new FileInputStream(fileName)) {
        configuration.loadConfiguration(inputStream);
      }
    });

    assertThat(exception.getMessage(), equalTo(expectedErrorMessage));
  }

  @Test
  public void isOCSPSigningConfigurationAvailableWhenItIsNotAvailable() {
    assertFalse(configuration.isOCSPSigningConfigurationAvailable());
  }

  @Test
  public void isOCSPSigningConfigurationAvailableWhenItIsAvailable() {
    configuration.setOCSPAccessCertificateFileName("test.p12");
    configuration.setOCSPAccessCertificatePassword("aaa".toCharArray());
    assertTrue(configuration.isOCSPSigningConfigurationAvailable());
  }

  @Test
  public void isOCSPSigningConfigurationAvailableWhenFileIsAvailable() {
    configuration.setOCSPAccessCertificateFileName("test.p12");
    assertFalse(configuration.isOCSPSigningConfigurationAvailable());
  }

  @Test
  public void isOCSPSigningConfigurationAvailableWhenPasswordIsAvailable() {
    configuration.setOCSPAccessCertificatePassword("aaa".toCharArray());
    assertFalse(configuration.isOCSPSigningConfigurationAvailable());
  }

  @Test
  public void getTspSourceDefaultValuesForProdConfiguration() {
    Configuration configuration = Configuration.of(Configuration.Mode.PROD);
    assertEquals(Constant.Production.TSP_SOURCE, configuration.getTspSource());
    assertEquals(Constant.Production.TSP_SOURCE, configuration.getTspSourceForArchiveTimestamps());
  }

  @Test
  public void getTspSourceDefaultValuesForTestConfiguration() {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    assertEquals(Constant.Test.TSP_SOURCE, configuration.getTspSource());
    assertEquals(Constant.Test.TSP_SOURCE, configuration.getTspSourceForArchiveTimestamps());
  }

  @Test
  public void getTspSourceFromConfigurationFile() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    assertEquals("http://tsp.source.test/HttpTspServer", configuration.getTspSource());
    assertEquals("http://tsp.source.test/HttpTspServer", configuration.getTspSourceForArchiveTimestamps());
  }

  @Test
  public void getTspSourceForArchiveTimestampsFromConfigurationFile() {
    String tspSource = configuration.getTspSource();
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_archive_timestamp.yaml");
    assertEquals("http://atsp.source.test", configuration.getTspSourceForArchiveTimestamps());
    assertEquals(tspSource, configuration.getTspSource());
  }

  @Test
  public void getValidationPolicyFromConfigurationFile() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    assertEquals("conf/test_validation_policy.xml", configuration.getValidationPolicy());
  }

  @Test
  public void getOcspSourceFromConfigurationFile() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    assertEquals("http://www.openxades.org/cgi-bin/test_ocsp_source.cgi", configuration.getOcspSource());
  }

  @Test
  public void getLotlTruststorePathFromConfigurationFile() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    assertEquals("TEST_LOTL_TRUSTSTORE_PATH", configuration.getLotlTruststorePath());
    assertEquals("TEST_LOTL_TRUSTSTORE_PATH", configuration.getTslKeyStoreLocation());
  }

  @Test
  public void getTslKeystoreLocationFromConfigurationFile() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_tsl_location_and_keystore.yaml");
    assertEquals("file:conf/test_TSLKeyStore_location", configuration.getLotlTruststorePath());
    assertEquals("file:conf/test_TSLKeyStore_location", configuration.getTslKeyStoreLocation());
  }

  @Test
  public void exceptionIsThrownWhenLotlTruststoreIsNotFound() {
    configuration = Configuration.of(Configuration.Mode.PROD);
    configuration.setLotlTruststorePath("not/existing/path");

    assertThrows(
            LotlTrustStoreNotFoundException.class,
            () -> configuration.getTSL().refresh()
    );
  }

  @Test
  public void testDefaultLotlTruststorePath() {
    configuration = Configuration.of(Configuration.Mode.PROD);
    assertEquals("classpath:truststores/lotl-truststore.p12", configuration.getLotlTruststorePath());
    assertEquals("classpath:truststores/lotl-truststore.p12", configuration.getTslKeyStoreLocation());
  }

  @Test
  public void testDefaultTestLotlTruststorePath() {
    assertEquals("classpath:truststores/test-lotl-truststore.p12", configuration.getLotlTruststorePath());
    assertEquals("classpath:truststores/test-lotl-truststore.p12", configuration.getTslKeyStoreLocation());
  }

  @Test
  public void getLotlTruststoreTypeFromConfigurationFile() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    assertEquals("TEST_LOTL_TRUSTSTORE_TYPE", configuration.getLotlTruststoreType());
  }

  @Test
  public void testDefaultLotlTruststoreType() {
    configuration = Configuration.of(Configuration.Mode.PROD);
    assertEquals("PKCS12", configuration.getLotlTruststoreType());
  }

  @Test
  public void testDefaultLotlTruststorePassword() {
    configuration = Configuration.of(Configuration.Mode.PROD);
    assertEquals("digidoc4j-password", configuration.getLotlTruststorePassword());
    assertEquals("digidoc4j-password", configuration.getTslKeyStorePassword());
  }

  @Test
  public void getLotlTruststorePasswordFromConfigurationFile() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    assertEquals("TEST_LOTL_TRUSTSTORE_PASSWORD", configuration.getLotlTruststorePassword());
    assertEquals("TEST_LOTL_TRUSTSTORE_PASSWORD", configuration.getTslKeyStorePassword());
  }

  @Test
  public void getTslKeystorePasswordFromConfigurationFile() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_tsl_location_and_keystore.yaml");
    assertEquals("test_TSLKeyStore_password", configuration.getLotlTruststorePassword());
    assertEquals("test_TSLKeyStore_password", configuration.getTslKeyStorePassword());
  }

  @Test
  public void testDefaultLotlPivotSupportEnabled() {
    configuration = Configuration.of(Configuration.Mode.PROD);
    assertTrue(configuration.isLotlPivotSupportEnabled());
  }

  @Test
  public void testDefaultTestLotlPivotSupportDisabled() {
    configuration = Configuration.of(Configuration.Mode.TEST);
    assertFalse(configuration.isLotlPivotSupportEnabled());
  }

  @Test
  public void getLotlPivotSupportFromConfigurationFile() throws Exception {
    configuration.setLotlPivotSupportEnabled(true);
    assertTrue(configuration.isLotlPivotSupportEnabled());
    loadConfigurationFromString(configuration, "LOTL_PIVOT_SUPPORT_ENABLED: false");
    assertFalse(configuration.isLotlPivotSupportEnabled());
    loadConfigurationFromString(configuration, "LOTL_PIVOT_SUPPORT_ENABLED: true");
    assertTrue(configuration.isLotlPivotSupportEnabled());
  }

  @Test
  public void setTslCacheExpirationTime() {
    configuration.setTslCacheExpirationTime(1337);
    assertEquals(1337, configuration.getTslCacheExpirationTime());
  }

  @Test
  public void defaultTslCacheExpirationTime_shouldBeOneDay() {
    long oneDayInMs = 1000 * 60 * 60 * 24;
    assertEquals(oneDayInMs, configuration.getTslCacheExpirationTime());
    assertEquals(oneDayInMs, Configuration.of(Configuration.Mode.PROD).getTslCacheExpirationTime());
  }

  @Test
  public void getTslCacheExpirationTimeFromConfigurationFile() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    assertEquals(1776, configuration.getTslCacheExpirationTime());
  }

  @Test
  public void defaultProxyConfiguration_shouldNotBeSet() {
    assertFalse(configuration.isNetworkProxyEnabled());
    assertNull(configuration.getHttpProxyHost());
    assertNull(configuration.getHttpProxyPort());
    assertNull(configuration.getHttpProxyUser());
    assertNull(configuration.getHttpProxyPassword());
    assertNull(configuration.getHttpsProxyHost());
    assertNull(configuration.getHttpsProxyPort());
    assertNull(configuration.getHttpsProxyUser());
    assertNull(configuration.getHttpsProxyPassword());
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      assertFalse(configuration.isNetworkProxyEnabledFor(connectionType));
      assertNull(configuration.getHttpProxyHostFor(connectionType));
      assertNull(configuration.getHttpProxyPortFor(connectionType));
      assertNull(configuration.getHttpProxyUserFor(connectionType));
      assertNull(configuration.getHttpProxyPasswordFor(connectionType));
      assertNull(configuration.getHttpsProxyHostFor(connectionType));
      assertNull(configuration.getHttpsProxyPortFor(connectionType));
      assertNull(configuration.getHttpsProxyUserFor(connectionType));
      assertNull(configuration.getHttpsProxyPasswordFor(connectionType));
    }
  }

  @Test
  public void getProxyConfigurationFromConfigurationFile_allParametersSet() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    assertTrue(configuration.isNetworkProxyEnabled());
    assertEquals("cache.noile.ee", configuration.getHttpProxyHost());
    assertEquals(8080, configuration.getHttpProxyPort().longValue());
    assertEquals("plainProxyMan", configuration.getHttpProxyUser());
    assertEquals("plainProxyPass", configuration.getHttpProxyPassword());
    assertEquals("secure.noile.ee", configuration.getHttpsProxyHost());
    assertEquals(8443, configuration.getHttpsProxyPort().longValue());
    assertEquals("secureProxyMan", configuration.getHttpsProxyUser());
    assertEquals("secureProxyPass", configuration.getHttpsProxyPassword());
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      assertTrue(configuration.isNetworkProxyEnabledFor(connectionType));
      assertEquals(connectionType + ".cache.noile.ee", configuration.getHttpProxyHostFor(connectionType));
      assertEquals(80800 + connectionType.ordinal(), configuration.getHttpProxyPortFor(connectionType).longValue());
      assertEquals(connectionType + "-plainProxyMan", configuration.getHttpProxyUserFor(connectionType));
      assertEquals(connectionType + "-plainProxyPass", configuration.getHttpProxyPasswordFor(connectionType));
      assertEquals(connectionType + ".secure.noile.ee", configuration.getHttpsProxyHostFor(connectionType));
      assertEquals(84430 + connectionType.ordinal(), configuration.getHttpsProxyPortFor(connectionType).longValue());
      assertEquals(connectionType + "-secureProxyMan", configuration.getHttpsProxyUserFor(connectionType));
      assertEquals(connectionType + "-secureProxyPass", configuration.getHttpsProxyPasswordFor(connectionType));
    }
  }

  @Test
  public void getInvalidProxyConfigurationFromConfigurationFile() {
    String expectedErrorMessage = "Configuration parameter HTTP_PROXY_PORT should have an integer value but the actual value is: notA_number.";

    ConfigurationException exception = assertThrows(
            ConfigurationException.class,
            () -> configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_invalid_key_usage.yaml")
    );

    assertThat(exception.getMessage(), containsString(expectedErrorMessage));
  }

  @Test
  public void getProxyConfigurationFromConfigurationFile_GenericParametersSet() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_generic_proxy_and_ssl_settings.yaml");
    assertTrue(configuration.isNetworkProxyEnabled());
    assertEquals("cache.noile.ee", configuration.getHttpProxyHost());
    assertEquals(8080, configuration.getHttpProxyPort().longValue());
    assertEquals("plainProxyMan", configuration.getHttpProxyUser());
    assertEquals("plainProxyPass", configuration.getHttpProxyPassword());
    assertEquals("secure.noile.ee", configuration.getHttpsProxyHost());
    assertEquals(8443, configuration.getHttpsProxyPort().longValue());
    assertEquals("secureProxyMan", configuration.getHttpsProxyUser());
    assertEquals("secureProxyPass", configuration.getHttpsProxyPassword());
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      assertTrue(configuration.isNetworkProxyEnabledFor(connectionType));
      assertEquals("cache.noile.ee", configuration.getHttpProxyHostFor(connectionType));
      assertEquals(8080, configuration.getHttpProxyPortFor(connectionType).longValue());
      assertEquals("plainProxyMan", configuration.getHttpProxyUserFor(connectionType));
      assertEquals("plainProxyPass", configuration.getHttpProxyPasswordFor(connectionType));
      assertEquals("secure.noile.ee", configuration.getHttpsProxyHostFor(connectionType));
      assertEquals(8443, configuration.getHttpsProxyPortFor(connectionType).longValue());
      assertEquals("secureProxyMan", configuration.getHttpsProxyUserFor(connectionType));
      assertEquals("secureProxyPass", configuration.getHttpsProxyPasswordFor(connectionType));
    }
  }

  @Test
  public void getProxyConfigurationFromConfigurationFile_specificParametersSet() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_specific_proxy_and_ssl_settings.yaml");
    assertFalse(configuration.isNetworkProxyEnabled());
    assertNull(configuration.getHttpProxyHost());
    assertNull(configuration.getHttpProxyPort());
    assertNull(configuration.getHttpProxyUser());
    assertNull(configuration.getHttpProxyPassword());
    assertNull(configuration.getHttpsProxyHost());
    assertNull(configuration.getHttpsProxyPort());
    assertNull(configuration.getHttpsProxyUser());
    assertNull(configuration.getHttpsProxyPassword());
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      assertTrue(configuration.isNetworkProxyEnabledFor(connectionType));
      assertEquals(connectionType + ".cache.noile.ee", configuration.getHttpProxyHostFor(connectionType));
      assertEquals(80800 + connectionType.ordinal(), configuration.getHttpProxyPortFor(connectionType).longValue());
      assertEquals(connectionType + "-plainProxyMan", configuration.getHttpProxyUserFor(connectionType));
      assertEquals(connectionType + "-plainProxyPass", configuration.getHttpProxyPasswordFor(connectionType));
      assertEquals(connectionType + ".secure.noile.ee", configuration.getHttpsProxyHostFor(connectionType));
      assertEquals(84430 + connectionType.ordinal(), configuration.getHttpsProxyPortFor(connectionType).longValue());
      assertEquals(connectionType + "-secureProxyMan", configuration.getHttpsProxyUserFor(connectionType));
      assertEquals(connectionType + "-secureProxyPass", configuration.getHttpsProxyPasswordFor(connectionType));
    }
  }

  @Test
  public void defaultSslProtocolsAndCiphers_shouldBeSet() {
    assertTrue(configuration.isSslConfigurationEnabled());
    assertNull(configuration.getSslKeystorePath());
    assertNull(configuration.getSslKeystoreType());
    assertNull(configuration.getSslKeystorePassword());
    assertNull(configuration.getSslTruststorePath());
    assertNull(configuration.getSslTruststoreType());
    assertNull(configuration.getSslTruststorePassword());
    assertEquals(DEFAULT_TLS_PROTOCOL, configuration.getSslProtocol());
    assertEquals(DEFAULT_SUPPORTED_TLS_PROTOCOLS, configuration.getSupportedSslProtocols());
    assertEquals(DEFAULT_SUPPORTED_TLS_CIPHER_SUITES, configuration.getSupportedSslCipherSuites());
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      assertTrue(configuration.isSslConfigurationEnabledFor(connectionType));
      assertNull(configuration.getSslKeystorePathFor(connectionType));
      assertNull(configuration.getSslKeystoreTypeFor(connectionType));
      assertNull(configuration.getSslKeystorePasswordFor(connectionType));
      assertNull(configuration.getSslTruststorePathFor(connectionType));
      assertNull(configuration.getSslTruststoreTypeFor(connectionType));
      assertNull(configuration.getSslTruststorePasswordFor(connectionType));
      assertEquals(DEFAULT_TLS_PROTOCOL, configuration.getSslProtocolFor(connectionType));
      assertEquals(DEFAULT_SUPPORTED_TLS_PROTOCOLS, configuration.getSupportedSslProtocolsFor(connectionType));
      assertEquals(DEFAULT_SUPPORTED_TLS_CIPHER_SUITES, configuration.getSupportedSslCipherSuitesFor(connectionType));
    }
  }

  @Test
  public void getSslConfigurationFromConfigurationFile_allParametersSet() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    assertTrue(configuration.isSslConfigurationEnabled());
    assertEquals("sslKeystorePath", configuration.getSslKeystorePath());
    assertEquals("sslKeystoreType", configuration.getSslKeystoreType());
    assertEquals("sslKeystorePassword", configuration.getSslKeystorePassword());
    assertEquals("sslTruststorePath", configuration.getSslTruststorePath());
    assertEquals("sslTruststoreType", configuration.getSslTruststoreType());
    assertEquals("sslTruststorePassword", configuration.getSslTruststorePassword());
    assertEquals("sslProtocol", configuration.getSslProtocol());
    assertEquals(Arrays.asList("sslProtocol1", "sslProtocol2", "sslProtocol3"), configuration.getSupportedSslProtocols());
    assertEquals(Arrays.asList("sslCipherSuite1", "sslCipherSuite2"), configuration.getSupportedSslCipherSuites());
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      assertTrue(configuration.isSslConfigurationEnabledFor(connectionType));
      assertEquals(connectionType + "-sslKeystorePath", configuration.getSslKeystorePathFor(connectionType));
      assertEquals(connectionType + "-sslKeystoreType", configuration.getSslKeystoreTypeFor(connectionType));
      assertEquals(connectionType + "-sslKeystorePassword", configuration.getSslKeystorePasswordFor(connectionType));
      assertEquals(connectionType + "-sslTruststorePath", configuration.getSslTruststorePathFor(connectionType));
      assertEquals(connectionType + "-sslTruststoreType", configuration.getSslTruststoreTypeFor(connectionType));
      assertEquals(connectionType + "-sslTruststorePassword", configuration.getSslTruststorePasswordFor(connectionType));
      assertEquals(connectionType + "-sslProtocol", configuration.getSslProtocolFor(connectionType));
      assertEquals(
              Stream.of("sslProtocol1", "sslProtocol2", "sslProtocol3").map(p -> connectionType + "-" + p).collect(Collectors.toList()),
              configuration.getSupportedSslProtocolsFor(connectionType));
      assertEquals(
              Stream.of("sslCipherSuite1", "sslCipherSuite2").map(cs -> connectionType + "-" + cs).collect(Collectors.toList()),
              configuration.getSupportedSslCipherSuitesFor(connectionType));
    }
  }

  @Test
  public void getSslConfigurationFromConfigurationFile_genericParametersSet() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_generic_proxy_and_ssl_settings.yaml");
    assertTrue(configuration.isSslConfigurationEnabled());
    assertEquals("sslKeystorePath", configuration.getSslKeystorePath());
    assertEquals("sslKeystoreType", configuration.getSslKeystoreType());
    assertEquals("sslKeystorePassword", configuration.getSslKeystorePassword());
    assertEquals("sslTruststorePath", configuration.getSslTruststorePath());
    assertEquals("sslTruststoreType", configuration.getSslTruststoreType());
    assertEquals("sslTruststorePassword", configuration.getSslTruststorePassword());
    assertEquals("sslProtocol", configuration.getSslProtocol());
    assertEquals(Arrays.asList("sslProtocol1", "sslProtocol2", "sslProtocol3"), configuration.getSupportedSslProtocols());
    assertEquals(Arrays.asList("sslCipherSuite1", "sslCipherSuite2"), configuration.getSupportedSslCipherSuites());
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      assertTrue(configuration.isSslConfigurationEnabledFor(connectionType));
      assertEquals("sslKeystorePath", configuration.getSslKeystorePathFor(connectionType));
      assertEquals("sslKeystoreType", configuration.getSslKeystoreTypeFor(connectionType));
      assertEquals("sslKeystorePassword", configuration.getSslKeystorePasswordFor(connectionType));
      assertEquals("sslTruststorePath", configuration.getSslTruststorePathFor(connectionType));
      assertEquals("sslTruststoreType", configuration.getSslTruststoreTypeFor(connectionType));
      assertEquals("sslTruststorePassword", configuration.getSslTruststorePasswordFor(connectionType));
      assertEquals("sslProtocol", configuration.getSslProtocolFor(connectionType));
      assertEquals(Arrays.asList("sslProtocol1", "sslProtocol2", "sslProtocol3"), configuration.getSupportedSslProtocolsFor(connectionType));
      assertEquals(Arrays.asList("sslCipherSuite1", "sslCipherSuite2"), configuration.getSupportedSslCipherSuitesFor(connectionType));
    }
  }

  @Test
  public void getSslConfigurationFromConfigurationFile_specificParametersSet() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_specific_proxy_and_ssl_settings.yaml");
    assertTrue(configuration.isSslConfigurationEnabled());
    assertNull(configuration.getSslKeystorePath());
    assertNull(configuration.getSslKeystoreType());
    assertNull(configuration.getSslKeystorePassword());
    assertNull(configuration.getSslTruststorePath());
    assertNull(configuration.getSslTruststoreType());
    assertNull(configuration.getSslTruststorePassword());
    assertEquals(DEFAULT_TLS_PROTOCOL, configuration.getSslProtocol());
    assertEquals(DEFAULT_SUPPORTED_TLS_PROTOCOLS, configuration.getSupportedSslProtocols());
    assertEquals(DEFAULT_SUPPORTED_TLS_CIPHER_SUITES, configuration.getSupportedSslCipherSuites());
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      assertTrue(configuration.isSslConfigurationEnabledFor(connectionType));
      assertEquals(connectionType + "-sslKeystorePath", configuration.getSslKeystorePathFor(connectionType));
      assertEquals(connectionType + "-sslKeystoreType", configuration.getSslKeystoreTypeFor(connectionType));
      assertEquals(connectionType + "-sslKeystorePassword", configuration.getSslKeystorePasswordFor(connectionType));
      assertEquals(connectionType + "-sslTruststorePath", configuration.getSslTruststorePathFor(connectionType));
      assertEquals(connectionType + "-sslTruststoreType", configuration.getSslTruststoreTypeFor(connectionType));
      assertEquals(connectionType + "-sslTruststorePassword", configuration.getSslTruststorePasswordFor(connectionType));
      assertEquals(connectionType + "-sslProtocol", configuration.getSslProtocolFor(connectionType));
      assertEquals(
              Stream.of("sslProtocol1", "sslProtocol2", "sslProtocol3").map(p -> connectionType + "-" + p).collect(Collectors.toList()),
              configuration.getSupportedSslProtocolsFor(connectionType));
      assertEquals(
              Stream.of("sslCipherSuite1", "sslCipherSuite2").map(cs -> connectionType + "-" + cs).collect(Collectors.toList()),
              configuration.getSupportedSslCipherSuitesFor(connectionType));
    }
  }

  @Test
  public void testDefaultZipCompressionConfiguration() {
    assertEquals(1024 * 1024, configuration.getZipCompressionRatioCheckThresholdInBytes());
    assertEquals(100, configuration.getMaxAllowedZipCompressionRatio());
  }

  @Test
  public void getInvalidZipCompressionRatioCheckThresholdInBytes() {
    String expectedErrorMessage = "Configuration parameter ZIP_COMPRESSION_RATIO_CHECK_THRESHOLD_IN_BYTES " +
            "should have a long integer value but the actual value is: invalidValue.";

    ConfigurationException exception = assertThrows(
            ConfigurationException.class,
            () -> configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_invalid_zip_threshold.yaml")
    );

    assertThat(exception.getMessage(), containsString(expectedErrorMessage));
  }

  @Test
  public void getInvalidMaxAllowedZipCompressionRatio() {
    String expectedErrorMessage = "Configuration parameter MAX_ALLOWED_ZIP_COMPRESSION_RATIO " +
            "should have an integer value but the actual value is: invalidValue.";

    ConfigurationException exception = assertThrows(
            ConfigurationException.class,
            () -> configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_invalid_zip_ratio.yaml")
    );

    assertThat(exception.getMessage(), containsString(expectedErrorMessage));
  }

  @Test
  public void setZipCompressionRatioCheckThresholdInBytes() {
    configuration.setZipCompressionRatioCheckThresholdInBytes(1234567);
    assertEquals(1234567, configuration.getZipCompressionRatioCheckThresholdInBytes());
  }

  @Test
  public void setMaxAllowedZipCompressionRatio() {
    configuration.setMaxAllowedZipCompressionRatio(2345);
    assertEquals(2345, configuration.getMaxAllowedZipCompressionRatio());
  }

  @Test
  public void loadMultipleCAsFromConfigurationFile() {
    Hashtable<String, String> ddoc4jConf = configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_two_cas.yaml");
    configuration.getDDoc4JConfiguration();
    assertEquals("AS Sertifitseerimiskeskus", ddoc4jConf.get("DIGIDOC_CA_1_NAME"));
    assertEquals("jar://certs/ESTEID-SK.crt", ddoc4jConf.get("DIGIDOC_CA_1_CERT2"));
    assertEquals("Second CA", ddoc4jConf.get("DIGIDOC_CA_2_NAME"));
    assertEquals("jar://certs/CA_2_CERT_3.crt", ddoc4jConf.get("DIGIDOC_CA_2_CERT3"));
    assertEquals("jar://certs/CA_2_OCSP_1_SECOND_CERT", ddoc4jConf.get("DIGIDOC_CA_2_OCSP1_CERT_1"));
  }

  @Test
  public void missingCA_shouldNotThrowException() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_no_ca.yaml");
  }

  @Test
  public void missingCA_shouldThrowException_whenUsingDDoc() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_no_ca.yaml";
    String expectedErrorMessage = "Configuration from " + fileName + " contains error(s):\n" +
        "Empty or no DIGIDOC_CAS entry";
    configuration.loadConfiguration(fileName);

    ConfigurationException exception = assertThrows(
            ConfigurationException.class,
            () -> configuration.getDDoc4JConfiguration()
    );

    assertThat(exception.getMessage(), equalTo(expectedErrorMessage));
  }

  @Test
  public void emptyCAThrowsException() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_empty_ca.yaml";
    String expectedErrorMessage = "Configuration from " + fileName + " contains error(s):\n" +
        "Empty or no DIGIDOC_CA for entry 1";
    configuration.loadConfiguration(fileName);

    ConfigurationException exception = assertThrows(
            ConfigurationException.class,
            () -> configuration.getDDoc4JConfiguration()
    );

    assertThat(exception.getMessage(), equalTo(expectedErrorMessage));
  }

  @Test
  public void isTestMode() {
    assertTrue(configuration.isTest());
  }

  @Test
  public void isNotTestMode() {
    configuration = Configuration.of(Configuration.Mode.PROD);
    assertFalse(configuration.isTest());
  }

  @Test
  public void verifyAllOptionalConfigurationSettingsAreLoadedFromFile() {
    configuration.setLotlLocation("Set LOTL location");
    configuration.setTspSource("Set TSP source");
    configuration.setOCSPAccessCertificateFileName("Set OCSP access certificate file name");
    configuration.setOCSPAccessCertificatePassword("Set password".toCharArray());
    configuration.setOcspSource("Set OCSP source");
    configuration.setValidationPolicy("Set validation policy");
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    assertEquals("123876", getDDoc4JConfigurationValue("DIGIDOC_MAX_DATAFILE_CACHED"));
    assertEquals("TEST_DIGIDOC_NOTARY_IMPL", getDDoc4JConfigurationValue("DIGIDOC_NOTARY_IMPL"));
    assertEquals("TEST_DIGIDOC_OCSP_SIGN_CERT_SERIAL", getDDoc4JConfigurationValue("DIGIDOC_OCSP_SIGN_CERT_SERIAL"));
    assertEquals("TEST_DIGIDOC_SECURITY_PROVIDER", getDDoc4JConfigurationValue("DIGIDOC_SECURITY_PROVIDER"));
    assertEquals("TEST_DIGIDOC_SECURITY_PROVIDER_NAME", getDDoc4JConfigurationValue("DIGIDOC_SECURITY_PROVIDER_NAME"));
    assertEquals("TEST_DIGIDOC_TSLFAC_IMPL", getDDoc4JConfigurationValue("DIGIDOC_TSLFAC_IMPL"));
    assertEquals("false", getDDoc4JConfigurationValue("DIGIDOC_USE_LOCAL_TSL"));
    assertEquals("false", getDDoc4JConfigurationValue("KEY_USAGE_CHECK"));
    assertEquals("false", getDDoc4JConfigurationValue(SIGN_OCSP_REQUESTS));
    assertEquals("TEST_DIGIDOC_DF_CACHE_DIR", getDDoc4JConfigurationValue("DIGIDOC_DF_CACHE_DIR"));
    assertEquals("TEST_DIGIDOC_FACTORY_IMPL", getDDoc4JConfigurationValue("DIGIDOC_FACTORY_IMPL"));
    assertEquals("TEST_CANONICALIZATION_FACTORY_IMPL", getDDoc4JConfigurationValue("CANONICALIZATION_FACTORY_IMPL"));
    assertEquals("false", getDDoc4JConfigurationValue("DATAFILE_HASHCODE_MODE"));
    assertEquals("TEST_DIGIDOC_PKCS12_CONTAINER", configuration.getRegistry().get(ConfigurationParameter.OcspAccessCertificateFile).get(0));
    assertEquals("TEST_DIGIDOC_PKCS12_PASSWD", configuration.getRegistry().get(ConfigurationParameter.OcspAccessCertificatePassword).get(0));
    assertEquals("TEST_OCSP_SOURCE", configuration.getRegistry().get(ConfigurationParameter.OcspSource).get(0));
    assertEquals("TEST_TSP_SOURCE", configuration.getRegistry().get(ConfigurationParameter.TspSource).get(0));
    assertEquals("TEST_TSP_SOURCE_FOR_ARCHIVE_TIMESTAMPS", configuration.getRegistry().get(ConfigurationParameter.TspSourceForArchiveTimestamps).get(0));
    assertEquals("TEST_VALIDATION_POLICY", configuration.getRegistry().get(ConfigurationParameter.ValidationPolicy).get(0));
    assertEquals("TEST_LOTL_LOCATION", configuration.getRegistry().get(ConfigurationParameter.LotlLocation).get(0));
    assertEquals("true", configuration.getRegistry().get(ConfigurationParameter.preferAiaOcsp).get(0));
    assertEquals("73", configuration.getRegistry().get(ConfigurationParameter.ZipCompressionRatioCheckThreshold).get(0));
    assertEquals("37", configuration.getRegistry().get(ConfigurationParameter.MaxAllowedZipCompressionRatio).get(0));
    assertEquals("SHA384", configuration.getRegistry().get(ConfigurationParameter.ArchiveTimestampDigestAlgorithm).get(0));
    assertEquals("SHA512", configuration.getRegistry().get(ConfigurationParameter.ArchiveTimestampReferenceDigestAlgorithm).get(0));

    configuration.setLotlLocation("Set LOTL location");
    configuration.setTspSource("Set TSP source");
    configuration.setOCSPAccessCertificateFileName("Set OCSP access certificate file name");
    configuration.setOCSPAccessCertificatePassword("Set password".toCharArray());
    configuration.setOcspSource("Set OCSP source");
    configuration.setValidationPolicy("Set validation policy");
    assertEquals("Set LOTL location", configuration.getLotlLocation());
    assertEquals("Set TSP source", configuration.getTspSource());
    assertEquals("TEST_TSP_SOURCE_FOR_ARCHIVE_TIMESTAMPS", configuration.getTspSourceForArchiveTimestamps());
    assertEquals("Set OCSP access certificate file name", configuration.getOCSPAccessCertificateFileName());
    assertEquals("Set password", configuration.getRegistry().get(ConfigurationParameter.OcspAccessCertificatePassword).get(0));
    assertEquals("Set OCSP source", configuration.getOcspSource());
    assertEquals("Set validation policy", configuration.getValidationPolicy());
  }

  @Test
  public void getDefaultTempFileMaxAge() {
    assertEquals(86400000, configuration.getTempFileMaxAge());
  }

  @Test
  public void loadTempFileMaxAgeFromFile() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_temp_file_max_age.yaml");
    assertEquals(60, configuration.getTempFileMaxAge());
  }

  @Test
  public void setTempFileMaxAgeFromCode(){
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_temp_file_max_age.yaml");
    configuration.setTempFileMaxAge(1000);
    assertEquals(1000, configuration.getTempFileMaxAge());
  }

  @Test
  public void getDefaultConnectionTimeout() {
    assertEquals(60000, configuration.getConnectionTimeout());
    assertEquals(60000, configuration.getSocketTimeout());
  }

  @Test
  public void loadConnectionTimeoutFromFile() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_connection_timeout.yaml");
    assertEquals(4000, configuration.getConnectionTimeout());
    assertEquals(2000, configuration.getSocketTimeout());
  }

  @Test
  public void setConnectionTimeoutFromCode() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_connection_timeout.yaml");
    configuration.setConnectionTimeout(2000);
    configuration.setSocketTimeout(5000);
    assertEquals(2000, configuration.getConnectionTimeout());
    assertEquals(5000, configuration.getSocketTimeout());
  }

  @Test
  public void revocationAndTimestampDelta_shouldBeOneDay() {
    int oneDayInMinutes = 24 * 60;
    assertEquals(oneDayInMinutes, configuration.getRevocationAndTimestampDeltaInMinutes());
  }

  @Test
  public void testSettingRevocationAndTimestampDelta() {
    int twoDaysInMinutes = 48 * 60;
    configuration.setRevocationAndTimestampDeltaInMinutes(twoDaysInMinutes);
    assertEquals(twoDaysInMinutes, configuration.getRevocationAndTimestampDeltaInMinutes());
  }

  @Test
  public void testLoadingRevocationAndTimestampDeltaFromConf() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    assertEquals(1337, configuration.getRevocationAndTimestampDeltaInMinutes());
  }

  @Test
  public void getDefaultAllowedOcspProviders() {
    assertEquals(Arrays.asList(Constant.Test.DEFAULT_OCSP_RESPONDERS), configuration.getAllowedOcspRespondersForTM());
  }

  @Test
  public void loadAllowedOcspProvidersFromConf() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    List<String> allowedOcspRespondersForTM = configuration.getAllowedOcspRespondersForTM();
    assertEquals(3,allowedOcspRespondersForTM.size());
    assertEquals("SK OCSP RESPONDER 2011", allowedOcspRespondersForTM.get(0));
    assertEquals("ESTEID-SK 2007 OCSP RESPONDER", allowedOcspRespondersForTM.get(1));
    assertEquals("EID-SK 2007 OCSP RESPONDER", allowedOcspRespondersForTM.get(2));
  }

  @Test
  public void setAllowedOcspProviders() {
    configuration.setAllowedOcspRespondersForTM("ESTEID-SK OCSP RESPONDER 2005", "ESTEID-SK OCSP RESPONDER");
    List<String> allowedOcspResponders = configuration.getAllowedOcspRespondersForTM();
    assertEquals(2, allowedOcspResponders.size());
    assertEquals("ESTEID-SK OCSP RESPONDER 2005", allowedOcspResponders.get(0));
    assertEquals("ESTEID-SK OCSP RESPONDER", allowedOcspResponders.get(1));
  }

  @Test
  public void getTrustedTerritories_defaultTesting_shouldBeNull() {
    assertEquals(Collections.emptyList(), configuration.getTrustedTerritories());
  }

  @Test
  public void getTrustedTerritories_defaultProd() {
    configuration = Configuration.of(Configuration.Mode.PROD);
    List<String> trustedTerritories = configuration.getTrustedTerritories();
    assertNotNull(trustedTerritories);
    assertTrue(trustedTerritories.contains("EE"));
    assertTrue(trustedTerritories.contains("BE"));
    assertTrue(trustedTerritories.contains("NO"));
    assertTrue(trustedTerritories.contains("DE"));
    assertTrue(trustedTerritories.contains("HR"));
  }

  @Test
  public void setTrustedTerritories() {
    configuration.setTrustedTerritories("AR", "US", "CA");
    List<String> trustedTerritories = configuration.getTrustedTerritories();
    assertEquals(Arrays.asList("AR", "US", "CA"), trustedTerritories);
  }

  @Test
  public void loadTrustedTerritoriesFromConf() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    List<String> trustedTerritories = configuration.getTrustedTerritories();
    assertEquals(Arrays.asList("NZ", "AU", "BR"), trustedTerritories);
  }

  @Test
  public void loadYamlTrustedTerritoriesFromConf() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc4j_test_conf_territories_lists.yaml");
    List<String> trustedTerritories = configuration.getTrustedTerritories();
    assertEquals(Arrays.asList("AU", "NZ", "AR"), trustedTerritories);
  }

  @Test
  public void loadEmptyTrustedTerritoriesFromConf() throws Exception {
    configuration.setTrustedTerritories("EE");
    loadConfigurationFromString(configuration, "TRUSTED_TERRITORIES: []");
    List<String> trustedTerritories = configuration.getTrustedTerritories();
    assertEquals(Collections.emptyList(), trustedTerritories);
  }

  @Test
  public void getRequiredTerritories_defaultTesting_shouldBeNull() {
    assertEquals(Collections.emptyList(), configuration.getRequiredTerritories());
  }

  @Test
  public void getRequiredTerritories_defaultProd() {
    configuration = Configuration.of(Configuration.Mode.PROD);
    List<String> requiredTerritories = configuration.getRequiredTerritories();
    assertEquals(Collections.singletonList("EE"), requiredTerritories);
  }

  @Test
  public void setRequiredTerritories() {
    configuration.setRequiredTerritories("CU", "LV");
    List<String> requiredTerritories = configuration.getRequiredTerritories();
    assertEquals(Arrays.asList("CU", "LV"), requiredTerritories);
  }

  @Test
  public void loadRequiredTerritoriesFromConf() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    List<String> requiredTerritories = configuration.getRequiredTerritories();
    assertEquals(Arrays.asList("GB", "LT"), requiredTerritories);
  }

  @Test
  public void loadYamlRequiredTerritoriesFromConf() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc4j_test_conf_territories_lists.yaml");
    List<String> requiredTerritories = configuration.getRequiredTerritories();
    assertEquals(Arrays.asList("IE", "LV"), requiredTerritories);
  }

  @Test
  public void loadEmptyRequiredTerritoriesFromConf() throws Exception {
    configuration.setRequiredTerritories("EE");
    loadConfigurationFromString(configuration, "REQUIRED_TERRITORIES: []");
    List<String> requiredTerritories = configuration.getRequiredTerritories();
    assertEquals(Collections.emptyList(), requiredTerritories);
  }

  @Test
  public void aiaOcspPreferredByDefault_defaultTest() {
    assertTrue(configuration.isAiaOcspPreferred());
  }

  @Test
  public void aiaOcspPreferredByDefault_defaultProd() {
    assertTrue(Configuration.of(Configuration.Mode.PROD).isAiaOcspPreferred());
  }

  @Test
  public void getAiaOcspSourceByCN_defaultTest() {
    assertNull(configuration.getAiaOcspSourceByCN(null));
    assertNull(configuration.getAiaOcspSourceByCN("ESTEID2018"));
    assertNull(configuration.getAiaOcspSourceByCN("ESTEID-SK 2011"));
    assertNull(configuration.getAiaOcspSourceByCN("EID-SK 2011"));
    assertNull(configuration.getAiaOcspSourceByCN("KLASS3-SK 2010"));
    assertNull(configuration.getAiaOcspSourceByCN("ESTEID-SK 2015"));
    assertNull(configuration.getAiaOcspSourceByCN("EID-SK 2016"));
    assertNull(configuration.getAiaOcspSourceByCN("NQ-SK 2016"));
    assertNull(configuration.getAiaOcspSourceByCN("KLASS3-SK 2016"));
    assertEquals("http://aia.demo.sk.ee/esteid2018", configuration.getAiaOcspSourceByCN("TEST of ESTEID2018"));
    assertEquals("http://aia.demo.sk.ee/esteid2011", configuration.getAiaOcspSourceByCN("TEST of ESTEID-SK 2011"));
    assertEquals("http://aia.demo.sk.ee/eid2011", configuration.getAiaOcspSourceByCN("TEST of EID-SK 2011"));
    assertEquals("http://aia.demo.sk.ee/klass3-2010", configuration.getAiaOcspSourceByCN("TEST of KLASS3-SK 2010"));
    assertEquals("http://aia.demo.sk.ee/esteid2015", configuration.getAiaOcspSourceByCN("TEST of ESTEID-SK 2015"));
    assertEquals("http://aia.demo.sk.ee/eid2016", configuration.getAiaOcspSourceByCN("TEST of EID-SK 2016"));
    assertEquals("http://aia.demo.sk.ee/nq2016", configuration.getAiaOcspSourceByCN("TEST of NQ-SK 2016"));
    assertEquals("http://aia.demo.sk.ee/klass3-2016", configuration.getAiaOcspSourceByCN("TEST of KLASS3-SK 2016"));
  }

  @Test
  public void getAiaOcspSourceByCN_defaultProd() {
    Configuration configuration = Configuration.of(Configuration.Mode.PROD);
    assertNull(configuration.getAiaOcspSourceByCN(null));
    assertEquals("http://aia.sk.ee/esteid2018", configuration.getAiaOcspSourceByCN("ESTEID2018"));
    assertEquals("http://aia.sk.ee/esteid2011", configuration.getAiaOcspSourceByCN("ESTEID-SK 2011"));
    assertEquals("http://aia.sk.ee/eid2011", configuration.getAiaOcspSourceByCN("EID-SK 2011"));
    assertEquals("http://aia.sk.ee/klass3-2010", configuration.getAiaOcspSourceByCN("KLASS3-SK 2010"));
    assertEquals("http://aia.sk.ee/esteid2015", configuration.getAiaOcspSourceByCN("ESTEID-SK 2015"));
    assertEquals("http://aia.sk.ee/eid2016", configuration.getAiaOcspSourceByCN("EID-SK 2016"));
    assertEquals("http://aia.sk.ee/nq2016", configuration.getAiaOcspSourceByCN("NQ-SK 2016"));
    assertEquals("http://aia.sk.ee/klass3-2016", configuration.getAiaOcspSourceByCN("KLASS3-SK 2016"));
    assertNull(configuration.getAiaOcspSourceByCN("TEST of ESTEID2018"));
    assertNull(configuration.getAiaOcspSourceByCN("TEST of ESTEID-SK 2011"));
    assertNull(configuration.getAiaOcspSourceByCN("TEST of EID-SK 2011"));
    assertNull(configuration.getAiaOcspSourceByCN("TEST of KLASS3-SK 2010"));
    assertNull(configuration.getAiaOcspSourceByCN("TEST of ESTEID-SK 2015"));
    assertNull(configuration.getAiaOcspSourceByCN("TEST of EID-SK 2016"));
    assertNull(configuration.getAiaOcspSourceByCN("TEST of NQ-SK 2016"));
    assertNull(configuration.getAiaOcspSourceByCN("TEST of KLASS3-SK 2016"));
  }

  @Test
  public void getUseNonceForAiaOcspByCN_defaultTest() {
    assertTrue(configuration.getUseNonceForAiaOcspByCN(null));
    assertTrue(configuration.getUseNonceForAiaOcspByCN("TEST of ESTEID2018"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of ESTEID-SK 2011"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of EID-SK 2011"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of KLASS3-SK 2010"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of ESTEID-SK 2015"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of EID-SK 2016"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of NQ-SK 2016"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of KLASS3-SK 2016"));
  }

  @Test
  public void getUseNonceForAiaOcspByCN_defaultProd() {
    Configuration configuration = Configuration.of(Configuration.Mode.PROD);
    assertTrue(configuration.getUseNonceForAiaOcspByCN(null));
    assertTrue(configuration.getUseNonceForAiaOcspByCN("ESTEID2018"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("ESTEID-SK 2011"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("EID-SK 2011"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("KLASS3-SK 2010"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("ESTEID-SK 2015"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("EID-SK 2016"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("NQ-SK 2016"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("KLASS3-SK 2016"));
  }

  @Test
  public void testAiaOcspNotConfiguredThroughYamlShouldUseDefaults_customTest() throws Exception {
    loadConfigurationFromString(configuration, "");
    assertEquals("http://aia.demo.sk.ee/esteid2018", configuration.getAiaOcspSourceByCN("TEST of ESTEID2018"));
    assertTrue(configuration.getUseNonceForAiaOcspByCN("TEST of ESTEID2018"));
    assertEquals("http://aia.demo.sk.ee/esteid2011", configuration.getAiaOcspSourceByCN("TEST of ESTEID-SK 2011"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of ESTEID-SK 2011"));
    assertEquals("http://aia.demo.sk.ee/eid2011", configuration.getAiaOcspSourceByCN("TEST of EID-SK 2011"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of EID-SK 2011"));
    assertEquals("http://aia.demo.sk.ee/klass3-2010", configuration.getAiaOcspSourceByCN("TEST of KLASS3-SK 2010"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of KLASS3-SK 2010"));
    assertEquals("http://aia.demo.sk.ee/esteid2015", configuration.getAiaOcspSourceByCN("TEST of ESTEID-SK 2015"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of ESTEID-SK 2015"));
    assertEquals("http://aia.demo.sk.ee/eid2016", configuration.getAiaOcspSourceByCN("TEST of EID-SK 2016"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of EID-SK 2016"));
    assertEquals("http://aia.demo.sk.ee/nq2016", configuration.getAiaOcspSourceByCN("TEST of NQ-SK 2016"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of NQ-SK 2016"));
    assertEquals("http://aia.demo.sk.ee/klass3-2016", configuration.getAiaOcspSourceByCN("TEST of KLASS3-SK 2016"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of KLASS3-SK 2016"));
  }

  @Test
  public void testConfigureAdditionalAiaOcspThroughYaml_customTest() throws Exception {
    loadConfigurationFromString(configuration, "AIA_OCSPS:",
            "  - ISSUER_CN: OCSP NAME",
            "    OCSP_SOURCE: scheme://host/path",
            "    USE_NONCE: true");
    assertEquals("http://aia.demo.sk.ee/esteid2018", configuration.getAiaOcspSourceByCN("TEST of ESTEID2018"));
    assertTrue(configuration.getUseNonceForAiaOcspByCN("TEST of ESTEID2018"));
    assertEquals("http://aia.demo.sk.ee/esteid2011", configuration.getAiaOcspSourceByCN("TEST of ESTEID-SK 2011"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of ESTEID-SK 2011"));
    assertEquals("http://aia.demo.sk.ee/eid2011", configuration.getAiaOcspSourceByCN("TEST of EID-SK 2011"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of EID-SK 2011"));
    assertEquals("http://aia.demo.sk.ee/klass3-2010", configuration.getAiaOcspSourceByCN("TEST of KLASS3-SK 2010"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of KLASS3-SK 2010"));
    assertEquals("http://aia.demo.sk.ee/esteid2015", configuration.getAiaOcspSourceByCN("TEST of ESTEID-SK 2015"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of ESTEID-SK 2015"));
    assertEquals("http://aia.demo.sk.ee/eid2016", configuration.getAiaOcspSourceByCN("TEST of EID-SK 2016"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of EID-SK 2016"));
    assertEquals("http://aia.demo.sk.ee/nq2016", configuration.getAiaOcspSourceByCN("TEST of NQ-SK 2016"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of NQ-SK 2016"));
    assertEquals("http://aia.demo.sk.ee/klass3-2016", configuration.getAiaOcspSourceByCN("TEST of KLASS3-SK 2016"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of KLASS3-SK 2016"));
    assertEquals("scheme://host/path", configuration.getAiaOcspSourceByCN("OCSP NAME"));
    assertTrue(configuration.getUseNonceForAiaOcspByCN("OCSP NAME"));
  }

  @Test
  public void testReconfigureExistingAiaOcspThroughYaml_customTest() throws Exception {
    loadConfigurationFromString(configuration, "AIA_OCSPS:",
            "  - ISSUER_CN: TEST of ESTEID2018",
            "    OCSP_SOURCE: new-url-for-test-of-esteid-2018",
            "    USE_NONCE: false",
            "  - ISSUER_CN: TEST of ESTEID-SK 2011",
            "    OCSP_SOURCE: new-url-for-test-of-esteid-sk-2011",
            "    USE_NONCE: true");
    assertEquals("new-url-for-test-of-esteid-2018", configuration.getAiaOcspSourceByCN("TEST of ESTEID2018"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of ESTEID2018"));
    assertEquals("new-url-for-test-of-esteid-sk-2011", configuration.getAiaOcspSourceByCN("TEST of ESTEID-SK 2011"));
    assertTrue(configuration.getUseNonceForAiaOcspByCN("TEST of ESTEID-SK 2011"));
    assertEquals("http://aia.demo.sk.ee/eid2011", configuration.getAiaOcspSourceByCN("TEST of EID-SK 2011"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of EID-SK 2011"));
    assertEquals("http://aia.demo.sk.ee/klass3-2010", configuration.getAiaOcspSourceByCN("TEST of KLASS3-SK 2010"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of KLASS3-SK 2010"));
    assertEquals("http://aia.demo.sk.ee/esteid2015", configuration.getAiaOcspSourceByCN("TEST of ESTEID-SK 2015"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of ESTEID-SK 2015"));
    assertEquals("http://aia.demo.sk.ee/eid2016", configuration.getAiaOcspSourceByCN("TEST of EID-SK 2016"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of EID-SK 2016"));
    assertEquals("http://aia.demo.sk.ee/nq2016", configuration.getAiaOcspSourceByCN("TEST of NQ-SK 2016"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of NQ-SK 2016"));
    assertEquals("http://aia.demo.sk.ee/klass3-2016", configuration.getAiaOcspSourceByCN("TEST of KLASS3-SK 2016"));
    assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of KLASS3-SK 2016"));
  }

  @Test
  public void testConfigureNewAiaOcspThroughYaml_missingIssuerCN() {
    ConfigurationException exception = assertThrows(
            ConfigurationException.class,
            () -> loadConfigurationFromString(configuration, "AIA_OCSPS:",
              "  - OCSP_SOURCE: scheme://host/path",
              "    USE_NONCE: true")
    );

    assertThat(exception.getMessage(), containsString("No value found for an entry <ISSUER_CN(1)>"));
  }

  @Test
  public void testConfigureNewAiaOcspThroughYaml_missingOcspSource() {
    ConfigurationException exception = assertThrows(
            ConfigurationException.class,
            () -> loadConfigurationFromString(configuration, "AIA_OCSPS:", 
                    "  - ISSUER_CN: OCSP NAME", 
                    "    USE_NONCE: true")
    );

    assertThat(exception.getMessage(), containsString("No value found for an entry <OCSP_SOURCE(1)>"));
  }

  @Test
  public void testConfigureNewAiaOcspThroughYaml_missingUseNonce() {
    ConfigurationException exception = assertThrows(ConfigurationException.class,
            () -> loadConfigurationFromString(configuration, "AIA_OCSPS:",
                    "  - ISSUER_CN: OCSP NAME",
                    "    OCSP_SOURCE: scheme://host/path")
    );

    assertThat(exception.getMessage(), containsString("No value found for an entry <USE_NONCE(1)>"));
  }

  @Test
  public void testOpenBDocWithConfFromSetter() {
    configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setOcspSource("http://demo.sk.ee/TEST");
    ContainerBuilder.aContainer().withConfiguration(configuration).
        fromExistingFile("src/test/resources/testFiles/valid-containers/test.asice").build();
    assertEquals("http://demo.sk.ee/TEST", configuration.getOcspSource());
  }

  @Test
  public void testOpenBDocWithConfFromYaml() {
    configuration = Configuration.of(Configuration.Mode.PROD);
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_parameters.yaml");
    ContainerBuilder.aContainer().withConfiguration(configuration).
        fromExistingFile("src/test/resources/testFiles/valid-containers/test.asice").build();
    assertEquals("test_source_from_yaml", configuration.getOcspSource());
  }

  @Test
  public void testOpenBDocWithConfFromSetterWhenYamlParamPresented() {
    configuration = new Configuration(Configuration.Mode.PROD);
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_parameters.yaml");
    configuration.setOcspSource("http://demo.sk.ee/TEST");
    ContainerBuilder.aContainer().withConfiguration(configuration).
        fromExistingFile("src/test/resources/testFiles/valid-containers/test.asice").build();
    assertEquals("http://demo.sk.ee/TEST", configuration.getOcspSource());
  }

  @Test
  public void loadAllowedTimestampAndOCSPResponseDelta() {
    assertEquals(15, configuration.getAllowedTimestampAndOCSPResponseDeltaInMinutes().longValue());
  }

  @Test
  public void loadAllowedTimestampAndOCSPResponseDeltaFromConf() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    assertEquals(1, configuration.getAllowedTimestampAndOCSPResponseDeltaInMinutes().longValue());
  }

  @Test
  public void testLoadingSignatureProfile() {
    assertNull(configuration.getSignatureProfile());
  }

  @Test
  public void testLoadingSignatureProfileFromConf() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    assertEquals(SignatureProfile.LT_TM, configuration.getSignatureProfile());
  }

  @Test
  public void testLoadingSignatureDigestAlgorithm() {
    assertNull(configuration.getSignatureDigestAlgorithm());
  }

  @Test
  public void testLoadingSignatureDigestAlgorithmFromConf() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    assertEquals(DigestAlgorithm.SHA512, configuration.getSignatureDigestAlgorithm());
  }

  @Test
  public void testLoadingDataFileDigestAlgorithm() {
    assertNull(configuration.getDataFileDigestAlgorithm());
  }

  @Test
  public void testLoadingDataFileDigestAlgorithmFromConf() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    assertEquals(DigestAlgorithm.SHA512, configuration.getDataFileDigestAlgorithm());
  }

  @Test
  public void getArchiveTimestampDigestAlgorithm_WhenDefaultProdConfiguration_ReturnsNull() {
    Configuration configuration = Configuration.of(Configuration.Mode.PROD);
    assertNull(configuration.getArchiveTimestampDigestAlgorithm());
  }

  @Test
  public void getArchiveTimestampDigestAlgorithm_WhenDefaultTestConfiguration_ReturnsNull() {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    assertNull(configuration.getArchiveTimestampDigestAlgorithm());
  }

  @Test
  public void getArchiveTimestampDigestAlgorithm_WhenConfigurationLoadedFromFile_ReturnsLoadedValue() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_archive_timestamp.yaml");
    assertEquals(DigestAlgorithm.SHA256, configuration.getArchiveTimestampDigestAlgorithm());
  }

  @Test
  public void getArchiveTimestampReferenceDigestAlgorithm_WhenDefaultProdConfiguration_ReturnsNull() {
    Configuration configuration = Configuration.of(Configuration.Mode.PROD);
    assertNull(configuration.getArchiveTimestampReferenceDigestAlgorithm());
  }

  @Test
  public void getArchiveTimestampReferenceDigestAlgorithm_WhenDefaultTestConfiguration_ReturnsNull() {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    assertNull(configuration.getArchiveTimestampReferenceDigestAlgorithm());
  }

  @Test
  public void getArchiveTimestampReferenceDigestAlgorithm_WhenConfigurationLoadedFromFile_ReturnsLoadedValue() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_archive_timestamp.yaml");
    assertEquals(DigestAlgorithm.SHA384, configuration.getArchiveTimestampReferenceDigestAlgorithm());
  }

  @Test
  public void testConfigurationHasChanged() throws Exception {
    Configuration otherConfiguration = Configuration.of(Configuration.Mode.PROD);
    File file = createTemporaryFile();
    Helper.serialize(configuration, file);
    configuration = Helper.deserializer(file);
    assertTrue(isConfigurationsDifferent(otherConfiguration), "No differences");
  }

  @Test
  public void testConfigurationHasNotChanged() throws Exception {
    Configuration otherConfiguration = new Configuration(Configuration.Mode.TEST);
    File file = createTemporaryFile();
    Helper.serialize(configuration, file);
    configuration = Helper.deserializer(file);
    assertFalse(isConfigurationsDifferent(otherConfiguration), "Differences");
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    configuration = new Configuration(Configuration.Mode.TEST);
  }

  private boolean isConfigurationsDifferent(Configuration otherConfiguration) {
    if (StringUtils.isBlank(configuration.getRegistry().getSealValue())) {
      return false;
    }
    return !configuration.getRegistry().getSealValue().equals(otherConfiguration.getRegistry().generateSealValue());
  }

  private File generateConfigurationByParameter(String parameter) {
    return createTemporaryFileBy(String.format("%s\n" +
        "DIGIDOC_CAS:\n" +
        "- DIGIDOC_CA:\n" +
        "    NAME: AS Sertifitseerimiskeskus\n" +
        "    TRADENAME: SK\n" +
        "    CERTS:\n" +
        "      - jar://certs/EID-SK.crt\n" +
        "    OCSPS:\n" +
        "      - OCSP:\n" +
        "        CA_CN: ESTEID-SK\n" +
        "        CA_CERT: jar://certs/ESTEID-SK 2007.crt\n" +
        "        CN: ESTEID-SK 2007 OCSP RESPONDER\n" +
        "        CERTS:\n" +
        "         - jar://certs/ESTEID-SK 2007 OCSP.crt\n" +
        "        URL: http://ocsp.sk.ee", parameter));
  }

  private static void loadConfigurationFromString(Configuration configuration, String... lines) throws Exception {
    String concatenatedString = String.join("\n", lines);
    try (InputStream in = new ByteArrayInputStream(concatenatedString.getBytes(StandardCharsets.UTF_8))) {
      configuration.loadConfiguration(in);
    }
  }

}
