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
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.tsl.ConditionForQualifiers;
import eu.europa.esig.dss.spi.tsl.TrustProperties;
import eu.europa.esig.dss.spi.tsl.TrustServiceStatusAndInformationExtensions;
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
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.junit.Assert.assertFalse;

public class ConfigurationTest extends AbstractTest {

  private final Logger log = LoggerFactory.getLogger(ConfigurationTest.class);
  private static final String SIGN_OCSP_REQUESTS = "SIGN_OCSP_REQUESTS";
  private static final String OCSP_PKCS12_CONTAINER = "DIGIDOC_PKCS12_CONTAINER";
  private static final String OCSP_PKCS_12_PASSWD = "DIGIDOC_PKCS12_PASSWD";

  @Test
  public void getLotlLocationWhenNotFileURL() {
    String lotlLocation = "URL:test";
    this.configuration.setLotlLocation(lotlLocation);
    Assert.assertEquals(lotlLocation, this.configuration.getLotlLocation());
    Assert.assertEquals(lotlLocation, this.configuration.getTslLocation());
  }

  @Test
  public void lotlLocationAndTslLocationReferToTheSameValue() {
    String lotlLocation = "URL:test";
    this.configuration.setLotlLocation(lotlLocation);
    Assert.assertEquals(lotlLocation, this.configuration.getLotlLocation());
    Assert.assertEquals(lotlLocation, this.configuration.getTslLocation());
    String tslLocation = "URL:test2";
    this.configuration.setTslLocation(tslLocation);
    Assert.assertEquals(tslLocation, this.configuration.getLotlLocation());
    Assert.assertEquals(tslLocation, this.configuration.getTslLocation());
  }

  @Test
  public void TSLIsLoadedOnlyOnceForGlobalConfiguration() {
    TSLCertificateSource tsl = this.configuration.getTSL();
    Assert.assertEquals(tsl, this.configuration.getTSL());
  }

  @Test
  public void addTSL()  {
    TSLCertificateSource source = this.configuration.getTSL();
    int numberOfTSLCertificates = source.getCertificates().size();
    this.addCertificateToTSL(Paths.get("src/test/resources/testFiles/certs/Juur-SK.pem.crt"), source);
    Assert.assertEquals(numberOfTSLCertificates + 1, this.configuration.getTSL().getCertificates().size());
  }

  @Test
  public void addingCertificateToTsl() {
    TSLCertificateSource source = new TSLCertificateSourceImpl();
    this.addCertificateToTSL(Paths.get("src/test/resources/testFiles/certs/Juur-SK.pem.crt"), source);
    CertificateToken certificateToken = source.getCertificates().get(0);
    Assert.assertThat(certificateToken.getKeyUsageBits(), hasItem(KeyUsageBit.NON_REPUDIATION));
    Assert.assertTrue(certificateToken.checkKeyUsage(KeyUsageBit.NON_REPUDIATION));
    List<TrustProperties> associatedTSPS = source.getTrustServices(certificateToken);
    TrustProperties trustProperties = associatedTSPS.iterator().next();
    TrustServiceStatusAndInformationExtensions informationExtensions = trustProperties.getTrustService().getLatest();
    Assert.assertEquals("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision", informationExtensions.getStatus());
    Assert.assertEquals("http://uri.etsi.org/TrstSvc/Svctype/CA/QC", informationExtensions.getType());
    Assert.assertNotNull(informationExtensions.getStartDate());
    List<ConditionForQualifiers> qualifiersAndConditions = informationExtensions.getConditionsForQualifiers();
    Assert.assertTrue(qualifiersAndConditions.get(0).getQualifiers().contains("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD"));
  }

  @Test
  public void addingSameCertificateToTSLMultipleTimes_certNumberRemainsSameButServiceInfoIsDuplicated() {
    Path certificatePath = Paths.get("src/test/resources/testFiles/certs/Juur-SK.pem.crt");
    TSLCertificateSource source = new TSLCertificateSourceImpl();

    this.addCertificateToTSL(certificatePath, source);
    Assert.assertSame(source.getCertificates().size(), 1);
    CertificateToken certificateToken = source.getCertificates().get(0);
    Assert.assertSame(source.getTrustServices(certificateToken).size(), 1);

    this.addCertificateToTSL(certificatePath, source);
    Assert.assertSame(source.getCertificates().size(), 1);
    certificateToken = source.getCertificates().get(0);
    Assert.assertSame(source.getTrustServices(certificateToken).size(), 2);

    this.addCertificateToTSL(certificatePath, source);
    Assert.assertSame(source.getCertificates().size(), 1);
    certificateToken = source.getCertificates().get(0);
    Assert.assertSame(source.getTrustServices(certificateToken).size(), 3);
  }

  @Test
  public void clearTSLLoadsFromConfiguration() {
    TSLCertificateSource tsl = this.configuration.getTSL();
    int numberOfTSLCertificates = tsl.getCertificates().size();
    this.configuration.setTSL(null);
    Assert.assertEquals(numberOfTSLCertificates, this.configuration.getTSL().getCertificates().size());
  }

  @Test
  public void setTSL() throws IOException, CertificateException {
    TSLCertificateSource source = new TSLCertificateSourceImpl();
    this.addCertificateToTSL(Paths.get("src/test/resources/testFiles/certs/Juur-SK.pem.crt"), source);
    this.configuration.setTSL(source);
    Assert.assertEquals(1, this.configuration.getTSL().getCertificates().size());
  }

  @SuppressWarnings("ConstantConditions")
  @Ignore("Ignored till problem with file times are solved")
  @Test
  public void clearTSLCache() throws Exception {
    // TODO: find out why file times are equal; till then ignore
    File fileCacheDirectory = TslLoader.fileCacheDirectory;
    if (fileCacheDirectory.exists()) {
      FileUtils.cleanDirectory(fileCacheDirectory);
    }
    TSLCertificateSource tslCertificateSource = this.configuration.getTSL();
    tslCertificateSource.refresh();
    TestCommonUtil.sleepInSeconds(1);
    File oldCachedFile = fileCacheDirectory.listFiles()[0];
    FileTime oldCachedFileDate = (FileTime) Files.getAttribute(oldCachedFile.toPath(),
        "basic:creationTime");

    tslCertificateSource.invalidateCache();
    this.configuration.setTSL(null);
    tslCertificateSource = this.configuration.getTSL();
    tslCertificateSource.refresh();
    File newCachedFile = fileCacheDirectory.listFiles()[0];
    FileTime newCachedFileDate = TestFileUtil.creationTime(newCachedFile.toPath());
    Assert.assertTrue(newCachedFileDate.compareTo(oldCachedFileDate) > 0);
  }

  @Test
  public void getTsl_whenCacheIsNotExpired_shouldUseCachedTsl() {
    TestTSLUtil.evictCache();
    this.configuration.setTslCacheExpirationTime(10000L);
    TSLCertificateSource tsl1 = this.configuration.getTSL();
    tsl1.refresh();
    long lastModified1 = TestTSLUtil.getCacheLastModified();
    TestCommonUtil.sleepInSeconds(1);
    TSLCertificateSource tsl2 = this.configuration.getTSL();
    tsl2.refresh();
    Assert.assertEquals(lastModified1, TestTSLUtil.getCacheLastModified());
    Assert.assertSame(tsl1, tsl2);
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
    Assert.assertTrue(lastModified < newModificationTime);
    Assert.assertSame(tsl, newTsl);
  }

  @Test
  public void lotlValidationFailsWithWrongCertsInTruststore() {
    this.configuration = new Configuration(Configuration.Mode.PROD);
    this.configuration.setLotlTruststorePath("truststores/test-lotl-truststore.p12");
    try {
      this.configuration.getTSL();
    } catch (TslCertificateSourceInitializationException e) {
      Assert.assertEquals("Not ETSI compliant signature. The signature is not valid.", e.getMessage());
    }
  }

  @Test(expected = TslRefreshException.class)
  public void lotlLoadingWithNoLotlSslCertificateInTruststoreUsingDefaultTslCallback() {
    configuration.setSslTruststorePath("classpath:testFiles/truststores/empty-truststore.p12");
    configuration.setSslTruststorePassword("digidoc4j-password");
    configuration.setSslTruststoreType("PKCS12");
    evictTSLCache();
    configuration.getTSL().refresh();
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
    Assert.assertTrue("Certificate path should not be trusted", validationResult.getErrors().stream()
            .anyMatch(e -> "The certificate chain for signature is not trusted, it does not contain a trust anchor.".equals(e.getMessage())));
  }

  @Test
  public void addedTSLIsValid() {
    TSLCertificateSource source = this.configuration.getTSL();
    this.addCertificateToTSL(Paths.get("src/test/resources/testFiles/certs/Juur-SK.pem.crt"), source);
    this.addCertificateToTSL(Paths.get("src/test/resources/testFiles/certs/EE_Certification_Centre_Root_CA.pem.crt"), source);
    this.addCertificateToTSL(Paths.get("src/test/resources/testFiles/certs/ESTEID-SK_2011.pem.crt"), source);
    this.addCertificateToTSL(Paths.get("src/test/resources/testFiles/certs/SK_OCSP_RESPONDER_2011.pem.cer"), source);
    this.addCertificateToTSL(Paths.get("src/test/resources/testFiles/certs/SK_TSA.pem.crt"), source);
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/test.asice", this.configuration);
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void policyFileIsReadFromNonDefaultFileLocation() {
    this.configuration.setValidationPolicy("src/test/resources/testFiles/constraints/moved_constraint.xml");
    ContainerOpener.open("src/test/resources/testFiles/invalid-containers/asics_for_testing.bdoc", this.configuration);
  }

  @Test
  public void TSLIsLoadedAfterSettingNewLOTLLocation() throws Exception {
    this.configuration.setLotlLocation("https://open-eid.github.io/test-TL/tl-mp-test-EE.xml");
    BDocContainer container = (BDocContainer) ContainerBuilder.aContainer(Container.DocumentType.BDOC)
        .withConfiguration(this.configuration).build();
    container.getConfiguration().getTSL();
    Assert.assertEquals(15, container.getConfiguration().getTSL().getCertificates().size());

    int tenSeconds = 10000;
    String lotlHost = "10.0.25.57";
    if (InetAddress.getByName(lotlHost).isReachable(tenSeconds)) {
      this.configuration.setLotlLocation("http://" + lotlHost + "/tsl/trusted-test-mp.xml");
      container = (BDocContainer) ContainerBuilder.aContainer(Container.DocumentType.BDOC).
          withConfiguration(this.configuration).build();
      Assert.assertNotEquals(5, container.getConfiguration().getTSL().getCertificates().size());
    } else {
      this.log.error("Host <{}> is unreachable", lotlHost);
    }
  }

  @Test
  public void LOTLFileNotFoundThrowsNoException() {
    this.configuration.setLotlLocation("file:test-lotl/NotExisting.xml");
    this.configuration.setTslRefreshCallback(new MockTSLRefreshCallback(true));
    BDocContainer container = (BDocContainer) ContainerBuilder.
        aContainer(Container.DocumentType.BDOC).
        withConfiguration(this.configuration).
        build();
    container.getConfiguration().getTSL().refresh();
    Assert.assertEquals(0, this.configuration.getTSL().getCertificates().size());
  }

  @Test
  public void LOTLConnectionFailureThrowsNoException() {
    this.configuration.setLotlLocation("http://127.0.0.1/lotl/incorrect.xml");
    this.configuration.setTslRefreshCallback(new MockTSLRefreshCallback(true));
    BDocContainer container = (BDocContainer) ContainerBuilder.
        aContainer(Container.DocumentType.BDOC).
        withConfiguration(this.configuration).
        build();
    container.getConfiguration().getTSL().refresh();
    Assert.assertEquals(0, this.configuration.getTSL().getCertificates().size());
  }

  @Test
  public void testLoadConfiguration() {
    BDocContainer container = (BDocContainer) ContainerBuilder.
        aContainer(Container.DocumentType.BDOC).
        withConfiguration(this.configuration).
        build();
    Assert.assertTrue(container.getConfiguration().storeDataFilesOnlyInMemory());
    container.getConfiguration().loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    Assert.assertFalse(container.getConfiguration().storeDataFilesOnlyInMemory());
    Assert.assertEquals(8192, container.getConfiguration().getMaxDataFileCachedInMB());
  }

  @Test
  public void whenLOTLLocationIsMalformedURLNoErrorIsRaisedAndThisSameValueIsReturned() {
    String lotlLocation = "file://C:\\";
    this.configuration.setLotlLocation(lotlLocation);
    Assert.assertEquals(lotlLocation, configuration.getLotlLocation());
  }

  @Test
  public void getLOTLLocationFileDoesNotExistReturnsUrlPath() {
    String lotlLocation = ("file:conf/does-not-exist.xml");
    this.configuration.setLotlLocation(lotlLocation);
    Assert.assertEquals(this.configuration.getLotlLocation(), lotlLocation);
  }

  @Test
  public void setLotlLocation() {
    this.configuration.setLotlLocation("lotlLocation");
    Assert.assertEquals("lotlLocation", this.configuration.getLotlLocation());
    Assert.assertEquals("lotlLocation", this.configuration.getTslLocation());
  }

  @Test
  public void setTslLocation() {
    this.configuration.setTslLocation("tslLocation");
    Assert.assertEquals("tslLocation", this.configuration.getLotlLocation());
    Assert.assertEquals("tslLocation", this.configuration.getTslLocation());
  }

  @Test
  public void getLotlLocationFromConfigurationFile() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    Assert.assertEquals("TEST_LOTL_LOCATION", this.configuration.getLotlLocation());
    Assert.assertEquals("TEST_LOTL_LOCATION", this.configuration.getTslLocation());
  }

  @Test
  public void getTslLocationFromConfigurationFile() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_tsl_location_and_keystore.yaml");
    Assert.assertEquals("file:conf/test_TSLLocation", this.configuration.getLotlLocation());
    Assert.assertEquals("file:conf/test_TSLLocation", this.configuration.getTslLocation());
  }

  @Test
  public void setLotlLocationOverwritesConfigurationFile() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    this.configuration.setLotlLocation("lotlLocation");
    Assert.assertEquals("lotlLocation", this.configuration.getLotlLocation());
    Assert.assertEquals("lotlLocation", this.configuration.getTslLocation());
  }

  @Test
  public void setTspSource() {
    this.configuration.setTspSource("tspSource");
    Assert.assertEquals("tspSource", this.configuration.getTspSource());
  }

  @Test
  public void setValidationPolicy() {
    this.configuration.setValidationPolicy("policy");
    Assert.assertEquals("policy", this.configuration.getValidationPolicy());
  }

  @Test
  public void setOcspSource() {
    this.configuration.setOcspSource("ocsp_source");
    Assert.assertEquals("ocsp_source", this.configuration.getOcspSource());
  }

  @Test
  public void setUseOcspNonce() {
    Assert.assertTrue(this.configuration.isOcspNonceUsed());
    this.configuration.setUseOcspNonce(false);
    Assert.assertFalse(this.configuration.isOcspNonceUsed());
  }

  @Test
  public void defaultOCSPAccessCertificateFile() {
    Assert.assertEquals("", this.configuration.getOCSPAccessCertificateFileName());
    Assert.assertEquals("", this.getDDoc4JConfigurationValue(OCSP_PKCS12_CONTAINER));
  }

  @Test
  public void getOCSPAccessCertificateFileFromConfigurationFile() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    Assert.assertEquals("conf/OCSP_access_certificate_test_file_name", this.configuration.getOCSPAccessCertificateFileName());
    Assert.assertEquals("conf/OCSP_access_certificate_test_file_name", this.getDDoc4JConfigurationValue(OCSP_PKCS12_CONTAINER));
  }

  @Test
  public void getOCSPAccessCertificateFileFromStream() throws Exception {
    try (InputStream inputStream = new FileInputStream("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml")) {
      this.configuration.loadConfiguration(inputStream);
    }
    Assert.assertEquals("conf/OCSP_access_certificate_test_file_name", this.configuration.getOCSPAccessCertificateFileName());
    Assert.assertEquals("conf/OCSP_access_certificate_test_file_name", this.getDDoc4JConfigurationValue(OCSP_PKCS12_CONTAINER));
  }

  @Test
  public void setOCSPAccessCertificateFileNameOverwritesConfigurationFile() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    this.configuration.setOCSPAccessCertificateFileName("New File");
    Assert.assertEquals("New File", configuration.getOCSPAccessCertificateFileName());
    Assert.assertEquals("New File", this.getDDoc4JConfigurationValue(OCSP_PKCS12_CONTAINER));
  }

  @Test
  public void defaultOCSPAccessCertificatePassword() {
    Assert.assertEquals(0, this.configuration.getOCSPAccessCertificatePassword().length);
    Assert.assertNull(this.getDDoc4JConfigurationValue(OCSP_PKCS_12_PASSWD));
  }

  @Test
  public void getOCSPAccessCertificatePasswordFromConfigurationFile() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    Assert.assertArrayEquals("OCSP_test_password".toCharArray(), this.configuration.getOCSPAccessCertificatePassword());
    Assert.assertEquals("OCSP_test_password", this.getDDoc4JConfigurationValue(OCSP_PKCS_12_PASSWD));
  }

  @Test
  public void setOCSPAccessCertificatePasswordOverwritesConfigurationFile() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    char[] newPassword = "New password".toCharArray();
    this.configuration.setOCSPAccessCertificatePassword(newPassword);
    Assert.assertArrayEquals(newPassword, this.configuration.getOCSPAccessCertificatePassword());
    Assert.assertEquals("New password", this.getDDoc4JConfigurationValue(OCSP_PKCS_12_PASSWD));
  }

  @Test
  public void signingOcspRequest_ShouldBeDisabled_InProdByDefault() {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    Assert.assertFalse(this.configuration.hasToBeOCSPRequestSigned());
    Assert.assertEquals("false", this.getDDoc4JConfigurationValue(SIGN_OCSP_REQUESTS));
  }

  @Test
  public void signingOcspRequest_ShouldBeDisabled_InTestByDefault() {
    Assert.assertFalse(this.configuration.hasToBeOCSPRequestSigned());
    Assert.assertEquals("false", this.getDDoc4JConfigurationValue(SIGN_OCSP_REQUESTS));
  }

  @Test
  public void disableSigningOcspRequestsInProd() {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    this.configuration.setSignOCSPRequests(false);
    Assert.assertFalse(this.configuration.hasToBeOCSPRequestSigned());
    Assert.assertEquals("false", this.getDDoc4JConfigurationValue(SIGN_OCSP_REQUESTS));
  }

  @Test
  public void enableSigningOcspRequestsInTest() {
    this.configuration.setSignOCSPRequests(true);
    Assert.assertTrue(this.configuration.hasToBeOCSPRequestSigned());
    Assert.assertEquals("true", this.getDDoc4JConfigurationValue(SIGN_OCSP_REQUESTS));
  }

  @Test
  public void loadDisableSigningOcspRequestFromConfFileInProd() {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    Assert.assertFalse(this.configuration.hasToBeOCSPRequestSigned());
    Assert.assertEquals("false", this.getDDoc4JConfigurationValue(SIGN_OCSP_REQUESTS));
  }

  @Test
  public void loadDisableSigningOcspRequestFromConfFile() {
    this.configuration.loadConfiguration(this.generateConfigurationByParameter("SIGN_OCSP_REQUESTS: false").getPath());
    Assert.assertFalse(this.configuration.hasToBeOCSPRequestSigned());
    Assert.assertEquals("false", this.getDDoc4JConfigurationValue(SIGN_OCSP_REQUESTS));
  }

  @Test
  public void loadEnableSigningOcspRequestFromConfFile() {
    this.configuration.loadConfiguration(this.generateConfigurationByParameter("SIGN_OCSP_REQUESTS: true").getPath());
    Assert.assertTrue(configuration.hasToBeOCSPRequestSigned());
    Assert.assertEquals("true", this.getDDoc4JConfigurationValue(SIGN_OCSP_REQUESTS));
  }

  @Test
  public void defaultOcspSource() {
    Assert.assertEquals("http://demo.sk.ee/ocsp", this.configuration.getOcspSource());
  }

  @Test
  public void defaultProductionConfiguration() {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    Assert.assertEquals("https://ec.europa.eu/tools/lotl/eu-lotl.xml",
        this.configuration.getLotlLocation());
  }

  @Test
  public void defaultConstructorWithSetSystemProperty() {
    this.configuration = new Configuration();
    Assert.assertEquals("https://open-eid.github.io/test-TL/tl-mp-test-EE.xml", this.configuration.getLotlLocation());
  }

  @Test
  public void setMaxDataFileCached() {
    long maxDataFileCached = 12345;
    this.configuration.setMaxFileSizeCachedInMemoryInMB(maxDataFileCached);
    Assert.assertEquals(maxDataFileCached, this.configuration.getMaxDataFileCachedInMB());
    Assert.assertEquals(maxDataFileCached * Constant.ONE_MB_IN_BYTES, this.configuration.getMaxDataFileCachedInBytes());
  }

  @Test
  public void setMaxDataFileCachedToNoCaching() {
    long maxDataFileCached = Constant.CACHE_NO_DATA_FILES;
    this.configuration.setMaxFileSizeCachedInMemoryInMB(maxDataFileCached);
    Assert.assertEquals(Constant.CACHE_NO_DATA_FILES, this.configuration.getMaxDataFileCachedInMB());
    Assert.assertEquals(Constant.CACHE_NO_DATA_FILES, this.configuration.getMaxDataFileCachedInBytes());
  }

  @Test
  public void setMaxDataFileCachedToAllCaching() {
    long maxDataFileCached = Constant.CACHE_ALL_DATA_FILES;
    this.configuration.setMaxFileSizeCachedInMemoryInMB(maxDataFileCached);
    Assert.assertEquals(Constant.CACHE_ALL_DATA_FILES, this.configuration.getMaxDataFileCachedInMB());
    Assert.assertEquals(Constant.CACHE_ALL_DATA_FILES, this.configuration.getMaxDataFileCachedInBytes());
  }

  @Test
  public void maxDataFileCachedNotAllowedValue() {
    long oldValue = 4096;
    this.configuration.setMaxFileSizeCachedInMemoryInMB(oldValue);
    this.configuration.setMaxFileSizeCachedInMemoryInMB(-2);
    Assert.assertEquals(oldValue, this.configuration.getMaxDataFileCachedInMB());
  }

  @Test
  public void maxDataFileCachedNotAllowedValueFromFile() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_max_datafile_cached_invalid.yaml";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage("Configuration parameter DIGIDOC_MAX_DATAFILE_CACHED should be greater or equal " +
        "-1 but the actual value is: -2.");
    this.configuration.loadConfiguration(fileName);
  }

  @Test
  public void defaultConstructorWithUnSetSystemProperty() {
    this.clearGlobalMode();
    this.configuration = new Configuration();
    Assert.assertEquals("https://ec.europa.eu/tools/lotl/eu-lotl.xml",
        this.configuration.getLotlLocation());
  }

  @Test
  public void generateDDoc4JConfig() {
    Hashtable<String, String> ddoc4jConf = this.configuration.loadConfiguration("src/main/resources/digidoc4j.yaml");
    this.configuration.getDDoc4JConfiguration();
    Assert.assertEquals("jar://certs/ESTEID-SK.crt", ddoc4jConf.get("DIGIDOC_CA_1_CERT2"));
    Assert.assertEquals("jar://certs/KLASS3-SK OCSP 2006.crt", ddoc4jConf.get("DIGIDOC_CA_1_OCSP2_CERT_1"));
    Assert.assertEquals("jar://certs/EID-SK OCSP 2006.crt", ddoc4jConf.get("DIGIDOC_CA_1_OCSP13_CERT_1"));
    Assert.assertEquals("jar://certs/TEST Juur-SK.crt", ddoc4jConf.get("DIGIDOC_CA_1_CERT19"));
    Assert.assertEquals(Constant.DDoc4J.SECURITY_PROVIDER, ddoc4jConf.get("DIGIDOC_SECURITY_PROVIDER"));
    Assert.assertEquals(Constant.DDoc4J.SECURITY_PROVIDER_NAME, ddoc4jConf.get("DIGIDOC_SECURITY_PROVIDER_NAME"));
    Assert.assertEquals("false", ddoc4jConf.get("DATAFILE_HASHCODE_MODE"));
    Assert.assertEquals(Constant.DDoc4J.CANONICALIZATION_FACTORY_IMPLEMENTATION, ddoc4jConf.get("CANONICALIZATION_FACTORY_IMPL"));
    Assert.assertEquals("-1", ddoc4jConf.get("DIGIDOC_MAX_DATAFILE_CACHED"));
    Assert.assertEquals("false", ddoc4jConf.get(SIGN_OCSP_REQUESTS));
    Assert.assertEquals("jar://certs/KLASS3-SK OCSP.crt", ddoc4jConf.get("DIGIDOC_CA_1_OCSP2_CERT"));
  }

  @Test
  public void loadsDDoc4JSecurityProviderFromFile() {
    Hashtable<String, String> ddoc4jConf = this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    Assert.assertEquals("org.bouncycastle.jce.provider.BouncyCastleProvider1", ddoc4jConf.get("DIGIDOC_SECURITY_PROVIDER"));
  }

  @Test
  public void loadsDDoc4JCacheDirectoryFromFile() {
    Hashtable<String, String> ddoc4jConf = this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    Assert.assertEquals("/test_cache_dir", ddoc4jConf.get("DIGIDOC_DF_CACHE_DIR"));
  }

  @Test
  public void defaultDDoc4JCacheDirectory() {
    Hashtable<String, String> ddoc4jConf =
        this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_without_cache_dir.yaml");
    Assert.assertNull(ddoc4jConf.get("DIGIDOC_DF_CACHE_DIR"));
  }

  @Test
  public void loadsMaxDataFileCachedFromFile() {
    Hashtable<String, String> ddoc4jConf = this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    Assert.assertEquals("8192", ddoc4jConf.get("DIGIDOC_MAX_DATAFILE_CACHED"));
    Assert.assertEquals(8192, this.configuration.getMaxDataFileCachedInMB());
    Assert.assertEquals(8192 * Constant.ONE_MB_IN_BYTES, this.configuration.getMaxDataFileCachedInBytes());
  }

  @Test
  public void settingNonExistingConfigurationFileThrowsError() {
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage("File src/test/resources/testFiles/not_exists.yaml not found in classpath.");
    this.configuration.loadConfiguration("src/test/resources/testFiles/not_exists.yaml");
  }

  @Test
  public void digiDocSecurityProviderDefaultValue() {
    Hashtable<String, String> ddoc4jConf = this.configuration.loadConfiguration("src/main/resources/digidoc4j.yaml");
    Assert.assertEquals(Constant.DDoc4J.SECURITY_PROVIDER, ddoc4jConf.get("DIGIDOC_SECURITY_PROVIDER"));
  }

  @Test
  public void digiDocSecurityProviderDefaultName() {
    Hashtable<String, String> ddoc4jConf = this.configuration.loadConfiguration("src/main/resources/digidoc4j.yaml");
    Assert.assertEquals(Constant.DDoc4J.SECURITY_PROVIDER_NAME, ddoc4jConf.get("DIGIDOC_SECURITY_PROVIDER_NAME"));
  }

  @Test
  public void asksValueOfNonExistingParameter() {
    Hashtable<String, String> ddoc4jConf = this.configuration.loadConfiguration("src/main/resources/digidoc4j.yaml");
    Assert.assertNull(ddoc4jConf.get("DIGIDOC_PROXY_HOST"));
  }

  @Test
  public void digidocMaxDataFileCachedParameterIsNotANumber() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_invalid_max_data_file_cached.yaml";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage("Configuration parameter DIGIDOC_MAX_DATAFILE_CACHED" +
        " should have an integer value but the actual value is: 8192MB.");
    this.configuration.loadConfiguration(fileName);
  }

  @Test
  public void digidocSignOcspRequestIsNotABoolean() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_invalid_sign_ocsp_request.yaml";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage("Configuration parameter SIGN_OCSP_REQUESTS should be set to true or false" +
        " but the actual value is: NonBooleanValue.");
    this.configuration.loadConfiguration(fileName);
  }

  @Test
  public void digidocKeyUsageCheckIsNotABoolean() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_invalid_key_usage.yaml";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage("Configuration parameter KEY_USAGE_CHECK should be set to true or false" +
        " but the actual value is: NonBooleanValue.");
    this.configuration.loadConfiguration(fileName);
  }

  @Test
  public void digidocUseLocalTslIsNotABoolean() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_invalid_use_local_tsl.yaml";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage("Configuration parameter DIGIDOC_USE_LOCAL_TSL should be set to true or false" +
        " but the actual value is: NonBooleanValue.");
    this.configuration.loadConfiguration(fileName);
  }

  @Test
  public void digidocDataFileHashcodeModeIsNotABoolean() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_invalid_datafile_hashcode_mode.yaml";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage("Configuration parameter DATAFILE_HASHCODE_MODE should be set to true or false" +
        " but the actual value is: NonBooleanValue.");
    this.configuration.loadConfiguration(fileName);
  }

  @Test
  public void missingOCSPSEntryThrowsException() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_ocsps_no_entry.yaml";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage("No OCSPS entry found or OCSPS entry is empty. Configuration from: " + fileName);
    this.configuration.loadConfiguration(fileName);
    this.configuration.getDDoc4JConfiguration();
  }

  @Test
  public void emptyOCSPSEntryThrowsException() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_ocsps_empty.yaml";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage("No OCSPS entry found or OCSPS entry is empty. Configuration from: " + fileName);
    this.configuration.loadConfiguration(fileName);
    this.configuration.getDDoc4JConfiguration();
  }

  @Test
  public void OCSPWithoutCaCnValueThrowsException() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_ocsps_no_ca_cn.yaml";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage("Configuration from " + fileName + " contains error(s):\n" +
        "OCSPS list entry 2 does not have an entry for CA_CN or the entry is empty\n");
    this.configuration.loadConfiguration(fileName);
    this.configuration.getDDoc4JConfiguration();
  }

  @Test
  public void OCSPWithEmptySubEntriesThrowsException() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_ocsps_empty_sub_entries.yaml";
    String expectedErrorMessage = "Configuration from " + fileName + " contains error(s):\n" +
        "OCSPS list entry 3 does not have an entry for CA_CN or the entry is empty\n" +
        "OCSPS list entry 4 does not have an entry for CA_CERT or the entry is empty\n" +
        "OCSPS list entry 5 does not have an entry for CN or the entry is empty\n" +
        "OCSPS list entry 8 does not have an entry for URL or the entry is empty\n";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage(expectedErrorMessage);
    this.configuration.loadConfiguration(fileName);
    this.configuration.getDDoc4JConfiguration();
  }

  @Test
  public void OCSPWithMissingSubEntriesThrowsException() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_ocsps_missing_sub_entries.yaml";
    String expectedErrorMessage = "Configuration from " + fileName + " contains error(s):\n" +
        "OCSPS list entry 3 does not have an entry for CN or the entry is empty\n" +
        "OCSPS list entry 4 does not have an entry for URL or the entry is empty\n" +
        "OCSPS list entry 5 does not have an entry for CA_CERT or the entry is empty\n" +
        "OCSPS list entry 8 does not have an entry for CA_CN or the entry is empty\n";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage(expectedErrorMessage);
    this.configuration.loadConfiguration(fileName);
    this.configuration.getDDoc4JConfiguration();
  }

  @Test
  public void OCSPWithMissingOcspsCertsEntryThrowsException() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_ocsps_missing_certs_entry.yaml";
    String expectedErrorMessage = "Configuration from " + fileName + " contains error(s):\n" +
        "OCSPS list entry 3 does not have an entry for CERTS or the entry is empty\n";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage(expectedErrorMessage);
    this.configuration.loadConfiguration(fileName);
    this.configuration.getDDoc4JConfiguration();
  }

  @Test
  public void OCSPWithEmptyOcspsCertsEntryThrowsException() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_ocsps_empty_certs_entry.yaml";
    String expectedErrorMessage = "Configuration from " + fileName + " contains error(s):\n" +
        "OCSPS list entry 2 does not have an entry for CERTS or the entry is empty\n";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage(expectedErrorMessage);
    this.configuration.loadConfiguration(fileName);
    this.configuration.getDDoc4JConfiguration();
  }

  @Test
  public void configurationFileIsNotYamlFormatThrowsException() {
    String fileName = "src/test/resources/testFiles/helper-files/test.txt";
    String expectedErrorMessage = "Configuration from " + fileName + " is not correctly formatted";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage(expectedErrorMessage);
    this.configuration.loadConfiguration(fileName);
  }

  @Test
  public void configurationStreamIsNotYamlFormatThrowsException() throws Exception {
    String fileName = "src/test/resources/testFiles/helper-files/test.txt";
    String expectedErrorMessage = "Configuration from stream is not correctly formatted";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage(expectedErrorMessage);
    try (InputStream inputStream = new FileInputStream(fileName)) {
      this.configuration.loadConfiguration(inputStream);
    }
  }

  @Test
  public void isOCSPSigningConfigurationAvailableWhenItIsNotAvailable() {
    assertFalse(this.configuration.isOCSPSigningConfigurationAvailable());
  }

  @Test
  public void isOCSPSigningConfigurationAvailableWhenItIsAvailable() {
    this.configuration.setOCSPAccessCertificateFileName("test.p12");
    this.configuration.setOCSPAccessCertificatePassword("aaa".toCharArray());
    Assert.assertTrue(this.configuration.isOCSPSigningConfigurationAvailable());
  }

  @Test
  public void isOCSPSigningConfigurationAvailableWhenFileIsAvailable() {
    this.configuration.setOCSPAccessCertificateFileName("test.p12");
    Assert.assertFalse(this.configuration.isOCSPSigningConfigurationAvailable());
  }

  @Test
  public void isOCSPSigningConfigurationAvailableWhenPasswordIsAvailable() {
    this.configuration.setOCSPAccessCertificatePassword("aaa".toCharArray());
    Assert.assertFalse(this.configuration.isOCSPSigningConfigurationAvailable());
  }

  @Test
  public void getTspSourceFromConfigurationFile() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    Assert.assertEquals("http://tsp.source.test/HttpTspServer", this.configuration.getTspSource());
  }

  @Test
  public void getValidationPolicyFromConfigurationFile() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    Assert.assertEquals("conf/test_validation_policy.xml", this.configuration.getValidationPolicy());
  }

  @Test
  public void getOcspSourceFromConfigurationFile() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    Assert.assertEquals("http://www.openxades.org/cgi-bin/test_ocsp_source.cgi", this.configuration.getOcspSource());
  }

  @Test
  public void getLotlTruststorePathFromConfigurationFile() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    Assert.assertEquals("TEST_LOTL_TRUSTSTORE_PATH", this.configuration.getLotlTruststorePath());
    Assert.assertEquals("TEST_LOTL_TRUSTSTORE_PATH", this.configuration.getTslKeyStoreLocation());
  }

  @Test
  public void getTslKeystoreLocationFromConfigurationFile() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_tsl_location_and_keystore.yaml");
    Assert.assertEquals("file:conf/test_TSLKeyStore_location", this.configuration.getLotlTruststorePath());
    Assert.assertEquals("file:conf/test_TSLKeyStore_location", this.configuration.getTslKeyStoreLocation());
  }

  @Test(expected = LotlTrustStoreNotFoundException.class)
  public void exceptionIsThrownWhenLotlTruststoreIsNotFound() throws IOException {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    this.configuration.setLotlTruststorePath("not/existing/path");
    this.configuration.getTSL().refresh();
  }

  @Test
  public void testDefaultLotlTruststorePath() {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    Assert.assertEquals("classpath:truststores/lotl-truststore.p12", this.configuration.getLotlTruststorePath());
    Assert.assertEquals("classpath:truststores/lotl-truststore.p12", this.configuration.getTslKeyStoreLocation());
  }

  @Test
  public void testDefaultTestLotlTruststorePath() {
    Assert.assertEquals("classpath:truststores/test-lotl-truststore.p12", this.configuration.getLotlTruststorePath());
    Assert.assertEquals("classpath:truststores/test-lotl-truststore.p12", this.configuration.getTslKeyStoreLocation());
  }

  @Test
  public void getLotlTruststoreTypeFromConfigurationFile() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    Assert.assertEquals("TEST_LOTL_TRUSTSTORE_TYPE", this.configuration.getLotlTruststoreType());
  }

  @Test
  public void testDefaultLotlTruststoreType() {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    Assert.assertEquals("PKCS12", this.configuration.getLotlTruststoreType());
  }

  @Test
  public void testDefaultLotlTruststorePassword() {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    Assert.assertEquals("digidoc4j-password", this.configuration.getLotlTruststorePassword());
    Assert.assertEquals("digidoc4j-password", this.configuration.getTslKeyStorePassword());
  }

  @Test
  public void getLotlTruststorePasswordFromConfigurationFile() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    Assert.assertEquals("TEST_LOTL_TRUSTSTORE_PASSWORD", this.configuration.getLotlTruststorePassword());
    Assert.assertEquals("TEST_LOTL_TRUSTSTORE_PASSWORD", this.configuration.getTslKeyStorePassword());
  }

  @Test
  public void getTslKeystorePasswordFromConfigurationFile() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_tsl_location_and_keystore.yaml");
    Assert.assertEquals("test_TSLKeyStore_password", this.configuration.getLotlTruststorePassword());
    Assert.assertEquals("test_TSLKeyStore_password", this.configuration.getTslKeyStorePassword());
  }

  @Test
  public void testDefaultLotlPivotSupportEnabled() {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    Assert.assertTrue(this.configuration.isLotlPivotSupportEnabled());
  }

  @Test
  public void testDefaultTestLotlPivotSupportDisabled() {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    Assert.assertFalse(this.configuration.isLotlPivotSupportEnabled());
  }

  @Test
  public void getLotlPivotSupportFromConfigurationFile() throws Exception {
    this.configuration.setLotlPivotSupportEnabled(true);
    Assert.assertTrue(this.configuration.isLotlPivotSupportEnabled());
    loadConfigurationFromString(this.configuration, "LOTL_PIVOT_SUPPORT_ENABLED: false");
    Assert.assertFalse(this.configuration.isLotlPivotSupportEnabled());
    loadConfigurationFromString(this.configuration, "LOTL_PIVOT_SUPPORT_ENABLED: true");
    Assert.assertTrue(this.configuration.isLotlPivotSupportEnabled());
  }

  @Test
  public void setTslCacheExpirationTime() {
    this.configuration.setTslCacheExpirationTime(1337);
    Assert.assertEquals(1337, this.configuration.getTslCacheExpirationTime());
  }

  @Test
  public void defaultTslCacheExpirationTime_shouldBeOneDay() {
    long oneDayInMs = 1000 * 60 * 60 * 24;
    Assert.assertEquals(oneDayInMs, this.configuration.getTslCacheExpirationTime());
    Assert.assertEquals(oneDayInMs, Configuration.of(Configuration.Mode.PROD).getTslCacheExpirationTime());
  }

  @Test
  public void getTslCacheExpirationTimeFromConfigurationFile() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    Assert.assertEquals(1776, this.configuration.getTslCacheExpirationTime());
  }

  @Test
  public void defaultProxyConfiguration_shouldNotBeSet() {
    Assert.assertFalse(this.configuration.isNetworkProxyEnabled());
    Assert.assertNull(this.configuration.getHttpProxyHost());
    Assert.assertNull(this.configuration.getHttpProxyPort());
    Assert.assertNull(this.configuration.getHttpProxyUser());
    Assert.assertNull(this.configuration.getHttpProxyPassword());
    Assert.assertNull(this.configuration.getHttpsProxyHost());
    Assert.assertNull(this.configuration.getHttpsProxyPort());
    Assert.assertNull(this.configuration.getHttpsProxyUser());
    Assert.assertNull(this.configuration.getHttpsProxyPassword());
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      Assert.assertFalse(this.configuration.isNetworkProxyEnabledFor(connectionType));
      Assert.assertNull(this.configuration.getHttpProxyHostFor(connectionType));
      Assert.assertNull(this.configuration.getHttpProxyPortFor(connectionType));
      Assert.assertNull(this.configuration.getHttpProxyUserFor(connectionType));
      Assert.assertNull(this.configuration.getHttpProxyPasswordFor(connectionType));
      Assert.assertNull(this.configuration.getHttpsProxyHostFor(connectionType));
      Assert.assertNull(this.configuration.getHttpsProxyPortFor(connectionType));
      Assert.assertNull(this.configuration.getHttpsProxyUserFor(connectionType));
      Assert.assertNull(this.configuration.getHttpsProxyPasswordFor(connectionType));
    }
  }

  @Test
  public void getProxyConfigurationFromConfigurationFile_allParametersSet() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    Assert.assertTrue(this.configuration.isNetworkProxyEnabled());
    Assert.assertEquals("cache.noile.ee", this.configuration.getHttpProxyHost());
    Assert.assertEquals(8080, this.configuration.getHttpProxyPort().longValue());
    Assert.assertEquals("plainProxyMan", this.configuration.getHttpProxyUser());
    Assert.assertEquals("plainProxyPass", this.configuration.getHttpProxyPassword());
    Assert.assertEquals("secure.noile.ee", this.configuration.getHttpsProxyHost());
    Assert.assertEquals(8443, this.configuration.getHttpsProxyPort().longValue());
    Assert.assertEquals("secureProxyMan", this.configuration.getHttpsProxyUser());
    Assert.assertEquals("secureProxyPass", this.configuration.getHttpsProxyPassword());
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      Assert.assertTrue(this.configuration.isNetworkProxyEnabledFor(connectionType));
      Assert.assertEquals(connectionType + ".cache.noile.ee", this.configuration.getHttpProxyHostFor(connectionType));
      Assert.assertEquals(80800 + connectionType.ordinal(), this.configuration.getHttpProxyPortFor(connectionType).longValue());
      Assert.assertEquals(connectionType + "-plainProxyMan", this.configuration.getHttpProxyUserFor(connectionType));
      Assert.assertEquals(connectionType + "-plainProxyPass", this.configuration.getHttpProxyPasswordFor(connectionType));
      Assert.assertEquals(connectionType + ".secure.noile.ee", this.configuration.getHttpsProxyHostFor(connectionType));
      Assert.assertEquals(84430 + connectionType.ordinal(), this.configuration.getHttpsProxyPortFor(connectionType).longValue());
      Assert.assertEquals(connectionType + "-secureProxyMan", this.configuration.getHttpsProxyUserFor(connectionType));
      Assert.assertEquals(connectionType + "-secureProxyPass", this.configuration.getHttpsProxyPasswordFor(connectionType));
    }
  }

  @Test
  public void getInvalidProxyConfigurationFromConfigurationFile() {
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage("Configuration parameter HTTP_PROXY_PORT should have an integer value but the actual value is: notA_number.");
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_invalid_key_usage.yaml");
  }

  @Test
  public void getProxyConfigurationFromConfigurationFile_GenericParametersSet() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_generic_proxy_and_ssl_settings.yaml");
    Assert.assertTrue(this.configuration.isNetworkProxyEnabled());
    Assert.assertEquals("cache.noile.ee", this.configuration.getHttpProxyHost());
    Assert.assertEquals(8080, this.configuration.getHttpProxyPort().longValue());
    Assert.assertEquals("plainProxyMan", this.configuration.getHttpProxyUser());
    Assert.assertEquals("plainProxyPass", this.configuration.getHttpProxyPassword());
    Assert.assertEquals("secure.noile.ee", this.configuration.getHttpsProxyHost());
    Assert.assertEquals(8443, this.configuration.getHttpsProxyPort().longValue());
    Assert.assertEquals("secureProxyMan", this.configuration.getHttpsProxyUser());
    Assert.assertEquals("secureProxyPass", this.configuration.getHttpsProxyPassword());
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      Assert.assertTrue(this.configuration.isNetworkProxyEnabledFor(connectionType));
      Assert.assertEquals("cache.noile.ee", this.configuration.getHttpProxyHostFor(connectionType));
      Assert.assertEquals(8080, this.configuration.getHttpProxyPortFor(connectionType).longValue());
      Assert.assertEquals("plainProxyMan", this.configuration.getHttpProxyUserFor(connectionType));
      Assert.assertEquals("plainProxyPass", this.configuration.getHttpProxyPasswordFor(connectionType));
      Assert.assertEquals("secure.noile.ee", this.configuration.getHttpsProxyHostFor(connectionType));
      Assert.assertEquals(8443, this.configuration.getHttpsProxyPortFor(connectionType).longValue());
      Assert.assertEquals("secureProxyMan", this.configuration.getHttpsProxyUserFor(connectionType));
      Assert.assertEquals("secureProxyPass", this.configuration.getHttpsProxyPasswordFor(connectionType));
    }
  }

  @Test
  public void getProxyConfigurationFromConfigurationFile_specificParametersSet() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_specific_proxy_and_ssl_settings.yaml");
    Assert.assertFalse(this.configuration.isNetworkProxyEnabled());
    Assert.assertNull(this.configuration.getHttpProxyHost());
    Assert.assertNull(this.configuration.getHttpProxyPort());
    Assert.assertNull(this.configuration.getHttpProxyUser());
    Assert.assertNull(this.configuration.getHttpProxyPassword());
    Assert.assertNull(this.configuration.getHttpsProxyHost());
    Assert.assertNull(this.configuration.getHttpsProxyPort());
    Assert.assertNull(this.configuration.getHttpsProxyUser());
    Assert.assertNull(this.configuration.getHttpsProxyPassword());
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      Assert.assertTrue(this.configuration.isNetworkProxyEnabledFor(connectionType));
      Assert.assertEquals(connectionType + ".cache.noile.ee", this.configuration.getHttpProxyHostFor(connectionType));
      Assert.assertEquals(80800 + connectionType.ordinal(), this.configuration.getHttpProxyPortFor(connectionType).longValue());
      Assert.assertEquals(connectionType + "-plainProxyMan", this.configuration.getHttpProxyUserFor(connectionType));
      Assert.assertEquals(connectionType + "-plainProxyPass", this.configuration.getHttpProxyPasswordFor(connectionType));
      Assert.assertEquals(connectionType + ".secure.noile.ee", this.configuration.getHttpsProxyHostFor(connectionType));
      Assert.assertEquals(84430 + connectionType.ordinal(), this.configuration.getHttpsProxyPortFor(connectionType).longValue());
      Assert.assertEquals(connectionType + "-secureProxyMan", this.configuration.getHttpsProxyUserFor(connectionType));
      Assert.assertEquals(connectionType + "-secureProxyPass", this.configuration.getHttpsProxyPasswordFor(connectionType));
    }
  }

  @Test
  public void defaultSslConfiguration_shouldNotBeSet() {
    Assert.assertFalse(this.configuration.isSslConfigurationEnabled());
    Assert.assertNull(this.configuration.getSslKeystorePath());
    Assert.assertNull(this.configuration.getSslKeystoreType());
    Assert.assertNull(this.configuration.getSslKeystorePassword());
    Assert.assertNull(this.configuration.getSslTruststorePath());
    Assert.assertNull(this.configuration.getSslTruststoreType());
    Assert.assertNull(this.configuration.getSslTruststorePassword());
    Assert.assertNull(this.configuration.getSslProtocol());
    Assert.assertNull(this.configuration.getSupportedSslProtocols());
    Assert.assertNull(this.configuration.getSupportedSslCipherSuites());
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      Assert.assertFalse(this.configuration.isSslConfigurationEnabledFor(connectionType));
      Assert.assertNull(this.configuration.getSslKeystorePathFor(connectionType));
      Assert.assertNull(this.configuration.getSslKeystoreTypeFor(connectionType));
      Assert.assertNull(this.configuration.getSslKeystorePasswordFor(connectionType));
      Assert.assertNull(this.configuration.getSslTruststorePathFor(connectionType));
      Assert.assertNull(this.configuration.getSslTruststoreTypeFor(connectionType));
      Assert.assertNull(this.configuration.getSslTruststorePasswordFor(connectionType));
      Assert.assertNull(this.configuration.getSslProtocolFor(connectionType));
      Assert.assertNull(this.configuration.getSupportedSslProtocolsFor(connectionType));
      Assert.assertNull(this.configuration.getSupportedSslCipherSuitesFor(connectionType));
    }
  }

  @Test
  public void getSslConfigurationFromConfigurationFile_allParametersSet() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    Assert.assertTrue(configuration.isSslConfigurationEnabled());
    Assert.assertEquals("sslKeystorePath", this.configuration.getSslKeystorePath());
    Assert.assertEquals("sslKeystoreType", this.configuration.getSslKeystoreType());
    Assert.assertEquals("sslKeystorePassword", this.configuration.getSslKeystorePassword());
    Assert.assertEquals("sslTruststorePath", this.configuration.getSslTruststorePath());
    Assert.assertEquals("sslTruststoreType", this.configuration.getSslTruststoreType());
    Assert.assertEquals("sslTruststorePassword", this.configuration.getSslTruststorePassword());
    Assert.assertEquals("sslProtocol", this.configuration.getSslProtocol());
    Assert.assertEquals(Arrays.asList("sslProtocol1", "sslProtocol2", "sslProtocol3"), this.configuration.getSupportedSslProtocols());
    Assert.assertEquals(Arrays.asList("sslCipherSuite1", "sslCipherSuite2"), this.configuration.getSupportedSslCipherSuites());
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      Assert.assertTrue(configuration.isSslConfigurationEnabledFor(connectionType));
      Assert.assertEquals(connectionType + "-sslKeystorePath", this.configuration.getSslKeystorePathFor(connectionType));
      Assert.assertEquals(connectionType + "-sslKeystoreType", this.configuration.getSslKeystoreTypeFor(connectionType));
      Assert.assertEquals(connectionType + "-sslKeystorePassword", this.configuration.getSslKeystorePasswordFor(connectionType));
      Assert.assertEquals(connectionType + "-sslTruststorePath", this.configuration.getSslTruststorePathFor(connectionType));
      Assert.assertEquals(connectionType + "-sslTruststoreType", this.configuration.getSslTruststoreTypeFor(connectionType));
      Assert.assertEquals(connectionType + "-sslTruststorePassword", this.configuration.getSslTruststorePasswordFor(connectionType));
      Assert.assertEquals(connectionType + "-sslProtocol", this.configuration.getSslProtocolFor(connectionType));
      Assert.assertEquals(
              Stream.of("sslProtocol1", "sslProtocol2", "sslProtocol3").map(p -> connectionType + "-" + p).collect(Collectors.toList()),
              this.configuration.getSupportedSslProtocolsFor(connectionType));
      Assert.assertEquals(
              Stream.of("sslCipherSuite1", "sslCipherSuite2").map(cs -> connectionType + "-" + cs).collect(Collectors.toList()),
              this.configuration.getSupportedSslCipherSuitesFor(connectionType));
    }
  }

  @Test
  public void getSslConfigurationFromConfigurationFile_genericParametersSet() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_generic_proxy_and_ssl_settings.yaml");
    Assert.assertTrue(configuration.isSslConfigurationEnabled());
    Assert.assertEquals("sslKeystorePath", this.configuration.getSslKeystorePath());
    Assert.assertEquals("sslKeystoreType", this.configuration.getSslKeystoreType());
    Assert.assertEquals("sslKeystorePassword", this.configuration.getSslKeystorePassword());
    Assert.assertEquals("sslTruststorePath", this.configuration.getSslTruststorePath());
    Assert.assertEquals("sslTruststoreType", this.configuration.getSslTruststoreType());
    Assert.assertEquals("sslTruststorePassword", this.configuration.getSslTruststorePassword());
    Assert.assertEquals("sslProtocol", this.configuration.getSslProtocol());
    Assert.assertEquals(Arrays.asList("sslProtocol1", "sslProtocol2", "sslProtocol3"), this.configuration.getSupportedSslProtocols());
    Assert.assertEquals(Arrays.asList("sslCipherSuite1", "sslCipherSuite2"), this.configuration.getSupportedSslCipherSuites());
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      Assert.assertTrue(configuration.isSslConfigurationEnabledFor(connectionType));
      Assert.assertEquals("sslKeystorePath", this.configuration.getSslKeystorePathFor(connectionType));
      Assert.assertEquals("sslKeystoreType", this.configuration.getSslKeystoreTypeFor(connectionType));
      Assert.assertEquals("sslKeystorePassword", this.configuration.getSslKeystorePasswordFor(connectionType));
      Assert.assertEquals("sslTruststorePath", this.configuration.getSslTruststorePathFor(connectionType));
      Assert.assertEquals("sslTruststoreType", this.configuration.getSslTruststoreTypeFor(connectionType));
      Assert.assertEquals("sslTruststorePassword", this.configuration.getSslTruststorePasswordFor(connectionType));
      Assert.assertEquals("sslProtocol", this.configuration.getSslProtocolFor(connectionType));
      Assert.assertEquals(Arrays.asList("sslProtocol1", "sslProtocol2", "sslProtocol3"), this.configuration.getSupportedSslProtocolsFor(connectionType));
      Assert.assertEquals(Arrays.asList("sslCipherSuite1", "sslCipherSuite2"), this.configuration.getSupportedSslCipherSuitesFor(connectionType));
    }
  }

  @Test
  public void getSslConfigurationFromConfigurationFile_specificParametersSet() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_specific_proxy_and_ssl_settings.yaml");
    Assert.assertFalse(this.configuration.isSslConfigurationEnabled());
    Assert.assertNull(this.configuration.getSslKeystorePath());
    Assert.assertNull(this.configuration.getSslKeystoreType());
    Assert.assertNull(this.configuration.getSslKeystorePassword());
    Assert.assertNull(this.configuration.getSslTruststorePath());
    Assert.assertNull(this.configuration.getSslTruststoreType());
    Assert.assertNull(this.configuration.getSslTruststorePassword());
    Assert.assertNull(this.configuration.getSslProtocol());
    Assert.assertNull(this.configuration.getSupportedSslProtocols());
    Assert.assertNull(this.configuration.getSupportedSslCipherSuites());
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      Assert.assertTrue(configuration.isSslConfigurationEnabledFor(connectionType));
      Assert.assertEquals(connectionType + "-sslKeystorePath", this.configuration.getSslKeystorePathFor(connectionType));
      Assert.assertEquals(connectionType + "-sslKeystoreType", this.configuration.getSslKeystoreTypeFor(connectionType));
      Assert.assertEquals(connectionType + "-sslKeystorePassword", this.configuration.getSslKeystorePasswordFor(connectionType));
      Assert.assertEquals(connectionType + "-sslTruststorePath", this.configuration.getSslTruststorePathFor(connectionType));
      Assert.assertEquals(connectionType + "-sslTruststoreType", this.configuration.getSslTruststoreTypeFor(connectionType));
      Assert.assertEquals(connectionType + "-sslTruststorePassword", this.configuration.getSslTruststorePasswordFor(connectionType));
      Assert.assertEquals(connectionType + "-sslProtocol", this.configuration.getSslProtocolFor(connectionType));
      Assert.assertEquals(
              Stream.of("sslProtocol1", "sslProtocol2", "sslProtocol3").map(p -> connectionType + "-" + p).collect(Collectors.toList()),
              this.configuration.getSupportedSslProtocolsFor(connectionType));
      Assert.assertEquals(
              Stream.of("sslCipherSuite1", "sslCipherSuite2").map(cs -> connectionType + "-" + cs).collect(Collectors.toList()),
              this.configuration.getSupportedSslCipherSuitesFor(connectionType));
    }
  }

  @Test
  public void testDefaultZipCompressionConfiguration() {
    Assert.assertEquals(1024 * 1024, this.configuration.getZipCompressionRatioCheckThresholdInBytes());
    Assert.assertEquals(100, this.configuration.getMaxAllowedZipCompressionRatio());
  }

  @Test
  public void getInvalidZipCompressionRatioCheckThresholdInBytes() {
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage("Configuration parameter ZIP_COMPRESSION_RATIO_CHECK_THRESHOLD_IN_BYTES should have a long integer value but the actual value is: invalidValue.");
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_invalid_zip_threshold.yaml");
  }

  @Test
  public void getInvalidMaxAllowedZipCompressionRatio() {
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage("Configuration parameter MAX_ALLOWED_ZIP_COMPRESSION_RATIO should have an integer value but the actual value is: invalidValue.");
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_invalid_zip_ratio.yaml");
  }

  @Test
  public void setZipCompressionRatioCheckThresholdInBytes() {
    this.configuration.setZipCompressionRatioCheckThresholdInBytes(1234567);
    Assert.assertEquals(1234567, this.configuration.getZipCompressionRatioCheckThresholdInBytes());
  }

  @Test
  public void setMaxAllowedZipCompressionRatio() {
    this.configuration.setMaxAllowedZipCompressionRatio(2345);
    Assert.assertEquals(2345, this.configuration.getMaxAllowedZipCompressionRatio());
  }

  @Test
  public void loadMultipleCAsFromConfigurationFile() {
    Hashtable<String, String> ddoc4jConf = this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_two_cas.yaml");
    this.configuration.getDDoc4JConfiguration();
    Assert.assertEquals("AS Sertifitseerimiskeskus", ddoc4jConf.get("DIGIDOC_CA_1_NAME"));
    Assert.assertEquals("jar://certs/ESTEID-SK.crt", ddoc4jConf.get("DIGIDOC_CA_1_CERT2"));
    Assert.assertEquals("Second CA", ddoc4jConf.get("DIGIDOC_CA_2_NAME"));
    Assert.assertEquals("jar://certs/CA_2_CERT_3.crt", ddoc4jConf.get("DIGIDOC_CA_2_CERT3"));
    Assert.assertEquals("jar://certs/CA_2_OCSP_1_SECOND_CERT", ddoc4jConf.get("DIGIDOC_CA_2_OCSP1_CERT_1"));
  }

  @Test
  public void missingCA_shouldNotThrowException() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_no_ca.yaml");
  }

  @Test
  public void missingCA_shouldThrowException_whenUsingDDoc() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_no_ca.yaml";
    String expectedErrorMessage = "Configuration from " + fileName + " contains error(s):\n" +
        "Empty or no DIGIDOC_CAS entry";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage(expectedErrorMessage);
    this.configuration.loadConfiguration(fileName);
    this.configuration.getDDoc4JConfiguration();
  }

  @Test
  public void emptyCAThrowsException() {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_empty_ca.yaml";
    String expectedErrorMessage = "Configuration from " + fileName + " contains error(s):\n" +
        "Empty or no DIGIDOC_CA for entry 1";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage(expectedErrorMessage);
    this.configuration.loadConfiguration(fileName);
    this.configuration.getDDoc4JConfiguration();
  }

  @Test
  public void isTestMode() {
    Assert.assertTrue(this.configuration.isTest());
  }

  @Test
  public void isNotTestMode() {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    Assert.assertFalse(this.configuration.isTest());
  }

  @Test
  public void verifyAllOptionalConfigurationSettingsAreLoadedFromFile() {
    this.configuration.setLotlLocation("Set LOTL location");
    this.configuration.setTspSource("Set TSP source");
    this.configuration.setOCSPAccessCertificateFileName("Set OCSP access certificate file name");
    this.configuration.setOCSPAccessCertificatePassword("Set password".toCharArray());
    this.configuration.setOcspSource("Set OCSP source");
    this.configuration.setValidationPolicy("Set validation policy");
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    Assert.assertEquals("123876", this.getDDoc4JConfigurationValue("DIGIDOC_MAX_DATAFILE_CACHED"));
    Assert.assertEquals("TEST_DIGIDOC_NOTARY_IMPL", this.getDDoc4JConfigurationValue("DIGIDOC_NOTARY_IMPL"));
    Assert.assertEquals("TEST_DIGIDOC_OCSP_SIGN_CERT_SERIAL", this.getDDoc4JConfigurationValue("DIGIDOC_OCSP_SIGN_CERT_SERIAL"));
    Assert.assertEquals("TEST_DIGIDOC_SECURITY_PROVIDER", this.getDDoc4JConfigurationValue("DIGIDOC_SECURITY_PROVIDER"));
    Assert.assertEquals("TEST_DIGIDOC_SECURITY_PROVIDER_NAME", this.getDDoc4JConfigurationValue("DIGIDOC_SECURITY_PROVIDER_NAME"));
    Assert.assertEquals("TEST_DIGIDOC_TSLFAC_IMPL", this.getDDoc4JConfigurationValue("DIGIDOC_TSLFAC_IMPL"));
    Assert.assertEquals("false", this.getDDoc4JConfigurationValue("DIGIDOC_USE_LOCAL_TSL"));
    Assert.assertEquals("false", this.getDDoc4JConfigurationValue("KEY_USAGE_CHECK"));
    Assert.assertEquals("false", this.getDDoc4JConfigurationValue(SIGN_OCSP_REQUESTS));
    Assert.assertEquals("TEST_DIGIDOC_DF_CACHE_DIR", this.getDDoc4JConfigurationValue("DIGIDOC_DF_CACHE_DIR"));
    Assert.assertEquals("TEST_DIGIDOC_FACTORY_IMPL", this.getDDoc4JConfigurationValue("DIGIDOC_FACTORY_IMPL"));
    Assert.assertEquals("TEST_CANONICALIZATION_FACTORY_IMPL", this.getDDoc4JConfigurationValue("CANONICALIZATION_FACTORY_IMPL"));
    Assert.assertEquals("false", this.getDDoc4JConfigurationValue("DATAFILE_HASHCODE_MODE"));
    Assert.assertEquals("TEST_DIGIDOC_PKCS12_CONTAINER", this.configuration.getRegistry().get(ConfigurationParameter.OcspAccessCertificateFile).get(0));
    Assert.assertEquals("TEST_DIGIDOC_PKCS12_PASSWD", this.configuration.getRegistry().get(ConfigurationParameter.OcspAccessCertificatePassword).get(0));
    Assert.assertEquals("TEST_OCSP_SOURCE", this.configuration.getRegistry().get(ConfigurationParameter.OcspSource).get(0));
    Assert.assertEquals("TEST_TSP_SOURCE", this.configuration.getRegistry().get(ConfigurationParameter.TspSource).get(0));
    Assert.assertEquals("TEST_VALIDATION_POLICY", this.configuration.getRegistry().get(ConfigurationParameter.ValidationPolicy).get(0));
    Assert.assertEquals("TEST_LOTL_LOCATION", this.configuration.getRegistry().get(ConfigurationParameter.LotlLocation).get(0));
    Assert.assertEquals("true", this.configuration.getRegistry().get(ConfigurationParameter.preferAiaOcsp).get(0));
    Assert.assertEquals("73", this.configuration.getRegistry().get(ConfigurationParameter.ZipCompressionRatioCheckThreshold).get(0));
    Assert.assertEquals("37", this.configuration.getRegistry().get(ConfigurationParameter.MaxAllowedZipCompressionRatio).get(0));

    this.configuration.setLotlLocation("Set LOTL location");
    this.configuration.setTspSource("Set TSP source");
    this.configuration.setOCSPAccessCertificateFileName("Set OCSP access certificate file name");
    this.configuration.setOCSPAccessCertificatePassword("Set password".toCharArray());
    this.configuration.setOcspSource("Set OCSP source");
    this.configuration.setValidationPolicy("Set validation policy");
    Assert.assertEquals("Set LOTL location", this.configuration.getLotlLocation());
    Assert.assertEquals("Set TSP source", this.configuration.getTspSource());
    Assert.assertEquals("Set OCSP access certificate file name", this.configuration.getOCSPAccessCertificateFileName());
    Assert.assertEquals("Set password", this.configuration.getRegistry().get(ConfigurationParameter.OcspAccessCertificatePassword).get(0));
    Assert.assertEquals("Set OCSP source", this.configuration.getOcspSource());
    Assert.assertEquals("Set validation policy", this.configuration.getValidationPolicy());
  }

  @Test
  public void getDefaultTempFileMaxAge() {
    Assert.assertEquals(86400000, this.configuration.getTempFileMaxAge());
  }

  @Test
  public void loadTempFileMaxAgeFromFile() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_temp_file_max_age.yaml");
    Assert.assertEquals(60, this.configuration.getTempFileMaxAge());
  }

  @Test
  public void setTempFileMaxAgeFromCode(){
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_temp_file_max_age.yaml");
    this.configuration.setTempFileMaxAge(1000);
    Assert.assertEquals(1000, this.configuration.getTempFileMaxAge());
  }

  @Test
  public void getDefaultConnectionTimeout() {
    Assert.assertEquals(1000, this.configuration.getConnectionTimeout());
    Assert.assertEquals(1000, this.configuration.getSocketTimeout());
  }

  @Test
  public void loadConnectionTimeoutFromFile() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_connection_timeout.yaml");
    Assert.assertEquals(4000, this.configuration.getConnectionTimeout());
    Assert.assertEquals(2000, this.configuration.getSocketTimeout());
  }

  @Test
  public void setConnectionTimeoutFromCode() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_connection_timeout.yaml");
    this.configuration.setConnectionTimeout(2000);
    this.configuration.setSocketTimeout(5000);
    Assert.assertEquals(2000, this.configuration.getConnectionTimeout());
    Assert.assertEquals(5000, this.configuration.getSocketTimeout());
  }

  @Test
  public void revocationAndTimestampDelta_shouldBeOneDay() {
    int oneDayInMinutes = 24 * 60;
    Assert.assertEquals(oneDayInMinutes, this.configuration.getRevocationAndTimestampDeltaInMinutes());
  }

  @Test
  public void testSettingRevocationAndTimestampDelta() {
    int twoDaysInMinutes = 48 * 60;
    this.configuration.setRevocationAndTimestampDeltaInMinutes(twoDaysInMinutes);
    Assert.assertEquals(twoDaysInMinutes, this.configuration.getRevocationAndTimestampDeltaInMinutes());
  }

  @Test
  public void testLoadingRevocationAndTimestampDeltaFromConf() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    Assert.assertEquals(1337, this.configuration.getRevocationAndTimestampDeltaInMinutes());
  }

  @Test
  public void getDefaultAllowedOcspProviders() {
    Assert.assertEquals(Arrays.asList(Constant.Test.DEFAULT_OCSP_RESPONDERS), this.configuration.getAllowedOcspRespondersForTM());
  }

  @Test
  public void loadAllowedOcspProvidersFromConf() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    List<String> allowedOcspRespondersForTM = this.configuration.getAllowedOcspRespondersForTM();
    Assert.assertEquals(3,allowedOcspRespondersForTM.size());
    Assert.assertEquals("SK OCSP RESPONDER 2011", allowedOcspRespondersForTM.get(0));
    Assert.assertEquals("ESTEID-SK 2007 OCSP RESPONDER", allowedOcspRespondersForTM.get(1));
    Assert.assertEquals("EID-SK 2007 OCSP RESPONDER", allowedOcspRespondersForTM.get(2));
  }

  @Test
  public void setAllowedOcspProviders() {
    this.configuration.setAllowedOcspRespondersForTM("ESTEID-SK OCSP RESPONDER 2005", "ESTEID-SK OCSP RESPONDER");
    List<String> allowedOcspResponders = this.configuration.getAllowedOcspRespondersForTM();
    Assert.assertEquals(2, allowedOcspResponders.size());
    Assert.assertEquals("ESTEID-SK OCSP RESPONDER 2005", allowedOcspResponders.get(0));
    Assert.assertEquals("ESTEID-SK OCSP RESPONDER", allowedOcspResponders.get(1));
  }

  @Test
  public void getTrustedTerritories_defaultTesting_shouldBeNull() {
    Assert.assertEquals(Collections.emptyList(), configuration.getTrustedTerritories());
  }

  @Test
  public void getTrustedTerritories_defaultProd() {
    configuration = Configuration.of(Configuration.Mode.PROD);
    List<String> trustedTerritories = configuration.getTrustedTerritories();
    Assert.assertNotNull(trustedTerritories);
    Assert.assertTrue(trustedTerritories.contains("EE"));
    Assert.assertTrue(trustedTerritories.contains("BE"));
    Assert.assertTrue(trustedTerritories.contains("NO"));
    Assert.assertTrue(trustedTerritories.contains("DE"));
    Assert.assertTrue(trustedTerritories.contains("HR"));
  }

  @Test
  public void setTrustedTerritories() {
    configuration.setTrustedTerritories("AR", "US", "CA");
    List<String> trustedTerritories = configuration.getTrustedTerritories();
    Assert.assertEquals(Arrays.asList("AR", "US", "CA"), trustedTerritories);
  }

  @Test
  public void loadTrustedTerritoriesFromConf() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    List<String> trustedTerritories = configuration.getTrustedTerritories();
    Assert.assertEquals(Arrays.asList("NZ", "AU", "BR"), trustedTerritories);
  }

  @Test
  public void loadYamlTrustedTerritoriesFromConf() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc4j_test_conf_territories_lists.yaml");
    List<String> trustedTerritories = configuration.getTrustedTerritories();
    Assert.assertEquals(Arrays.asList("AU", "NZ", "AR"), trustedTerritories);
  }

  @Test
  public void loadEmptyTrustedTerritoriesFromConf() throws Exception {
    configuration.setTrustedTerritories("EE");
    loadConfigurationFromString(configuration, "TRUSTED_TERRITORIES: []");
    List<String> trustedTerritories = configuration.getTrustedTerritories();
    Assert.assertEquals(Collections.emptyList(), trustedTerritories);
  }

  @Test
  public void getRequiredTerritories_defaultTesting_shouldBeNull() {
    Assert.assertEquals(Collections.emptyList(), configuration.getRequiredTerritories());
  }

  @Test
  public void getRequiredTerritories_defaultProd() {
    configuration = Configuration.of(Configuration.Mode.PROD);
    List<String> requiredTerritories = configuration.getRequiredTerritories();
    Assert.assertEquals(Collections.singletonList("EE"), requiredTerritories);
  }

  @Test
  public void setRequiredTerritories() {
    configuration.setRequiredTerritories("CU", "LV");
    List<String> requiredTerritories = configuration.getRequiredTerritories();
    Assert.assertEquals(Arrays.asList("CU", "LV"), requiredTerritories);
  }

  @Test
  public void loadRequiredTerritoriesFromConf() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    List<String> requiredTerritories = configuration.getRequiredTerritories();
    Assert.assertEquals(Arrays.asList("GB", "LT"), requiredTerritories);
  }

  @Test
  public void loadYamlRequiredTerritoriesFromConf() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc4j_test_conf_territories_lists.yaml");
    List<String> requiredTerritories = configuration.getRequiredTerritories();
    Assert.assertEquals(Arrays.asList("IE", "LV"), requiredTerritories);
  }

  @Test
  public void loadEmptyRequiredTerritoriesFromConf() throws Exception {
    configuration.setRequiredTerritories("EE");
    loadConfigurationFromString(configuration, "REQUIRED_TERRITORIES: []");
    List<String> requiredTerritories = configuration.getRequiredTerritories();
    Assert.assertEquals(Collections.emptyList(), requiredTerritories);
  }

  @Test
  public void aiaOcspNotPreferredByDefault_defaultTest() {
    Assert.assertFalse(configuration.isAiaOcspPreferred());
  }

    @Test
    public void aiaOcspNotPreferredByDefault_defaultProd() {
        Assert.assertFalse(Configuration.of(Configuration.Mode.PROD).isAiaOcspPreferred());
    }

  @Test
  public void getAiaOcspSourceByCN_defaultTest() {
    Assert.assertNull(configuration.getAiaOcspSourceByCN(null));
    Assert.assertNull(configuration.getAiaOcspSourceByCN("ESTEID2018"));
    Assert.assertNull(configuration.getAiaOcspSourceByCN("ESTEID-SK 2011"));
    Assert.assertNull(configuration.getAiaOcspSourceByCN("EID-SK 2011"));
    Assert.assertNull(configuration.getAiaOcspSourceByCN("KLASS3-SK 2010"));
    Assert.assertNull(configuration.getAiaOcspSourceByCN("ESTEID-SK 2015"));
    Assert.assertNull(configuration.getAiaOcspSourceByCN("EID-SK 2016"));
    Assert.assertNull(configuration.getAiaOcspSourceByCN("NQ-SK 2016"));
    Assert.assertNull(configuration.getAiaOcspSourceByCN("KLASS3-SK 2016"));
    Assert.assertEquals("http://aia.demo.sk.ee/esteid2018", configuration.getAiaOcspSourceByCN("TEST of ESTEID2018"));
    Assert.assertEquals("http://aia.demo.sk.ee/esteid2011", configuration.getAiaOcspSourceByCN("TEST of ESTEID-SK 2011"));
    Assert.assertEquals("http://aia.demo.sk.ee/eid2011", configuration.getAiaOcspSourceByCN("TEST of EID-SK 2011"));
    Assert.assertEquals("http://aia.demo.sk.ee/klass3-2010", configuration.getAiaOcspSourceByCN("TEST of KLASS3-SK 2010"));
    Assert.assertEquals("http://aia.demo.sk.ee/esteid2015", configuration.getAiaOcspSourceByCN("TEST of ESTEID-SK 2015"));
    Assert.assertEquals("http://aia.demo.sk.ee/eid2016", configuration.getAiaOcspSourceByCN("TEST of EID-SK 2016"));
    Assert.assertEquals("http://aia.demo.sk.ee/nq2016", configuration.getAiaOcspSourceByCN("TEST of NQ-SK 2016"));
    Assert.assertEquals("http://aia.demo.sk.ee/klass3-2016", configuration.getAiaOcspSourceByCN("TEST of KLASS3-SK 2016"));
  }

  @Test
  public void getAiaOcspSourceByCN_defaultProd() {
    Configuration configuration = Configuration.of(Configuration.Mode.PROD);
    Assert.assertNull(configuration.getAiaOcspSourceByCN(null));
    Assert.assertEquals("http://aia.sk.ee/esteid2018", configuration.getAiaOcspSourceByCN("ESTEID2018"));
    Assert.assertEquals("http://aia.sk.ee/esteid2011", configuration.getAiaOcspSourceByCN("ESTEID-SK 2011"));
    Assert.assertEquals("http://aia.sk.ee/eid2011", configuration.getAiaOcspSourceByCN("EID-SK 2011"));
    Assert.assertEquals("http://aia.sk.ee/klass3-2010", configuration.getAiaOcspSourceByCN("KLASS3-SK 2010"));
    Assert.assertEquals("http://aia.sk.ee/esteid2015", configuration.getAiaOcspSourceByCN("ESTEID-SK 2015"));
    Assert.assertEquals("http://aia.sk.ee/eid2016", configuration.getAiaOcspSourceByCN("EID-SK 2016"));
    Assert.assertEquals("http://aia.sk.ee/nq2016", configuration.getAiaOcspSourceByCN("NQ-SK 2016"));
    Assert.assertEquals("http://aia.sk.ee/klass3-2016", configuration.getAiaOcspSourceByCN("KLASS3-SK 2016"));
    Assert.assertNull(configuration.getAiaOcspSourceByCN("TEST of ESTEID2018"));
    Assert.assertNull(configuration.getAiaOcspSourceByCN("TEST of ESTEID-SK 2011"));
    Assert.assertNull(configuration.getAiaOcspSourceByCN("TEST of EID-SK 2011"));
    Assert.assertNull(configuration.getAiaOcspSourceByCN("TEST of KLASS3-SK 2010"));
    Assert.assertNull(configuration.getAiaOcspSourceByCN("TEST of ESTEID-SK 2015"));
    Assert.assertNull(configuration.getAiaOcspSourceByCN("TEST of EID-SK 2016"));
    Assert.assertNull(configuration.getAiaOcspSourceByCN("TEST of NQ-SK 2016"));
    Assert.assertNull(configuration.getAiaOcspSourceByCN("TEST of KLASS3-SK 2016"));
  }

  @Test
  public void getUseNonceForAiaOcspByCN_defaultTest() {
    Assert.assertTrue(configuration.getUseNonceForAiaOcspByCN(null));
    Assert.assertTrue(configuration.getUseNonceForAiaOcspByCN("TEST of ESTEID2018"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of ESTEID-SK 2011"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of EID-SK 2011"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of KLASS3-SK 2010"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of ESTEID-SK 2015"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of EID-SK 2016"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of NQ-SK 2016"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of KLASS3-SK 2016"));
  }

  @Test
  public void getUseNonceForAiaOcspByCN_defaultProd() {
    Configuration configuration = Configuration.of(Configuration.Mode.PROD);
    Assert.assertTrue(configuration.getUseNonceForAiaOcspByCN(null));
    Assert.assertTrue(configuration.getUseNonceForAiaOcspByCN("ESTEID2018"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("ESTEID-SK 2011"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("EID-SK 2011"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("KLASS3-SK 2010"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("ESTEID-SK 2015"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("EID-SK 2016"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("NQ-SK 2016"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("KLASS3-SK 2016"));
  }

  @Test
  public void testAiaOcspNotConfiguredThroughYamlShouldUseDefaults_customTest() throws Exception {
    loadConfigurationFromString(configuration, "");
    Assert.assertEquals("http://aia.demo.sk.ee/esteid2018", configuration.getAiaOcspSourceByCN("TEST of ESTEID2018"));
    Assert.assertTrue(configuration.getUseNonceForAiaOcspByCN("TEST of ESTEID2018"));
    Assert.assertEquals("http://aia.demo.sk.ee/esteid2011", configuration.getAiaOcspSourceByCN("TEST of ESTEID-SK 2011"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of ESTEID-SK 2011"));
    Assert.assertEquals("http://aia.demo.sk.ee/eid2011", configuration.getAiaOcspSourceByCN("TEST of EID-SK 2011"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of EID-SK 2011"));
    Assert.assertEquals("http://aia.demo.sk.ee/klass3-2010", configuration.getAiaOcspSourceByCN("TEST of KLASS3-SK 2010"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of KLASS3-SK 2010"));
    Assert.assertEquals("http://aia.demo.sk.ee/esteid2015", configuration.getAiaOcspSourceByCN("TEST of ESTEID-SK 2015"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of ESTEID-SK 2015"));
    Assert.assertEquals("http://aia.demo.sk.ee/eid2016", configuration.getAiaOcspSourceByCN("TEST of EID-SK 2016"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of EID-SK 2016"));
    Assert.assertEquals("http://aia.demo.sk.ee/nq2016", configuration.getAiaOcspSourceByCN("TEST of NQ-SK 2016"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of NQ-SK 2016"));
    Assert.assertEquals("http://aia.demo.sk.ee/klass3-2016", configuration.getAiaOcspSourceByCN("TEST of KLASS3-SK 2016"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of KLASS3-SK 2016"));
  }

  @Test
  public void testConfigureAdditionalAiaOcspThroughYaml_customTest() throws Exception {
    loadConfigurationFromString(configuration, "AIA_OCSPS:",
            "  - ISSUER_CN: OCSP NAME",
            "    OCSP_SOURCE: scheme://host/path",
            "    USE_NONCE: true");
    Assert.assertEquals("http://aia.demo.sk.ee/esteid2018", configuration.getAiaOcspSourceByCN("TEST of ESTEID2018"));
    Assert.assertTrue(configuration.getUseNonceForAiaOcspByCN("TEST of ESTEID2018"));
    Assert.assertEquals("http://aia.demo.sk.ee/esteid2011", configuration.getAiaOcspSourceByCN("TEST of ESTEID-SK 2011"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of ESTEID-SK 2011"));
    Assert.assertEquals("http://aia.demo.sk.ee/eid2011", configuration.getAiaOcspSourceByCN("TEST of EID-SK 2011"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of EID-SK 2011"));
    Assert.assertEquals("http://aia.demo.sk.ee/klass3-2010", configuration.getAiaOcspSourceByCN("TEST of KLASS3-SK 2010"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of KLASS3-SK 2010"));
    Assert.assertEquals("http://aia.demo.sk.ee/esteid2015", configuration.getAiaOcspSourceByCN("TEST of ESTEID-SK 2015"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of ESTEID-SK 2015"));
    Assert.assertEquals("http://aia.demo.sk.ee/eid2016", configuration.getAiaOcspSourceByCN("TEST of EID-SK 2016"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of EID-SK 2016"));
    Assert.assertEquals("http://aia.demo.sk.ee/nq2016", configuration.getAiaOcspSourceByCN("TEST of NQ-SK 2016"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of NQ-SK 2016"));
    Assert.assertEquals("http://aia.demo.sk.ee/klass3-2016", configuration.getAiaOcspSourceByCN("TEST of KLASS3-SK 2016"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of KLASS3-SK 2016"));
    Assert.assertEquals("scheme://host/path", configuration.getAiaOcspSourceByCN("OCSP NAME"));
    Assert.assertTrue(configuration.getUseNonceForAiaOcspByCN("OCSP NAME"));
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
    Assert.assertEquals("new-url-for-test-of-esteid-2018", configuration.getAiaOcspSourceByCN("TEST of ESTEID2018"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of ESTEID2018"));
    Assert.assertEquals("new-url-for-test-of-esteid-sk-2011", configuration.getAiaOcspSourceByCN("TEST of ESTEID-SK 2011"));
    Assert.assertTrue(configuration.getUseNonceForAiaOcspByCN("TEST of ESTEID-SK 2011"));
    Assert.assertEquals("http://aia.demo.sk.ee/eid2011", configuration.getAiaOcspSourceByCN("TEST of EID-SK 2011"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of EID-SK 2011"));
    Assert.assertEquals("http://aia.demo.sk.ee/klass3-2010", configuration.getAiaOcspSourceByCN("TEST of KLASS3-SK 2010"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of KLASS3-SK 2010"));
    Assert.assertEquals("http://aia.demo.sk.ee/esteid2015", configuration.getAiaOcspSourceByCN("TEST of ESTEID-SK 2015"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of ESTEID-SK 2015"));
    Assert.assertEquals("http://aia.demo.sk.ee/eid2016", configuration.getAiaOcspSourceByCN("TEST of EID-SK 2016"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of EID-SK 2016"));
    Assert.assertEquals("http://aia.demo.sk.ee/nq2016", configuration.getAiaOcspSourceByCN("TEST of NQ-SK 2016"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of NQ-SK 2016"));
    Assert.assertEquals("http://aia.demo.sk.ee/klass3-2016", configuration.getAiaOcspSourceByCN("TEST of KLASS3-SK 2016"));
    Assert.assertFalse(configuration.getUseNonceForAiaOcspByCN("TEST of KLASS3-SK 2016"));
  }

  @Test
  public void testConfigureNewAiaOcspThroughYaml_missingIssuerCN() throws Exception {
    expectedException.expect(ConfigurationException.class);
    expectedException.expectMessage(Matchers.containsString("No value found for an entry <ISSUER_CN(1)>"));
    loadConfigurationFromString(configuration, "AIA_OCSPS:",
            "  - OCSP_SOURCE: scheme://host/path",
            "    USE_NONCE: true");
  }

  @Test
  public void testConfigureNewAiaOcspThroughYaml_missingOcspSource() throws Exception {
    expectedException.expect(ConfigurationException.class);
    expectedException.expectMessage(Matchers.containsString("No value found for an entry <OCSP_SOURCE(1)>"));
    loadConfigurationFromString(configuration, "AIA_OCSPS:",
            "  - ISSUER_CN: OCSP NAME",
            "    USE_NONCE: true");
  }

  @Test
  public void testConfigureNewAiaOcspThroughYaml_missingUseNonce() throws Exception {
    expectedException.expect(ConfigurationException.class);
    expectedException.expectMessage(Matchers.containsString("No value found for an entry <USE_NONCE(1)>"));
    loadConfigurationFromString(configuration, "AIA_OCSPS:",
            "  - ISSUER_CN: OCSP NAME",
            "    OCSP_SOURCE: scheme://host/path");
  }

  @Test
  public void testOpenBDocWithConfFromSetter() {
    this.configuration = new Configuration(Configuration.Mode.PROD);
    this.configuration.setOcspSource("http://demo.sk.ee/TEST");
    ContainerBuilder.aContainer().withConfiguration(this.configuration).
        fromExistingFile("src/test/resources/testFiles/valid-containers/test.asice").build();
    Assert.assertEquals("http://demo.sk.ee/TEST", this.configuration.getOcspSource());
  }

  @Test
  public void testOpenBDocWithConfFromYaml() {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_parameters.yaml");
    ContainerBuilder.aContainer().withConfiguration(this.configuration).
        fromExistingFile("src/test/resources/testFiles/valid-containers/test.asice").build();
    Assert.assertEquals("test_source_from_yaml", configuration.getOcspSource());
  }

  @Test
  public void testOpenBDocWithConfFromSetterWhenYamlParamPresented() {
    this.configuration = new Configuration(Configuration.Mode.PROD);
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_parameters.yaml");
    this.configuration.setOcspSource("http://demo.sk.ee/TEST");
    ContainerBuilder.aContainer().withConfiguration(this.configuration).
        fromExistingFile("src/test/resources/testFiles/valid-containers/test.asice").build();
    Assert.assertEquals("http://demo.sk.ee/TEST", this.configuration.getOcspSource());
  }

  @Test
  public void loadAllowedTimestampAndOCSPResponseDelta() {
    Assert.assertEquals(15, this.configuration.getAllowedTimestampAndOCSPResponseDeltaInMinutes().longValue());
  }

  @Test
  public void loadAllowedTimestampAndOCSPResponseDeltaFromConf() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    Assert.assertEquals(1, this.configuration.getAllowedTimestampAndOCSPResponseDeltaInMinutes().longValue());
  }

  @Test
  public void testLoadingSignatureProfile() {
    Assert.assertNull(this.configuration.getSignatureProfile());
  }

  @Test
  public void testLoadingSignatureProfileFromConf() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    Assert.assertEquals(SignatureProfile.LT_TM, this.configuration.getSignatureProfile());
  }

  @Test
  public void testLoadingSignatureDigestAlgorithm() {
    Assert.assertNull(this.configuration.getSignatureDigestAlgorithm());
  }

  @Test
  public void testLoadingSignatureDigestAlgorithmFromConf() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    Assert.assertEquals(DigestAlgorithm.SHA512, this.configuration.getSignatureDigestAlgorithm());
  }

  @Test
  public void testLoadingDataFileDigestAlgorithm() {
    Assert.assertNull(this.configuration.getDataFileDigestAlgorithm());
  }

  @Test
  public void testLoadingDataFileDigestAlgorithmFromConf() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    Assert.assertEquals(DigestAlgorithm.SHA512, this.configuration.getDataFileDigestAlgorithm());
  }

  @Test
  public void testConfigurationHasChanged() throws Exception {
    Configuration otherConfiguration = Configuration.of(Configuration.Mode.PROD);
    File file = this.createTemporaryFile();
    Helper.serialize(this.configuration, file);
    this.configuration = Helper.deserializer(file);
    Assert.assertTrue("No differences", this.isConfigurationsDifferent(otherConfiguration));
  }

  @Test
  public void testConfigurationHasNotChanged() throws Exception {
    Configuration otherConfiguration = new Configuration(Configuration.Mode.TEST);
    File file = this.createTemporaryFile();
    Helper.serialize(this.configuration, file);
    this.configuration = Helper.deserializer(file);
    Assert.assertFalse("Differences", this.isConfigurationsDifferent(otherConfiguration));
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.configuration = new Configuration(Configuration.Mode.TEST);
  }

  private boolean isConfigurationsDifferent(Configuration otherConfiguration) {
    if (StringUtils.isBlank(this.configuration.getRegistry().getSealValue())) {
      return false;
    }
    return !this.configuration.getRegistry().getSealValue().equals(otherConfiguration.getRegistry().generateSealValue());
  }

  private File generateConfigurationByParameter(String parameter) {
    return this.createTemporaryFileBy(String.format("%s\n" +
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
