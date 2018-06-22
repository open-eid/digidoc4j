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

import static org.digidoc4j.Constant.BDOC_CONTAINER_TYPE;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.junit.Assert.assertFalse;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.attribute.FileTime;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.exceptions.ConfigurationException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.TslCertificateSourceInitializationException;
import org.digidoc4j.exceptions.TslKeyStoreNotFoundException;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainer;
import org.digidoc4j.impl.asic.tsl.TSLCertificateSourceImpl;
import org.digidoc4j.impl.asic.tsl.TslLoader;
import org.digidoc4j.test.util.TestCommonUtil;
import org.digidoc4j.test.util.TestFileUtil;
import org.digidoc4j.test.util.TestTSLUtil;
import org.digidoc4j.utils.Helper;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.tsl.Condition;
import eu.europa.esig.dss.tsl.KeyUsageBit;
import eu.europa.esig.dss.tsl.ServiceInfo;
import eu.europa.esig.dss.tsl.ServiceInfoStatus;
import eu.europa.esig.dss.x509.CertificateToken;

public class ConfigurationTest extends AbstractTest {

  private final Logger log = LoggerFactory.getLogger(ConfigurationTest.class);
  private static final String SIGN_OCSP_REQUESTS = "SIGN_OCSP_REQUESTS";
  private static final String OCSP_PKCS12_CONTAINER = "DIGIDOC_PKCS12_CONTAINER";
  private static final String OCSP_PKCS_12_PASSWD = "DIGIDOC_PKCS12_PASSWD";

  @Test
  public void getTSLLocationWhenNotFileURL() {
    String tslLocation = "URL:test";
    this.configuration.setTslLocation(tslLocation);
    Assert.assertEquals(tslLocation, this.configuration.getTslLocation());
  }

  @Test
  public void TSLIsLoadedOnlyOnceForGlobalConfiguration() {
    TSLCertificateSource tsl = this.configuration.getTSL();
    Assert.assertEquals(tsl, this.configuration.getTSL());
  }

  @Test
  public void addTSL() throws IOException, CertificateException {
    TSLCertificateSource source = this.configuration.getTSL();
    int numberOfTSLCertificates = source.getCertificates().size();
    this.addCertificateToTSL(Paths.get("src/test/resources/testFiles/certs/Juur-SK.pem.crt"), source);
    Assert.assertEquals(numberOfTSLCertificates + 1, this.configuration.getTSL().getCertificates().size());
  }

  @Test
  public void addingCertificateToTsl() throws Exception {
    TSLCertificateSource source = new TSLCertificateSourceImpl();
    this.addCertificateToTSL(Paths.get("src/test/resources/testFiles/certs/Juur-SK.pem.crt"), source);
    CertificateToken certificateToken = source.getCertificates().get(0);
    Assert.assertThat(certificateToken.getKeyUsageBits(), hasItem(KeyUsageBit.nonRepudiation));
    Assert.assertTrue(certificateToken.checkKeyUsage(KeyUsageBit.nonRepudiation));
    ServiceInfo serviceInfo = certificateToken.getAssociatedTSPS().iterator().next();
    //TODO test ServiceInfoStatus new methods
    ServiceInfoStatus serviceInfostatus = serviceInfo.getStatus().getLatest();
    Assert.assertEquals("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision", serviceInfostatus.getStatus());
    Assert.assertEquals("http://uri.etsi.org/TrstSvc/Svctype/CA/QC", serviceInfostatus.getType());
    Assert.assertNotNull(serviceInfostatus.getStartDate());
    Map<String, List<Condition>> qualifiersAndConditions = serviceInfostatus.getQualifiersAndConditions();
    Assert.assertTrue(qualifiersAndConditions.containsKey("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD"));
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
  public void getTsl_whenCacheIsNotExpired_shouldUseCachedTsl() throws Exception {
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
  public void getTsl_whenCacheIsExpired_shouldDownloadNewTsl() throws Exception {
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
  public void lotlValidationFailsWithWrongCertsInKeystore() {
    this.configuration = new Configuration(Configuration.Mode.PROD);
    this.configuration.setTslKeyStoreLocation("keystore/test-keystore.jks");
    try {
      this.configuration.getTSL();
    } catch (TslCertificateSourceInitializationException e) {
      Assert.assertEquals("Not ETSI compliant signature. The signature is not valid.", e.getMessage());
    }
  }

  @Test
  public void addedTSLIsValid() throws IOException, CertificateException {
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
  @Ignore("Ignored as this functionality is not used in DDS but this test is broken due to DDS forks custom revocation handling.")
  public void policyFileIsReadFromNonDefaultFileLocation() {
    this.configuration.setValidationPolicy("src/test/resources/testFiles/constraints/moved_constraint.xml");
    ContainerOpener.open("src/test/resources/testFiles/invalid-containers/asics_for_testing.bdoc", this.configuration);
  }

  @Test
  public void TSLIsLoadedAfterSettingNewTSLLocation() {
    this.configuration.setTslLocation("https://open-eid.github.io/test-TL/tl-mp-test-EE.xml");
    BDocContainer container = (BDocContainer) ContainerBuilder.aContainer(BDOC_CONTAINER_TYPE)
        .withConfiguration(this.configuration).build();
    container.getConfiguration().getTSL();
    Assert.assertEquals(8, container.getConfiguration().getTSL().getCertificates().size());
    try {
      int tenSeconds = 10000;
      String tslHost = "10.0.25.57";
      if (InetAddress.getByName(tslHost).isReachable(tenSeconds)) {
        this.configuration.setTslLocation("http://" + tslHost + "/tsl/trusted-test-mp.xml");
        container = (BDocContainer) ContainerBuilder.aContainer(BDOC_CONTAINER_TYPE).
            withConfiguration(this.configuration).build();
        Assert.assertNotEquals(5, container.getConfiguration().getTSL().getCertificates().size());
      } else {
        this.log.error("Host <{}> is unreachable", tslHost);
      }
    } catch (Exception e) {
    }
  }

  @Test(expected = DigiDoc4JException.class)
  public void TSLFileNotFoundThrowsException() {
    this.configuration.setTslLocation("file:test-tsl/NotExisting.xml");
    BDocContainer container = (BDocContainer) ContainerBuilder.
        aContainer(BDOC_CONTAINER_TYPE).
        withConfiguration(this.configuration).
        build();
    container.getConfiguration().getTSL().refresh();
  }

  @Test(expected = DigiDoc4JException.class)
  public void TSLConnectionFailureThrowsException() {
    this.configuration.setTslLocation("http://127.0.0.1/tsl/incorrect.xml");
    BDocContainer container = (BDocContainer) ContainerBuilder.
        aContainer(BDOC_CONTAINER_TYPE).
        withConfiguration(this.configuration).
        build();
    container.getConfiguration().getTSL().refresh();
  }

  @Test
  public void testLoadConfiguration() throws Exception {
    BDocContainer container = (BDocContainer) ContainerBuilder.
        aContainer(BDOC_CONTAINER_TYPE).
        withConfiguration(this.configuration).
        build();
    Assert.assertFalse(container.getConfiguration().isBigFilesSupportEnabled());
    container.getConfiguration().loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    Assert.assertTrue(container.getConfiguration().isBigFilesSupportEnabled());
    Assert.assertEquals(8192, container.getConfiguration().getMaxDataFileCachedInMB());
  }

  @Test
  public void whenTSLLocationIsMalformedURLNoErrorIsRaisedAndThisSameValueIsReturned() throws Exception {
    String tslLocation = "file://C:\\";
    this.configuration.setTslLocation(tslLocation);
    Assert.assertEquals(tslLocation, configuration.getTslLocation());
  }

  @Test
  public void getTSLLocationFileDoesNotExistReturnsUrlPath() {
    String tslLocation = ("file:conf/does-not-exist.xml");
    this.configuration.setTslLocation(tslLocation);
    Assert.assertEquals(this.configuration.getTslLocation(), tslLocation);
  }

  @Test
  public void setTslLocation() throws Exception {
    this.configuration.setTslLocation("tslLocation");
    Assert.assertEquals("tslLocation", this.configuration.getTslLocation());
  }

  @Test
  public void getTslLocationFromConfigurationFile() throws Exception {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    Assert.assertEquals("file:conf/test_TSLLocation", this.configuration.getTslLocation());
  }

  @Test
  public void setTslLocationOverwritesConfigurationFile() throws Exception {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    this.configuration.setTslLocation("tslLocation");
    Assert.assertEquals("tslLocation", this.configuration.getTslLocation());
  }

  @Test
  public void setTspSource() throws Exception {
    this.configuration.setTspSource("tspSource");
    Assert.assertEquals("tspSource", this.configuration.getTspSource());
  }

  @Test
  public void setValidationPolicy() throws Exception {
    this.configuration.setValidationPolicy("policy");
    Assert.assertEquals("policy", this.configuration.getValidationPolicy());
  }

  @Test
  public void setOcspSource() throws Exception {
    this.configuration.setOcspSource("ocsp_source");
    Assert.assertEquals("ocsp_source", this.configuration.getOcspSource());
  }

  @Test
  public void defaultOCSPAccessCertificateFile() {
    Assert.assertEquals("", this.configuration.getOCSPAccessCertificateFileName());
    Assert.assertEquals("", this.getJDigiDocConfigurationValue(OCSP_PKCS12_CONTAINER));
  }

  @Test
  public void getOCSPAccessCertificateFileFromConfigurationFile() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    Assert.assertEquals("conf/OCSP_access_certificate_test_file_name", this.configuration.getOCSPAccessCertificateFileName());
    Assert.assertEquals("conf/OCSP_access_certificate_test_file_name", this.getJDigiDocConfigurationValue(OCSP_PKCS12_CONTAINER));
  }

  @Test
  public void getOCSPAccessCertificateFileFromStream() throws FileNotFoundException {
    this.configuration.loadConfiguration(new FileInputStream("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml"));
    Assert.assertEquals("conf/OCSP_access_certificate_test_file_name", this.configuration.getOCSPAccessCertificateFileName());
    Assert.assertEquals("conf/OCSP_access_certificate_test_file_name", this.getJDigiDocConfigurationValue(OCSP_PKCS12_CONTAINER));
  }

  @Test
  public void setOCSPAccessCertificateFileNameOverwritesConfigurationFile() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    this.configuration.setOCSPAccessCertificateFileName("New File");
    Assert.assertEquals("New File", configuration.getOCSPAccessCertificateFileName());
    Assert.assertEquals("New File", this.getJDigiDocConfigurationValue(OCSP_PKCS12_CONTAINER));
  }

  @Test
  public void defaultOCSPAccessCertificatePassword() {
    Assert.assertEquals(0, this.configuration.getOCSPAccessCertificatePassword().length);
    Assert.assertNull(this.getJDigiDocConfigurationValue(OCSP_PKCS_12_PASSWD));
  }

  @Test
  public void getOCSPAccessCertificatePasswordFromConfigurationFile() throws Exception {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    Assert.assertArrayEquals("OCSP_test_password".toCharArray(), this.configuration.getOCSPAccessCertificatePassword());
    Assert.assertEquals("OCSP_test_password", this.getJDigiDocConfigurationValue(OCSP_PKCS_12_PASSWD));
  }

  @Test
  public void setOCSPAccessCertificatePasswordOverwritesConfigurationFile() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    char[] newPassword = "New password".toCharArray();
    this.configuration.setOCSPAccessCertificatePassword(newPassword);
    Assert.assertArrayEquals(newPassword, this.configuration.getOCSPAccessCertificatePassword());
    Assert.assertEquals("New password", this.getJDigiDocConfigurationValue(OCSP_PKCS_12_PASSWD));
  }

  @Test
  public void signingOcspRequest_ShouldBeDisabled_InProdByDefault() throws Exception {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    Assert.assertFalse(this.configuration.hasToBeOCSPRequestSigned());
    Assert.assertEquals("false", this.getJDigiDocConfigurationValue(SIGN_OCSP_REQUESTS));
  }

  @Test
  public void signingOcspRequest_ShouldBeDisabled_InTestByDefault() throws Exception {
    Assert.assertFalse(this.configuration.hasToBeOCSPRequestSigned());
    Assert.assertEquals("false", this.getJDigiDocConfigurationValue(SIGN_OCSP_REQUESTS));
  }

  @Test
  public void disableSigningOcspRequestsInProd() throws Exception {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    this.configuration.setSignOCSPRequests(false);
    Assert.assertFalse(this.configuration.hasToBeOCSPRequestSigned());
    Assert.assertEquals("false", this.getJDigiDocConfigurationValue(SIGN_OCSP_REQUESTS));
  }

  @Test
  public void enableSigningOcspRequestsInTest() throws Exception {
    this.configuration.setSignOCSPRequests(true);
    Assert.assertTrue(this.configuration.hasToBeOCSPRequestSigned());
    Assert.assertEquals("true", this.getJDigiDocConfigurationValue(SIGN_OCSP_REQUESTS));
  }

  @Test
  public void loadDisableSigningOcspRequestFromConfFileInProd() throws Exception {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    Assert.assertFalse(this.configuration.hasToBeOCSPRequestSigned());
    Assert.assertEquals("false", this.getJDigiDocConfigurationValue(SIGN_OCSP_REQUESTS));
  }

  @Test
  public void loadDisableSigningOcspRequestFromConfFile() throws Exception {
    this.configuration.loadConfiguration(this.generateConfigurationByParameter("SIGN_OCSP_REQUESTS: false").getPath());
    Assert.assertFalse(this.configuration.hasToBeOCSPRequestSigned());
    Assert.assertEquals("false", this.getJDigiDocConfigurationValue(SIGN_OCSP_REQUESTS));
  }

  @Test
  public void loadEnableSigningOcspRequestFromConfFile() throws Exception {
    this.configuration.loadConfiguration(this.generateConfigurationByParameter("SIGN_OCSP_REQUESTS: true").getPath());
    Assert.assertTrue(configuration.hasToBeOCSPRequestSigned());
    Assert.assertEquals("true", this.getJDigiDocConfigurationValue(SIGN_OCSP_REQUESTS));
  }

  @Test
  public void defaultOcspSource() throws Exception {
    Assert.assertEquals("http://demo.sk.ee/ocsp", this.configuration.getOcspSource());
  }

  @Test
  public void defaultProductionConfiguration() throws Exception {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    Assert.assertEquals("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml",
        this.configuration.getTslLocation());
  }

  @Test
  public void defaultConstructorWithSetSystemProperty() throws Exception {
    this.configuration = new Configuration();
    Assert.assertEquals("https://open-eid.github.io/test-TL/tl-mp-test-EE.xml", this.configuration.getTslLocation());
  }

  @Test
  public void setMaxDataFileCached() throws Exception {
    long maxDataFileCached = 12345;
    this.configuration.enableBigFilesSupport(maxDataFileCached);
    Assert.assertEquals(maxDataFileCached, this.configuration.getMaxDataFileCachedInMB());
    Assert.assertEquals(maxDataFileCached * Constant.ONE_MB_IN_BYTES, this.configuration.getMaxDataFileCachedInBytes());
  }

  @Test
  public void setMaxDataFileCachedToNoCaching() {
    long maxDataFileCached = Constant.CACHE_NO_DATA_FILES;
    this.configuration.enableBigFilesSupport(maxDataFileCached);
    Assert.assertEquals(Constant.CACHE_NO_DATA_FILES, this.configuration.getMaxDataFileCachedInMB());
    Assert.assertEquals(Constant.CACHE_NO_DATA_FILES, this.configuration.getMaxDataFileCachedInBytes());
  }

  @Test
  public void setMaxDataFileCachedToAllCaching() {
    long maxDataFileCached = Constant.CACHE_ALL_DATA_FILES;
    this.configuration.enableBigFilesSupport(maxDataFileCached);
    Assert.assertEquals(Constant.CACHE_ALL_DATA_FILES, this.configuration.getMaxDataFileCachedInMB());
    Assert.assertEquals(Constant.CACHE_ALL_DATA_FILES, this.configuration.getMaxDataFileCachedInBytes());
  }

  @Test
  public void maxDataFileCachedNotAllowedValue() {
    long oldValue = 4096;
    this.configuration.enableBigFilesSupport(oldValue);
    this.configuration.enableBigFilesSupport(-2);
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
  public void defaultConstructorWithUnSetSystemProperty() throws Exception {
    this.clearGlobalMode();
    this.configuration = new Configuration();
    Assert.assertEquals("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml",
        this.configuration.getTslLocation());
  }

  @Test
  public void generateJDigiDocConfig() throws Exception {
    Hashtable<String, String> jDigiDocConf = this.configuration.loadConfiguration("src/main/resources/digidoc4j.yaml");
    this.configuration.getJDigiDocConfiguration();
    Assert.assertEquals("jar://certs/ESTEID-SK.crt", jDigiDocConf.get("DIGIDOC_CA_1_CERT2"));
    Assert.assertEquals("jar://certs/KLASS3-SK OCSP 2006.crt", jDigiDocConf.get("DIGIDOC_CA_1_OCSP2_CERT_1"));
    Assert.assertEquals("jar://certs/EID-SK OCSP 2006.crt", jDigiDocConf.get("DIGIDOC_CA_1_OCSP13_CERT_1"));
    Assert.assertEquals("jar://certs/TEST Juur-SK.crt", jDigiDocConf.get("DIGIDOC_CA_1_CERT19"));
    Assert.assertEquals(Constant.JDigiDoc.SECURITY_PROVIDER, jDigiDocConf.get("DIGIDOC_SECURITY_PROVIDER"));
    Assert.assertEquals(Constant.JDigiDoc.SECURITY_PROVIDER_NAME, jDigiDocConf.get("DIGIDOC_SECURITY_PROVIDER_NAME"));
    Assert.assertEquals("false", jDigiDocConf.get("DATAFILE_HASHCODE_MODE"));
    Assert.assertEquals(Constant.JDigiDoc.CANONICALIZATION_FACTORY_IMPLEMENTATION, jDigiDocConf.get("CANONICALIZATION_FACTORY_IMPL"));
    Assert.assertEquals("-1", jDigiDocConf.get("DIGIDOC_MAX_DATAFILE_CACHED"));
    Assert.assertEquals("false", jDigiDocConf.get(SIGN_OCSP_REQUESTS));
    Assert.assertEquals("jar://certs/KLASS3-SK OCSP.crt", jDigiDocConf.get("DIGIDOC_CA_1_OCSP2_CERT"));
  }

  @Test
  public void loadsJDigiDocSecurityProviderFromFile() throws Exception {
    Hashtable<String, String> jDigiDocConf = this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    Assert.assertEquals("org.bouncycastle.jce.provider.BouncyCastleProvider1", jDigiDocConf.get("DIGIDOC_SECURITY_PROVIDER"));
  }

  @Test
  public void loadsJDigiDocCacheDirectoryFromFile() throws Exception {
    Hashtable<String, String> jDigiDocConf = this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    Assert.assertEquals("/test_cache_dir", jDigiDocConf.get("DIGIDOC_DF_CACHE_DIR"));
  }

  @Test
  public void defaultJDigiDocCacheDirectory() throws Exception {
    Hashtable<String, String> jDigiDocConf =
        this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_without_cache_dir.yaml");
    Assert.assertNull(jDigiDocConf.get("DIGIDOC_DF_CACHE_DIR"));
  }

  @SuppressWarnings("NumericOverflow")
  @Test
  public void loadsMaxDataFileCachedFromFile() throws Exception {
    Hashtable<String, String> jDigiDocConf = this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    Assert.assertEquals("8192", jDigiDocConf.get("DIGIDOC_MAX_DATAFILE_CACHED"));
    Assert.assertEquals(8192, this.configuration.getMaxDataFileCachedInMB());
    Assert.assertEquals(8192 * Constant.ONE_MB_IN_BYTES, this.configuration.getMaxDataFileCachedInBytes());
  }

  @Test
  public void settingNonExistingConfigurationFileThrowsError() throws Exception {
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage("File src/test/resources/testFiles/not_exists.yaml not found in classpath.");
    this.configuration.loadConfiguration("src/test/resources/testFiles/not_exists.yaml");
  }

  @Test
  public void digiDocSecurityProviderDefaultValue() throws Exception {
    Hashtable<String, String> jDigiDocConf = this.configuration.loadConfiguration("src/main/resources/digidoc4j.yaml");
    Assert.assertEquals(Constant.JDigiDoc.SECURITY_PROVIDER, jDigiDocConf.get("DIGIDOC_SECURITY_PROVIDER"));
  }

  @Test
  public void digiDocSecurityProviderDefaultName() throws Exception {
    Hashtable<String, String> jDigiDocConf = this.configuration.loadConfiguration("src/main/resources/digidoc4j.yaml");
    Assert.assertEquals(Constant.JDigiDoc.SECURITY_PROVIDER_NAME, jDigiDocConf.get("DIGIDOC_SECURITY_PROVIDER_NAME"));
  }

  @Test
  public void asksValueOfNonExistingParameter() throws Exception {
    Hashtable<String, String> jDigiDocConf = this.configuration.loadConfiguration("src/main/resources/digidoc4j.yaml");
    Assert.assertNull(jDigiDocConf.get("DIGIDOC_PROXY_HOST"));
  }

  @Test
  public void digidocMaxDataFileCachedParameterIsNotANumber() throws Exception {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_invalid_max_data_file_cached.yaml";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage("Configuration parameter DIGIDOC_MAX_DATAFILE_CACHED" +
        " should have an integer value but the actual value is: 8192MB.");
    this.configuration.loadConfiguration(fileName);
  }

  @Test
  public void digidocSignOcspRequestIsNotABoolean() throws Exception {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_invalid_sign_ocsp_request.yaml";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage("Configuration parameter SIGN_OCSP_REQUESTS should be set to true or false" +
        " but the actual value is: NonBooleanValue.");
    this.configuration.loadConfiguration(fileName);
  }

  @Test
  public void digidocKeyUsageCheckIsNotABoolean() throws Exception {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_invalid_key_usage.yaml";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage("Configuration parameter KEY_USAGE_CHECK should be set to true or false" +
        " but the actual value is: NonBooleanValue.");
    this.configuration.loadConfiguration(fileName);
  }

  @Test
  public void digidocUseLocalTslIsNotABoolean() throws Exception {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_invalid_use_local_tsl.yaml";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage("Configuration parameter DIGIDOC_USE_LOCAL_TSL should be set to true or false" +
        " but the actual value is: NonBooleanValue.");
    this.configuration.loadConfiguration(fileName);
  }

  @Test
  public void digidocDataFileHashcodeModeIsNotABoolean() throws Exception {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_invalid_datafile_hashcode_mode.yaml";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage("Configuration parameter DATAFILE_HASHCODE_MODE should be set to true or false" +
        " but the actual value is: NonBooleanValue.");
    this.configuration.loadConfiguration(fileName);
  }

  @Test
  public void missingOCSPSEntryThrowsException() throws Exception {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_ocsps_no_entry.yaml";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage("No OCSPS entry found or OCSPS entry is empty. Configuration from: " + fileName);
    this.configuration.loadConfiguration(fileName);
    this.configuration.getJDigiDocConfiguration();
  }

  @Test
  public void emptyOCSPSEntryThrowsException() throws Exception {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_ocsps_empty.yaml";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage("No OCSPS entry found or OCSPS entry is empty. Configuration from: " + fileName);
    this.configuration.loadConfiguration(fileName);
    this.configuration.getJDigiDocConfiguration();
  }

  @Test
  public void OCSPWithoutCaCnValueThrowsException() throws Exception {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_ocsps_no_ca_cn.yaml";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage("Configuration from " + fileName + " contains error(s):\n" +
        "OCSPS list entry 2 does not have an entry for CA_CN or the entry is empty\n");
    this.configuration.loadConfiguration(fileName);
    this.configuration.getJDigiDocConfiguration();
  }

  @Test
  public void OCSPWithEmptySubEntriesThrowsException() throws Exception {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_ocsps_empty_sub_entries.yaml";
    String expectedErrorMessage = "Configuration from " + fileName + " contains error(s):\n" +
        "OCSPS list entry 3 does not have an entry for CA_CN or the entry is empty\n" +
        "OCSPS list entry 4 does not have an entry for CA_CERT or the entry is empty\n" +
        "OCSPS list entry 5 does not have an entry for CN or the entry is empty\n" +
        "OCSPS list entry 8 does not have an entry for URL or the entry is empty\n";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage(expectedErrorMessage);
    this.configuration.loadConfiguration(fileName);
    this.configuration.getJDigiDocConfiguration();
  }

  @Test
  public void OCSPWithMissingSubEntriesThrowsException() throws Exception {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_ocsps_missing_sub_entries.yaml";
    String expectedErrorMessage = "Configuration from " + fileName + " contains error(s):\n" +
        "OCSPS list entry 3 does not have an entry for CN or the entry is empty\n" +
        "OCSPS list entry 4 does not have an entry for URL or the entry is empty\n" +
        "OCSPS list entry 5 does not have an entry for CA_CERT or the entry is empty\n" +
        "OCSPS list entry 8 does not have an entry for CA_CN or the entry is empty\n";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage(expectedErrorMessage);
    this.configuration.loadConfiguration(fileName);
    this.configuration.getJDigiDocConfiguration();
  }

  @Test
  public void OCSPWithMissingOcspsCertsEntryThrowsException() throws Exception {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_ocsps_missing_certs_entry.yaml";
    String expectedErrorMessage = "Configuration from " + fileName + " contains error(s):\n" +
        "OCSPS list entry 3 does not have an entry for CERTS or the entry is empty\n";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage(expectedErrorMessage);
    this.configuration.loadConfiguration(fileName);
    this.configuration.getJDigiDocConfiguration();
  }

  @Test
  public void OCSPWithEmptyOcspsCertsEntryThrowsException() throws Exception {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_ocsps_empty_certs_entry.yaml";
    String expectedErrorMessage = "Configuration from " + fileName + " contains error(s):\n" +
        "OCSPS list entry 2 does not have an entry for CERTS or the entry is empty\n";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage(expectedErrorMessage);
    this.configuration.loadConfiguration(fileName);
    this.configuration.getJDigiDocConfiguration();
  }

  @Test
  public void configurationFileIsNotYamlFormatThrowsException() throws Exception {
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
    this.configuration.loadConfiguration(new FileInputStream(fileName));
  }

  @Test
  public void isOCSPSigningConfigurationAvailableWhenItIsNotAvailable() throws Exception {
    assertFalse(this.configuration.isOCSPSigningConfigurationAvailable());
  }

  @Test
  public void isOCSPSigningConfigurationAvailableWhenItIsAvailable() throws Exception {
    this.configuration.setOCSPAccessCertificateFileName("test.p12");
    this.configuration.setOCSPAccessCertificatePassword("aaa".toCharArray());
    Assert.assertTrue(this.configuration.isOCSPSigningConfigurationAvailable());
  }

  @Test
  public void isOCSPSigningConfigurationAvailableWhenFileIsAvailable() throws Exception {
    this.configuration.setOCSPAccessCertificateFileName("test.p12");
    Assert.assertFalse(this.configuration.isOCSPSigningConfigurationAvailable());
  }

  @Test
  public void isOCSPSigningConfigurationAvailableWhenPasswordIsAvailable() throws Exception {
    this.configuration.setOCSPAccessCertificatePassword("aaa".toCharArray());
    Assert.assertFalse(this.configuration.isOCSPSigningConfigurationAvailable());
  }

  @Test
  public void getTspSourceFromConfigurationFile() throws Exception {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    Assert.assertEquals("http://tsp.source.test/HttpTspServer", this.configuration.getTspSource());
  }

  @Test
  public void getValidationPolicyFromConfigurationFile() throws Exception {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    Assert.assertEquals("conf/test_validation_policy.xml", this.configuration.getValidationPolicy());
  }

  @Test
  public void getOcspSourceFromConfigurationFile() throws Exception {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    Assert.assertEquals("http://www.openxades.org/cgi-bin/test_ocsp_source.cgi", this.configuration.getOcspSource());
  }

  @Test
  public void getTslKeystoreLocationFromConfigurationFile() throws Exception {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    Assert.assertEquals("keystore", this.configuration.getTslKeyStoreLocation());
  }

  @Test(expected = TslKeyStoreNotFoundException.class)
  public void exceptionIsThrownWhenTslKeystoreIsNotFound() throws IOException {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    this.configuration.setTslKeyStoreLocation("not/existing/path");
    this.configuration.getTSL().refresh();
  }

  @Test
  public void testDefaultTslKeystoreLocation() throws Exception {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    Assert.assertEquals("keystore/keystore.jks", this.configuration.getTslKeyStoreLocation());
  }

  @Test
  public void testDefaultTestTslKeystoreLocation() throws Exception {
    Assert.assertEquals("keystore/test-keystore.jks", this.configuration.getTslKeyStoreLocation());
  }

  @Test
  public void testDefaultTslKeystorePassword() throws Exception {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    Assert.assertEquals("digidoc4j-password", this.configuration.getTslKeyStorePassword());
  }

  @Test
  public void getTslKeystorePasswordFromConfigurationFile() throws Exception {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    Assert.assertEquals("password", this.configuration.getTslKeyStorePassword());
  }

  @Test
  public void setTslCacheExpirationTime() throws Exception {
    this.configuration.setTslCacheExpirationTime(1337);
    Assert.assertEquals(1337, this.configuration.getTslCacheExpirationTime());
  }

  @Test
  public void defaultTslCacheExpirationTime_shouldBeOneDay() throws Exception {
    long oneDayInMs = 1000 * 60 * 60 * 24;
    Assert.assertEquals(oneDayInMs, this.configuration.getTslCacheExpirationTime());
    Assert.assertEquals(oneDayInMs, Configuration.of(Configuration.Mode.PROD).getTslCacheExpirationTime());
  }

  @Test
  public void getTslCacheExpirationTimeFromConfigurationFile() throws Exception {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    Assert.assertEquals(1776, this.configuration.getTslCacheExpirationTime());
  }

  @Test
  public void defaultProxyConfiguration_shouldNotBeSet() throws Exception {
    Assert.assertFalse(this.configuration.isNetworkProxyEnabled());
    Assert.assertNull(this.configuration.getHttpProxyHost());
    Assert.assertNull(this.configuration.getHttpProxyPort());
    Assert.assertNull(this.configuration.getHttpProxyUser());
    Assert.assertNull(this.configuration.getHttpProxyPassword());
  }

  @Test
  public void getProxyConfigurationFromConfigurationFile() throws Exception {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf.yaml");
    Assert.assertTrue(this.configuration.isNetworkProxyEnabled());
    Assert.assertEquals("cache.noile.ee", this.configuration.getHttpProxyHost());
    Assert.assertEquals(8080, this.configuration.getHttpProxyPort().longValue());
    Assert.assertEquals("proxyMan", this.configuration.getHttpProxyUser());
    Assert.assertEquals("proxyPass", this.configuration.getHttpProxyPassword());

  }

  @Test
  public void getInvalidProxyConfigurationFromConfigurationFile() throws Exception {
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage("Configuration parameter HTTP_PROXY_PORT should have an integer value but the actual value is: notA_number.");
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_invalid_key_usage.yaml");
  }

  @Test
  public void defaultSslConfiguration_shouldNotBeSet() throws Exception {
    Assert.assertFalse(this.configuration.isSslConfigurationEnabled());
    Assert.assertNull(this.configuration.getSslKeystorePath());
    Assert.assertNull(this.configuration.getSslKeystoreType());
    Assert.assertNull(this.configuration.getSslKeystorePassword());
    Assert.assertNull(this.configuration.getSslTruststorePath());
    Assert.assertNull(this.configuration.getSslTruststoreType());
    Assert.assertNull(this.configuration.getSslTruststorePassword());
  }

  @Test
  public void getSslConfigurationFromConfigurationFile() throws Exception {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    Assert.assertTrue(configuration.isSslConfigurationEnabled());
    Assert.assertEquals("sslKeystorePath", this.configuration.getSslKeystorePath());
    Assert.assertEquals("sslKeystoreType", this.configuration.getSslKeystoreType());
    Assert.assertEquals("sslKeystorePassword", this.configuration.getSslKeystorePassword());
    Assert.assertEquals("sslTruststorePath", this.configuration.getSslTruststorePath());
    Assert.assertEquals("sslTruststoreType", this.configuration.getSslTruststoreType());
    Assert.assertEquals("sslTruststorePassword", this.configuration.getSslTruststorePassword());
  }

  @Test
  public void loadMultipleCAsFromConfigurationFile() throws Exception {
    Hashtable<String, String> jDigiDocConf = this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_two_cas.yaml");
    this.configuration.getJDigiDocConfiguration();
    Assert.assertEquals("AS Sertifitseerimiskeskus", jDigiDocConf.get("DIGIDOC_CA_1_NAME"));
    Assert.assertEquals("jar://certs/ESTEID-SK.crt", jDigiDocConf.get("DIGIDOC_CA_1_CERT2"));
    Assert.assertEquals("Second CA", jDigiDocConf.get("DIGIDOC_CA_2_NAME"));
    Assert.assertEquals("jar://certs/CA_2_CERT_3.crt", jDigiDocConf.get("DIGIDOC_CA_2_CERT3"));
    Assert.assertEquals("jar://certs/CA_2_OCSP_1_SECOND_CERT", jDigiDocConf.get("DIGIDOC_CA_2_OCSP1_CERT_1"));
  }

  @Test
  public void missingCA_shouldNotThrowException() throws Exception {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_no_ca.yaml");
  }

  @Test
  public void missingCA_shouldThrowException_whenUsingDDoc() throws Exception {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_no_ca.yaml";
    String expectedErrorMessage = "Configuration from " + fileName + " contains error(s):\n" +
        "Empty or no DIGIDOC_CAS entry";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage(expectedErrorMessage);
    this.configuration.loadConfiguration(fileName);
    this.configuration.getJDigiDocConfiguration();
  }

  @Test
  public void emptyCAThrowsException() throws Exception {
    String fileName = "src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_empty_ca.yaml";
    String expectedErrorMessage = "Configuration from " + fileName + " contains error(s):\n" +
        "Empty or no DIGIDOC_CA for entry 1";
    this.expectedException.expect(ConfigurationException.class);
    this.expectedException.expectMessage(expectedErrorMessage);
    this.configuration.loadConfiguration(fileName);
    this.configuration.getJDigiDocConfiguration();
  }

  @Test
  public void isTestMode() throws Exception {
    Assert.assertTrue(this.configuration.isTest());
  }

  @Test
  public void isNotTestMode() throws Exception {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    Assert.assertFalse(this.configuration.isTest());
  }

  @Test
  public void verifyAllOptionalConfigurationSettingsAreLoadedFromFile() throws Exception {
    this.configuration.setTslLocation("Set TSL location");
    this.configuration.setTspSource("Set TSP source");
    this.configuration.setOCSPAccessCertificateFileName("Set OCSP access certificate file name");
    this.configuration.setOCSPAccessCertificatePassword("Set password".toCharArray());
    this.configuration.setOcspSource("Set OCSP source");
    this.configuration.setValidationPolicy("Set validation policy");
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    Assert.assertEquals("123876", this.getJDigiDocConfigurationValue("DIGIDOC_MAX_DATAFILE_CACHED"));
    Assert.assertEquals("TEST_DIGIDOC_NOTARY_IMPL", this.getJDigiDocConfigurationValue("DIGIDOC_NOTARY_IMPL"));
    Assert.assertEquals("TEST_DIGIDOC_OCSP_SIGN_CERT_SERIAL", this.getJDigiDocConfigurationValue("DIGIDOC_OCSP_SIGN_CERT_SERIAL"));
    Assert.assertEquals("TEST_DIGIDOC_SECURITY_PROVIDER", this.getJDigiDocConfigurationValue("DIGIDOC_SECURITY_PROVIDER"));
    Assert.assertEquals("TEST_DIGIDOC_SECURITY_PROVIDER_NAME", this.getJDigiDocConfigurationValue("DIGIDOC_SECURITY_PROVIDER_NAME"));
    Assert.assertEquals("TEST_DIGIDOC_TSLFAC_IMPL", this.getJDigiDocConfigurationValue("DIGIDOC_TSLFAC_IMPL"));
    Assert.assertEquals("false", this.getJDigiDocConfigurationValue("DIGIDOC_USE_LOCAL_TSL"));
    Assert.assertEquals("false", this.getJDigiDocConfigurationValue("KEY_USAGE_CHECK"));
    Assert.assertEquals("false", this.getJDigiDocConfigurationValue(SIGN_OCSP_REQUESTS));
    Assert.assertEquals("TEST_DIGIDOC_DF_CACHE_DIR", this.getJDigiDocConfigurationValue("DIGIDOC_DF_CACHE_DIR"));
    Assert.assertEquals("TEST_DIGIDOC_FACTORY_IMPL", this.getJDigiDocConfigurationValue("DIGIDOC_FACTORY_IMPL"));
    Assert.assertEquals("TEST_CANONICALIZATION_FACTORY_IMPL", this.getJDigiDocConfigurationValue("CANONICALIZATION_FACTORY_IMPL"));
    Assert.assertEquals("false", this.getJDigiDocConfigurationValue("DATAFILE_HASHCODE_MODE"));
    Assert.assertEquals("TEST_DIGIDOC_PKCS12_CONTAINER", this.configuration.getRegistry().get(ConfigurationParameter.OcspAccessCertificateFile));
    Assert.assertEquals("TEST_DIGIDOC_PKCS12_PASSWD", this.configuration.getRegistry().get(ConfigurationParameter.OcspAccessCertificatePassword));
    Assert.assertEquals("TEST_OCSP_SOURCE", this.configuration.getRegistry().get(ConfigurationParameter.OcspSource));
    Assert.assertEquals("TEST_TSP_SOURCE", this.configuration.getRegistry().get(ConfigurationParameter.TspSource));
    Assert.assertEquals("TEST_VALIDATION_POLICY", this.configuration.getRegistry().get(ConfigurationParameter.ValidationPolicy));
    Assert.assertEquals("TEST_TSL_LOCATION", this.configuration.getRegistry().get(ConfigurationParameter.TslLocation));
    this.configuration.setTslLocation("Set TSL location");
    this.configuration.setTspSource("Set TSP source");
    this.configuration.setOCSPAccessCertificateFileName("Set OCSP access certificate file name");
    this.configuration.setOCSPAccessCertificatePassword("Set password".toCharArray());
    this.configuration.setOcspSource("Set OCSP source");
    this.configuration.setValidationPolicy("Set validation policy");
    Assert.assertEquals("Set TSL location", this.configuration.getTslLocation());
    Assert.assertEquals("Set TSP source", this.configuration.getTspSource());
    Assert.assertEquals("Set OCSP access certificate file name", this.configuration.getOCSPAccessCertificateFileName());
    Assert.assertEquals("Set password", this.configuration.getRegistry().get(ConfigurationParameter.OcspAccessCertificatePassword));
    Assert.assertEquals("Set OCSP source", this.configuration.getOcspSource());
    Assert.assertEquals("Set validation policy", this.configuration.getValidationPolicy());
  }

  @Test
  public void getDefaultConnectionTimeout() throws Exception {
    Assert.assertEquals(1000, this.configuration.getConnectionTimeout());
    Assert.assertEquals(1000, this.configuration.getSocketTimeout());
  }

  @Test
  public void loadConnectionTimeoutFromFile() throws Exception {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_connection_timeout.yaml");
    Assert.assertEquals(4000, this.configuration.getConnectionTimeout());
    Assert.assertEquals(2000, this.configuration.getSocketTimeout());
  }

  @Test
  public void setConnectionTimeoutFromCode() throws Exception {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_connection_timeout.yaml");
    this.configuration.setConnectionTimeout(2000);
    this.configuration.setSocketTimeout(5000);
    Assert.assertEquals(2000, this.configuration.getConnectionTimeout());
    Assert.assertEquals(5000, this.configuration.getSocketTimeout());
  }

  @Test
  public void revocationAndTimestampDelta_shouldBeOneDay() throws Exception {
    int oneDayInMinutes = 24 * 60;
    Assert.assertEquals(oneDayInMinutes, this.configuration.getRevocationAndTimestampDeltaInMinutes());
  }

  @Test
  public void testSettingRevocationAndTimestampDelta() throws Exception {
    int twoDaysInMinutes = 48 * 60;
    this.configuration.setRevocationAndTimestampDeltaInMinutes(twoDaysInMinutes);
    Assert.assertEquals(twoDaysInMinutes, this.configuration.getRevocationAndTimestampDeltaInMinutes());
  }

  @Test
  public void testLoadingRevocationAndTimestampDeltaFromConf() throws Exception {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    Assert.assertEquals(1337, this.configuration.getRevocationAndTimestampDeltaInMinutes());
  }

  @Test
  public void getTruestedTerritories_defaultTesting_shouldBeNull() throws Exception {
    Assert.assertEquals(new ArrayList<>(), this.configuration.getTrustedTerritories());
  }

  @Test
  public void getTrustedTerritories_defaultProd() throws Exception {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    List<String> trustedTerritories = this.configuration.getTrustedTerritories();
    Assert.assertNotNull(trustedTerritories);
    Assert.assertTrue(trustedTerritories.contains("EE"));
    Assert.assertTrue(trustedTerritories.contains("BE"));
    Assert.assertTrue(trustedTerritories.contains("NO"));
    Assert.assertFalse(trustedTerritories.contains("DE"));
    Assert.assertFalse(trustedTerritories.contains("HR"));
  }

  @Test
  public void setTrustedTerritories() throws Exception {
    this.configuration.setTrustedTerritories("AR", "US", "CA");
    List<String> trustedTerritories = this.configuration.getTrustedTerritories();
    Assert.assertEquals(3, trustedTerritories.size());
    Assert.assertEquals("AR", trustedTerritories.get(0));
    Assert.assertEquals("US", trustedTerritories.get(1));
    Assert.assertEquals("CA", trustedTerritories.get(2));
  }

  @Test
  public void loadTrustedTerritoriesFromConf() throws Exception {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    List<String> trustedTerritories = this.configuration.getTrustedTerritories();
    Assert.assertEquals(3, trustedTerritories.size());
    Assert.assertEquals("NZ", trustedTerritories.get(0));
    Assert.assertEquals("AU", trustedTerritories.get(1));
    Assert.assertEquals("BR", trustedTerritories.get(2));
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
  public void loadAllowedTimestampAndOCSPResponseDelta() throws Exception {
    Assert.assertEquals(15, this.configuration.getAllowedTimestampAndOCSPResponseDeltaInMinutes().longValue());
  }

  @Test
  public void loadAllowedTimestampAndOCSPResponseDeltaFromConf() throws Exception {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    Assert.assertEquals(1, this.configuration.getAllowedTimestampAndOCSPResponseDeltaInMinutes().longValue());
  }

  @Test
  public void testLoadingSignatureProfile() throws Exception {
    Assert.assertEquals(SignatureProfile.LT, this.configuration.getSignatureProfile());
  }

  @Test
  public void testLoadingSignatureProfileFromConf() throws Exception {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    Assert.assertEquals(SignatureProfile.LT_TM, this.configuration.getSignatureProfile());
  }

  @Test
  public void testLoadingSignatureDigestAlgorithm() throws Exception {
    Assert.assertEquals(DigestAlgorithm.SHA256, this.configuration.getSignatureDigestAlgorithm());
  }

  @Test
  public void testLoadingSignatureDigestAlgorithmFromConf() throws Exception {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_all_optional_settings.yaml");
    Assert.assertEquals(DigestAlgorithm.SHA512, this.configuration.getSignatureDigestAlgorithm());
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

  private File generateConfigurationByParameter(String parameter) throws IOException {
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

}