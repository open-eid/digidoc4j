package org.digidoc4j.api;

import org.digidoc4j.api.exceptions.ConfigurationException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Hashtable;
import java.util.List;

import static org.digidoc4j.api.Configuration.*;
import static org.digidoc4j.api.Configuration.Mode.PROD;
import static org.digidoc4j.api.Configuration.Mode.TEST;
import static org.junit.Assert.*;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.spy;

public class ConfigurationTest {
  private Configuration configuration;

  @Rule
  public ExpectedException expectedException = ExpectedException.none();

  @Before
  public void setUp() {
    System.clearProperty("digidoc4j.mode");
    configuration = new Configuration(TEST);
  }

  @Test
  public void setTslLocation() throws Exception {
    configuration.setTslLocation("tslLocation");
    assertEquals("tslLocation", configuration.getTslLocation());
  }

  @Test
  public void defaultUseTslLocation() throws Exception {
    assertTrue(configuration.usesLocalTsl());
  }



  @Test
  public void defaultNotaryImplementation() throws Exception {
    assertEquals(DEFAULT_NOTARY_IMPLEMENTATION, configuration.getNotaryImplementation());
  }

  @Test
  public void defaultTslFactoryImplementation() throws Exception {
    assertEquals(DEFAULT_TSL_FACTORY_IMPLEMENTATION, configuration.getTslFactoryImplementation());
  }

  @Test
  public void setUseLocalTslLocation() throws Exception {
    configuration.setUseLocalTsl(false);
    assertFalse(configuration.usesLocalTsl());
  }

  @Test
  public void setTspSource() throws Exception {
    configuration.setTspSource("tspSource");
    assertEquals("tspSource", configuration.getTspSource());
  }

  @Test
  public void setValidationPolicy() throws Exception {
    configuration.setValidationPolicy("policy");
    assertEquals("policy", configuration.getValidationPolicy());
  }

  @Test
  public void defaultCanonicalizationFactoryImplementation() throws Exception {
    assertEquals(DEFAULT_CANONICALIZATION_FACTORY_IMPLEMENTATION, configuration.getCanonicalizationFactoryImplementation());
  }

  @Test
  public void setOcspSource() throws Exception {
    configuration.setOcspSource("ocsp_source");
    assertEquals("ocsp_source", configuration.getOcspSource());
  }

  @Test
  public void defaultOcspSource() throws Exception {
    assertEquals("http://www.openxades.org/cgi-bin/ocsp.cgi", configuration.getOcspSource());
  }

  @Test
  public void defaultFactoryImplementation() throws Exception {
    assertEquals(DEFAULT_FACTORY_IMPLEMENTATION, configuration.getFactoryImplementation());
  }

  @Test
  public void defaultProductionConfiguration() throws Exception {
    Configuration configuration = new Configuration(PROD);
    assertEquals("http://ftp.id.eesti.ee/pub/id/tsl/trusted-test-mp.xml", configuration.getTslLocation());
//    assertEquals("http://sr.riik.ee/tsl/estonian-tsl.xml", configuration.getTslLocation());
  }

  @Test
  public void defaultConstructorWithSetSystemProperty() throws Exception {
    System.setProperty("digidoc4j.mode", "TEST");
    Configuration configuration = new Configuration();
    assertEquals("file:conf/trusted-test-tsl.xml", configuration.getTslLocation());
  }

  @Test
  public void setMaxDataFileCached() throws Exception {
    configuration = new Configuration();
    long maxDataFileCached = 12345;
    configuration.setMaxDataFileCached(maxDataFileCached);
    assertEquals(maxDataFileCached, configuration.getMaxDataFileCached());
  }

  @Test
  public void setLog4JConfig() throws Exception {
    configuration = new Configuration();
    String fileName = "./NewFolder/NewFile.txt";
    configuration.setLog4JConfiguration(fileName);
    assertEquals(fileName, configuration.getLog4JConfiguration());
  }

  @Test
  public void defaultConstructorWithUnSetSystemProperty() throws Exception {
    Configuration configuration = new Configuration();
    assertEquals("http://ftp.id.eesti.ee/pub/id/tsl/trusted-test-mp.xml", configuration.getTslLocation());
//    assertEquals("http://sr.riik.ee/tsl/estonian-tsl.xml", configuration.getTslLocation());
  }

  @Test
  public void testGetPKCS11ModulePath() throws Exception {
    assertEquals("/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so", configuration.getPKCS11ModulePath());
  }

  @Test
  public void readConfigurationFromPropertiesFile() throws Exception {
    configuration.loadConfiguration("digidoc4j.yaml");
    List<X509Certificate> certificates = configuration.getCACerts();
    assertEquals(17, certificates.size());
  }

  @Test
  public void isKeyUsageCheckedDefaultValue() throws Exception {
    assertEquals(Boolean.parseBoolean(DEFAULT_KEY_USAGE_CHECK), configuration.isKeyUsageChecked());
  }

  @Test
  public void readConfigurationFromPropertiesFileThrowsException() throws Exception {
    Configuration configuration = spy(new Configuration(Mode.TEST));
    doThrow(new CertificateException()).when(configuration).getX509CertificateFromFile(anyString());
    doCallRealMethod().when(configuration).loadConfiguration(anyString());

    configuration.loadConfiguration("digidoc4j.yaml");

    assertEquals(0, configuration.getCACerts().size());
  }

  @Test
  public void generateJDigiDocConfig() throws Exception {
    Hashtable<String, String> jDigiDocConf = configuration.loadConfiguration("digidoc4j.yaml");

    assertEquals("jar://certs/ESTEID-SK.crt", jDigiDocConf.get("DIGIDOC_CA_1_CERT2"));
    assertEquals("jar://certs/KLASS3-SK OCSP 2006.crt", jDigiDocConf.get("DIGIDOC_CA_1_OCSP2_CERT_1"));
    assertEquals("jar://certs/EID-SK OCSP 2006.crt", jDigiDocConf.get("DIGIDOC_CA_1_OCSP13_CERT_1"));
    assertEquals("jar://certs/TEST Juur-SK.crt", jDigiDocConf.get("DIGIDOC_CA_1_CERT17"));
    assertEquals(DEFAULT_LOG4J_CONFIGURATION, jDigiDocConf.get("DIGIDOC_LOG4J_CONFIG"));
    assertEquals(DEFAULT_SECURITY_PROVIDER, jDigiDocConf.get("DIGIDOC_SECURITY_PROVIDER"));
    assertEquals(DEFAULT_SECURITY_PROVIDER_NAME, jDigiDocConf.get("DIGIDOC_SECURITY_PROVIDER_NAME"));
    assertEquals("false", jDigiDocConf.get("DATAFILE_HASHCODE_MODE"));
    assertEquals(DEFAULT_CANONICALIZATION_FACTORY_IMPLEMENTATION, jDigiDocConf.get("CANONICALIZATION_FACTORY_IMPL"));
    assertEquals("4096", jDigiDocConf.get("DIGIDOC_MAX_DATAFILE_CACHED"));
    assertEquals("false", jDigiDocConf.get("SIGN_OCSP_REQUESTS"));

    assertEquals("jar://certs/KLASS3-SK OCSP.crt", jDigiDocConf.get("DIGIDOC_CA_1_OCSP2_CERT"));
  }

  @Test
  public void getLog4jConfigurationLocation() throws Exception {
    configuration.loadConfiguration("digidoc4j.yaml");
    assertEquals("./log4j.properties", configuration.getLog4JConfiguration());
  }

  @Test
  public void getLog4jDefaultConfigurationLocation() throws Exception {
    assertEquals("./log4j.properties", configuration.getLog4JConfiguration());
  }

  @Test
  public void getLog4jDefaultConfigurationLocationWhenParameterInFileIsNotPresent() throws Exception {
    configuration.setLog4JConfiguration("new_file");
    configuration.loadConfiguration("digidoc4j.yaml");
    assertEquals("new_file", configuration.getLog4JConfiguration());
  }

  @Test
  public void getLog4jDefaultConfigurationLocationWhenParameterInFileIsPresent() throws Exception {
    configuration.setLog4JConfiguration("new_file");
    configuration.loadConfiguration("testFiles/digidoc_test_conf.yaml");
    assertEquals("new_log4j.properties", configuration.getLog4JConfiguration());
  }

  @Test
  public void loadsJDigiDocSecurityProviderFromFile() throws Exception {
    Hashtable<String, String> jDigiDocConf = configuration.loadConfiguration("testFiles/digidoc_test_conf.yaml");
    assertEquals("org.bouncycastle.jce.provider.BouncyCastleProvider1", jDigiDocConf.get("DIGIDOC_SECURITY_PROVIDER"));
  }

  @Test
  public void settingNonExistingConfigurationFileThrowsError() throws Exception {
    expectedException.expect(ConfigurationException.class);
    expectedException.expectMessage("testFiles/not_exists.yaml (No such file or directory)");
    configuration.loadConfiguration("testFiles/not_exists.yaml");
  }

  @Test
  public void digiDocSecurityProviderDefaultValue() throws Exception {
    Hashtable<String, String> jDigiDocConf = configuration.loadConfiguration("digidoc4j.yaml");
    assertEquals(DEFAULT_SECURITY_PROVIDER, jDigiDocConf.get("DIGIDOC_SECURITY_PROVIDER"));
  }

  @Test
  public void digiDocSecurityProviderDefaultName() throws Exception {
    Hashtable<String, String> jDigiDocConf = configuration.loadConfiguration("digidoc4j.yaml");
    assertEquals(DEFAULT_SECURITY_PROVIDER_NAME, jDigiDocConf.get("DIGIDOC_SECURITY_PROVIDER_NAME"));
  }

  @Test
  public void asksValueOfNonExistingParameter() throws Exception {
    Hashtable<String, String> jDigiDocConf = configuration.loadConfiguration("digidoc4j.yaml");
    assertNull(jDigiDocConf.get("DIGIDOC_PROXY_HOST"));
  }

  @Test
  public void isDataFileInHashCodeMode() throws Exception {
    assertFalse(configuration.isDataFileInHashCodeMode());
  }

  @Test
  public void setDataFileHashCodeMode() throws Exception {
    configuration.setDataFileHashCodeMode(true);
    assertTrue(configuration.isDataFileInHashCodeMode());
  }

  @Test
  public void DefaultOCSPSigningCertificateSerialNumber() throws Exception {
    assertEquals("", configuration.getOCSPSigningCertificateSerialNumber());
  }

  @Test
  public void SetOCSPSigningCertificateSerialNumber() throws Exception {
    configuration.setOCSPSigningCertificateSerialNumber("New Serial Number");
    assertEquals("New Serial Number", configuration.getOCSPSigningCertificateSerialNumber());
  }


  @Test
  public void digidocMaxDataFileCachedParameterIsNotANumber() throws Exception {
    String fileName = "testFiles/digidoc_test_conf_invalid_max_data_file_cached.yaml";
    expectedException.expect(ConfigurationException.class);
    expectedException.expectMessage("Configuration parameter DIGIDOC_MAX_DATAFILE_CACHED should have a numeric value " +
        "but the actual value is: 8192MB. Configuration file: " + fileName);
    configuration.loadConfiguration(fileName);
  }

  @Test
  public void digidocSignOcspRequestIsNotABoolean() throws Exception {
    String fileName = "testFiles/digidoc_test_conf_invalid_sign_ocsp_request.yaml";
    expectedException.expect(ConfigurationException.class);
    expectedException.expectMessage("Configuration parameter SIGN_OCSP_REQUESTS should be set to true or false" +
        " but the actual value is: NonBooleanValue. Configuration file: " + fileName);
    configuration.loadConfiguration(fileName);
  }

  @Test
  public void digidocKeyUsageCheckIsNotABoolean() throws Exception {
    String fileName = "testFiles/digidoc_test_conf_invalid_key_usage.yaml";
    expectedException.expect(ConfigurationException.class);
    expectedException.expectMessage("Configuration parameter KEY_USAGE_CHECK should be set to true or false" +
        " but the actual value is: NonBooleanValue. Configuration file: " + fileName);
    configuration.loadConfiguration(fileName);
  }

  @Test
  public void digidocUseLocalTslIsNotABoolean() throws Exception {
    String fileName = "testFiles/digidoc_test_conf_invalid_use_local_tsl.yaml";
    expectedException.expect(ConfigurationException.class);
    expectedException.expectMessage("Configuration parameter DIGIDOC_USE_LOCAL_TSL should be set to true or false" +
        " but the actual value is: NonBooleanValue. Configuration file: " + fileName);
    configuration.loadConfiguration(fileName);
  }

  @Test
  public void digidocDataFileHashcodeModeIsNotABoolean() throws Exception {
    String fileName = "testFiles/digidoc_test_conf_invalid_datafile_hashcode_mode.yaml";
    expectedException.expect(ConfigurationException.class);
    expectedException.expectMessage("Configuration parameter DATAFILE_HASHCODE_MODE should be set to true or false" +
        " but the actual value is: NonBooleanValue. Configuration file: " + fileName);
    configuration.loadConfiguration(fileName);
  }

  @Test
  public void missingOCSPSEntryThrowsException() throws Exception {
    String fileName = "testFiles/digidoc_test_conf_ocsps_no_entry.yaml";
    expectedException.expect(ConfigurationException.class);
    expectedException.expectMessage("No OCSPS entry found or OCSPS entry is empty. Configuration file: " + fileName);
    configuration.loadConfiguration(fileName);
  }

  @Test
  public void emptyOCSPSEntryThrowsException() throws Exception {
    String fileName = "testFiles/digidoc_test_conf_ocsps_empty.yaml";
    expectedException.expect(ConfigurationException.class);
    expectedException.expectMessage("No OCSPS entry found or OCSPS entry is empty. Configuration file: " + fileName);
    configuration.loadConfiguration(fileName);
  }

  @Test
  public void OCSPWithoutCaCnValueThrowsException() throws Exception {
    String fileName = "testFiles/digidoc_test_conf_ocsps_no_ca_cn.yaml";
    expectedException.expect(ConfigurationException.class);
    expectedException.expectMessage("Configuration file " + fileName + " contains error(s):\n" +
        "OCSPS list entry 2 does not have an entry for CA_CN or the entry is empty\n");
    configuration.loadConfiguration(fileName);
  }

  @Test
  public void OCSPWithEmptySubEntriesThrowsException() throws Exception {
    String fileName = "testFiles/digidoc_test_conf_ocsps_empty_sub_entries.yaml";
    String expectedErrorMessage = "Configuration file " + fileName + " contains error(s):\n" +
        "OCSPS list entry 3 does not have an entry for CA_CN or the entry is empty\n" +
        "OCSPS list entry 4 does not have an entry for CA_CERT or the entry is empty\n" +
        "OCSPS list entry 5 does not have an entry for CN or the entry is empty\n" +
        "OCSPS list entry 8 does not have an entry for URL or the entry is empty\n";
    expectedException.expect(ConfigurationException.class);
    expectedException.expectMessage(expectedErrorMessage);
    configuration.loadConfiguration(fileName);
  }

  @Test
  public void OCSPWithMissingSubEntriesThrowsException() throws Exception {
    String fileName = "testFiles/digidoc_test_conf_ocsps_missing_sub_entries.yaml";
    String expectedErrorMessage = "Configuration file " + fileName + " contains error(s):\n" +
        "OCSPS list entry 3 does not have an entry for CN or the entry is empty\n" +
        "OCSPS list entry 4 does not have an entry for URL or the entry is empty\n" +
        "OCSPS list entry 5 does not have an entry for CA_CERT or the entry is empty\n" +
        "OCSPS list entry 8 does not have an entry for CA_CN or the entry is empty\n";
    expectedException.expect(ConfigurationException.class);
    expectedException.expectMessage(expectedErrorMessage);
    configuration.loadConfiguration(fileName);
  }

  @Test
  public void OCSPWithMissingOcspsCertsEntryThrowsException() throws Exception {
    String fileName = "testFiles/digidoc_test_conf_ocsps_missing_certs_entry.yaml";
    String expectedErrorMessage = "Configuration file " + fileName + " contains error(s):\n" +
        "OCSPS list entry 3 does not have an entry for CERTS or the entry is empty\n";
    expectedException.expect(ConfigurationException.class);
    expectedException.expectMessage(expectedErrorMessage);
    configuration.loadConfiguration(fileName);
  }

  @Test
  public void OCSPWithEmptyOcspsCertsEntryThrowsException() throws Exception {
    String fileName = "testFiles/digidoc_test_conf_ocsps_empty_certs_entry.yaml";
    String expectedErrorMessage = "Configuration file " + fileName + " contains error(s):\n" +
        "OCSPS list entry 2 does not have an entry for CERTS or the entry is empty\n";
    expectedException.expect(ConfigurationException.class);
    expectedException.expectMessage(expectedErrorMessage);
    configuration.loadConfiguration(fileName);
  }

  @Test
  public void configurationFileIsNotYamlFormatThrowsException() throws Exception {
    String fileName = "testFiles/test.txt";
    String expectedErrorMessage = "Configuration file " + fileName + " is not a correctly formatted yaml file";
    expectedException.expect(ConfigurationException.class);
    expectedException.expectMessage(expectedErrorMessage);
    configuration.loadConfiguration(fileName);
  }

  @Test
  public void isOCSPSigningConfigurationAvailableWhenItIsNotAvailable() throws Exception {
    assertFalse(configuration.isOCSPSigningConfigurationAvailable());
  }

  @Test
  public void isOCSPSigningConfigurationAvailableWhenItIsAvailable() throws Exception {
    configuration.setOCSPAccessCertificateFileName("test.p12");
    configuration.setOCSPAccessCertificatePassword("aaa".toCharArray());
    assertTrue(configuration.isOCSPSigningConfigurationAvailable());
  }

  @Test
  public void isOCSPSigningConfigurationAvailableWhenFileIsAvailable() throws Exception {
    configuration.setOCSPAccessCertificateFileName("test.p12");
    assertFalse(configuration.isOCSPSigningConfigurationAvailable());
  }

  @Test
  public void isOCSPSigningConfigurationAvailableWhenPasswordIsAvailable() throws Exception {
    configuration.setOCSPAccessCertificatePassword("aaa".toCharArray());
    assertFalse(configuration.isOCSPSigningConfigurationAvailable());
  }


}
