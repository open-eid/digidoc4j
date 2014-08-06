package org.digidoc4j.api;

import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.junit.Before;
import org.junit.Test;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Hashtable;
import java.util.List;

import static org.digidoc4j.api.Configuration.Mode.PROD;
import static org.digidoc4j.api.Configuration.Mode.TEST;
import static org.junit.Assert.*;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.*;

public class ConfigurationTest {
  private Configuration configuration;

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
  public void setOcspSource() throws Exception {
    configuration.setOcspSource("ocsp_source");
    assertEquals("ocsp_source", configuration.getOcspSource());
  }

  @Test
  public void defaultProductionConfiguration() throws Exception {
    Configuration configuration = new Configuration(PROD);
    assertEquals("http://sr.riik.ee/tsl/estonian-tsl.xml", configuration.getTslLocation());
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
  public void setSecurityProvider() throws Exception {


  }

  @Test
  public void defaultConstructorWithUnSetSystemProperty() throws Exception {
    Configuration configuration = new Configuration();
    assertEquals("http://sr.riik.ee/tsl/estonian-tsl.xml", configuration.getTslLocation());
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
  public void readConfigurationFromPropertiesFileThrowsException() throws Exception {
    Configuration configuration = spy(new Configuration(Configuration.Mode.TEST));
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
    assertEquals("./log4j.properties", jDigiDocConf.get("DIGIDOC_LOG4J_CONFIG"));
    assertEquals("org.bouncycastle.jce.provider.BouncyCastleProvider", jDigiDocConf.get("DIGIDOC_SECURITY_PROVIDER"));
    assertEquals("BC", jDigiDocConf.get("DIGIDOC_SECURITY_PROVIDER_NAME"));
    assertEquals("false", jDigiDocConf.get("DATAFILE_HASHCODE_MODE"));
    assertEquals("ee.sk.digidoc.c14n.TinyXMLCanonicalizer", jDigiDocConf.get("CANONICALIZATION_FACTORY_IMPL"));
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

  @Test(expected = DigiDoc4JException.class)
  public void settingNonExistingConfigurationFileThrowsError() throws Exception {
    configuration.loadConfiguration("testFiles/not_exists.yaml");
    assertEquals("new_log4j.properties", configuration.getLog4JConfiguration());
  }

  @Test
  public void digiDocSecurityProviderDefaultValue() throws Exception {
    Hashtable<String, String> jDigiDocConf = configuration.loadConfiguration("digidoc4j.yaml");
    assertEquals("org.bouncycastle.jce.provider.BouncyCastleProvider", jDigiDocConf.get("DIGIDOC_SECURITY_PROVIDER"));
  }

  @Test
  public void digiDocSecurityProviderDefaultName() throws Exception {
    Hashtable<String, String> jDigiDocConf = configuration.loadConfiguration("digidoc4j.yaml");
    assertEquals("BC", jDigiDocConf.get("DIGIDOC_SECURITY_PROVIDER_NAME"));
  }

  @Test
  public void asksValueOfNonExistingParameter() throws Exception {
    Hashtable<String, String> jDigiDocConf = configuration.loadConfiguration("digidoc4j.yaml");
    assertNull(jDigiDocConf.get("DIGIDOC_PROXY_HOST"));
  }

  @Test(expected = DigiDoc4JException.class)
  public void digidocMaxDataFileCachedParameterIsNotANumber() throws Exception {
    configuration.loadConfiguration("digidoc_test_conf_invalid.yaml");
    configuration.getMaxDataFileCached();
  }

  @Test
  public void isDataFileInHashCodeMode() throws Exception {
    assertFalse(configuration.isDataFileInHashCodeMode());
  }


}