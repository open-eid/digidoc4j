package org.digidoc4j.api;

import org.apache.commons.io.IOUtils;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Possibility to create custom configurations for {@link org.digidoc4j.api.Container} implementation.
 * <p/>
 * You can specify configuration mode. Is it {@link Configuration.Mode#TEST} or {@link Configuration.Mode#PROD}
 * configuration.
 * <p/>
 * Default is {@link Configuration.Mode#PROD}.
 * <p/>
 * Also it is possible to set mode by System property. Setting property "digidoc4j.mode" to "TEST" forces
 * default mode to {@link Configuration.Mode#TEST}  mode
 */
public class Configuration {

  final Logger logger = LoggerFactory.getLogger(Configuration.class);

  private final Mode mode;
  private static final int JAR_FILE_NAME_BEGIN_INDEX = 6;
  private LinkedHashMap configurationFromFile;
  private Hashtable<String, String> jDigiDocConfiguration = new Hashtable<String, String>();

  /**
   * Application mode
   */
  public enum Mode {
    TEST,
    PROD
  }

  /**
   * Operating system
   */
  protected enum OS {
    Linux,
    Win,
    OSX
  }

  Map<Mode, Map<String, String>> configuration = new HashMap<Mode, Map<String, String>>();

  /**
   * Create new configuration
   */
  public Configuration() {
    logger.debug("");
    if ("TEST".equalsIgnoreCase(System.getProperty("digidoc4j.mode")))
      mode = Mode.TEST;
    else
      mode = Mode.PROD;

    logger.info("Configuration loaded for " + mode + " mode");

    initDefaultValues();
  }

  /**
   * Create new configuration for application mode specified
   *
   * @param mode Application mode
   */
  public Configuration(Mode mode) {
    logger.debug("Mode: " + mode);
    this.mode = mode;
    initDefaultValues();
  }

  private void initDefaultValues() {
    logger.debug("");
    Map<String, String> testConfiguration = new HashMap<String, String>();
    Map<String, String> prodConfiguration = new HashMap<String, String>();

//  testConfiguration.put("tslLocation", "http://ftp.id.eesti.ee/pub/id/tsl/trusted-test-mp.xml");
    testConfiguration.put("tslLocation", "file:conf/trusted-test-tsl.xml");
    prodConfiguration.put("tslLocation", "http://sr.riik.ee/tsl/estonian-tsl.xml");

    testConfiguration.put("tspSource", "http://tsa01.quovadisglobal.com/TSS/HttpTspServer");
    prodConfiguration.put("tspSource", "http://tsa01.quovadisglobal.com/TSS/HttpTspServer");

    testConfiguration.put("validationPolicy", "conf/constraint.xml");
    prodConfiguration.put("validationPolicy", "conf/constraint.xml");

    testConfiguration.put("pkcs11ModuleLinux", "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so");
    prodConfiguration.put("pkcs11ModuleLinux", "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so");

    testConfiguration.put("ocspSource", "http://www.openxades.org/cgi-bin/ocsp.cgi");
    prodConfiguration.put("ocspSource", "http://ocsp.org.ee");

    jDigiDocConfiguration.put("DIGIDOC_LOG4J_CONFIG", "./log4j.properties");

    configuration.put(Mode.TEST, testConfiguration);
    configuration.put(Mode.PROD, prodConfiguration);

    logger.debug("Test configuration:\n" + configuration.get(Mode.TEST));
    logger.debug("Prod configuration:\n" + configuration.get(Mode.PROD));
  }

  /**
   * Add configuration settings from a file
   *
   * @param file File name
   * @return configuration hashtable
   */
  public Hashtable<String, String> loadConfiguration(String file) {
    configurationFromFile = new LinkedHashMap();
    logger.debug("File " + file);
    Yaml yaml = new Yaml();
    InputStream resourceAsStream = getResourceAsStream(file);
    if (resourceAsStream == null) {
      try {
        resourceAsStream = new FileInputStream(file);
      } catch (FileNotFoundException e) {
        throw new DigiDoc4JException(e);
      }
    }
    configurationFromFile = (LinkedHashMap) yaml.load(resourceAsStream);
    return mapToJDigiDocConfiguration();
  }

  /**
   * Get CA Certificates
   *
   * @return list of X509 Certificates
   */
  public List<X509Certificate> getCACerts() {
    logger.debug("");
    List<X509Certificate> certificates = new ArrayList<X509Certificate>();
    ArrayList<String> certificateAuthorityCerts =
        getCACertsAsArray((LinkedHashMap) configurationFromFile.get("DIGIDOC_CA"));
    for (String certFile : certificateAuthorityCerts) {
      try {
        certificates.add(getX509CertificateFromFile(certFile));
      } catch (CertificateException e) {
        logger.warn("Not able to read certificate from file " + certFile + ". " + e.getMessage());
      }
    }
    return certificates;
  }
  X509Certificate getX509CertificateFromFile(String certFile) throws CertificateException {
    logger.debug("File: " + certFile);
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

    InputStream certAsStream = getResourceAsStream(certFile.substring(JAR_FILE_NAME_BEGIN_INDEX));
    X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(certAsStream);
    IOUtils.closeQuietly(certAsStream);

    return cert;
  }

  private InputStream getResourceAsStream(String certFile) {
    return getClass().getClassLoader().getResourceAsStream(certFile);
  }

  /**
   * Gives back all configuration parameters needed for jDigiDoc
   *
   * @return Hashtable containing jDigiDoc configuration parameters
   */

  private Hashtable<String, String> mapToJDigiDocConfiguration() {
    logger.debug("loading JDigiDoc configuration");

    setJDigiDocConfigurationValue("DIGIDOC_LOG4J_CONFIG", getLog4JConfiguration());
    setJDigiDocConfigurationValue("DIGIDOC_SECURITY_PROVIDER", "org.bouncycastle.jce.provider.BouncyCastleProvider");
    setJDigiDocConfigurationValue("DIGIDOC_SECURITY_PROVIDER_NAME", "BC");

    jDigiDocConfiguration.put("DATAFILE_HASHCODE_MODE", defaultIfNull("DATAFILE_HASHCODE_MODE", "false"));
    jDigiDocConfiguration.put("CANONICALIZATION_FACTORY_IMPL", defaultIfNull("CANONICALIZATION_FACTORY_IMPL",
        "ee.sk.digidoc.c14n.TinyXMLCanonicalizer")); //*
    jDigiDocConfiguration.put("DIGIDOC_MAX_DATAFILE_CACHED", defaultIfNull("DIGIDOC_MAX_DATAFILE_CACHED", "4096"));
    jDigiDocConfiguration.put("DIGIDOC_USE_LOCAL_TSL", defaultIfNull("DIGIDOC_USE_LOCAL_TSL", "true"));
    jDigiDocConfiguration.put("DIGIDOC_NOTARY_IMPL", defaultIfNull("DIGIDOC_NOTARY_IMPL",
        "ee.sk.digidoc.factory.BouncyCastleNotaryFactory")); //*
    jDigiDocConfiguration.put("DIGIDOC_TSLFAC_IMPL", defaultIfNull("DIGIDOC_TSLFAC_IMPL",
        "ee.sk.digidoc.tsl.DigiDocTrustServiceFactory")); //*
    jDigiDocConfiguration.put("DIGIDOC_OCSP_RESPONDER_URL", getOcspSource());
    jDigiDocConfiguration.put("DIGIDOC_FACTORY_IMPL", defaultIfNull("DIGIDOC_FACTORY_IMPL",
        "ee.sk.digidoc.factory.SAXDigiDocFactory")); //*
    jDigiDocConfiguration.put("SIGN_OCSP_REQUESTS", defaultIfNull("SIGN_OCSP_REQUESTS", "false"));

    loadCertificateAuthorityCerts();
    loadOCSPCertificates();

    return jDigiDocConfiguration;
  }

  /**
   * Indicates if Data file should be in Hashcode mode
   *
   * @return boolean
   */
  public boolean isDataFileInHashCodeMode() {
    return Boolean.parseBoolean(jDigiDocConfiguration.get("DATAFILE_HASHCODE_MODE"));
  }

  private void setJDigiDocConfigurationValue(String key, String defaultValue) {
    jDigiDocConfiguration.put(key, defaultIfNull(key, defaultValue));
  }

  /**
   * Load Log4J configuration parameters from a file
   *
   * @param fileName File name
   */
  public void setLog4JConfiguration(String fileName) {
    jDigiDocConfiguration.put("DIGIDOC_LOG4J_CONFIG", fileName);
  }

  /**
   * Get Log4J parameters
   *
   * @return Log4j parameters
   */
  public String getLog4JConfiguration() {
    return jDigiDocConfiguration.get("DIGIDOC_LOG4J_CONFIG");
  }

  /**
   * Set the maximum size of data files to be cached
   *
   * @param maxDataFileCached Maximum size
   */
  public void setMaxDataFileCached(long maxDataFileCached) {
    jDigiDocConfiguration.put("DIGIDOC_MAX_DATAFILE_CACHED", Long.toString(maxDataFileCached));
  }

  /**
   * Get the maximum size of data files to be cached
   *
   * @return Size
   */
  public long getMaxDataFileCached() {
    try {
      return Long.parseLong(jDigiDocConfiguration.get("DIGIDOC_MAX_DATAFILE_CACHED"));
    } catch (NumberFormatException e) {
      throw new DigiDoc4JException(e.getMessage());
    }
  }

  private String defaultIfNull(String configParameter, String defaultValue) {
    logger.debug("Parameter: " + configParameter + ", default value: " + defaultValue);
    if (configurationFromFile == null) return defaultValue;
    Object value = configurationFromFile.get(configParameter);
    return value != null ? value.toString() : defaultValue;
  }

  private void loadOCSPCertificates() {
    logger.debug("");
    LinkedHashMap digiDocCA = (LinkedHashMap) configurationFromFile.get("DIGIDOC_CA");
    @SuppressWarnings("unchecked")
    ArrayList<LinkedHashMap> ocsps = (ArrayList<LinkedHashMap>) digiDocCA.get("OCSPS");
    int numberOfOCSPCertificates = ocsps.size();
    jDigiDocConfiguration.put("DIGIDOC_CA_1_OCSPS", String.valueOf(numberOfOCSPCertificates));

    for (int i = 1; i <= numberOfOCSPCertificates; i++) {
      LinkedHashMap ocsp = ocsps.get(i - 1);
      String prefix = "DIGIDOC_CA_1_OCSP" + i;
      jDigiDocConfiguration.put(prefix + "_CA_CN", ocsp.get("CA_CN").toString());
      jDigiDocConfiguration.put(prefix + "_CA_CERT", ocsp.get("CA_CERT").toString());
      jDigiDocConfiguration.put(prefix + "_CN", ocsp.get("CN").toString());
      getOCSPCertificates(prefix, ocsp);
      jDigiDocConfiguration.put(prefix + "_URL", ocsp.get("URL").toString());
    }
  }

  @SuppressWarnings("unchecked")
  private void getOCSPCertificates(String prefix, LinkedHashMap ocsp) {
    logger.debug("");
    ArrayList<String> certificates = (ArrayList<String>) ocsp.get("CERTS");
    for (int j = 0; j < certificates.size(); j++) {
      if (j == 0) {
        jDigiDocConfiguration.put(prefix + "_CERT", certificates.get(0));
      } else {
        jDigiDocConfiguration.put(prefix + "_CERT_" + j, certificates.get(j));
      }
    }
  }

  private void loadCertificateAuthorityCerts() {
    logger.debug("");
    LinkedHashMap digiDocCA = (LinkedHashMap) configurationFromFile.get("DIGIDOC_CA");
    ArrayList<String> certificateAuthorityCerts = getCACertsAsArray(digiDocCA);

    jDigiDocConfiguration.put("DIGIDOC_CAS", "1");
    jDigiDocConfiguration.put("DIGIDOC_CA_1_NAME", digiDocCA.get("NAME").toString());
    jDigiDocConfiguration.put("DIGIDOC_CA_1_TRADENAME", digiDocCA.get("TRADENAME").toString());
    int numberOfCACertificates = certificateAuthorityCerts.size();
    jDigiDocConfiguration.put("DIGIDOC_CA_1_CERTS", String.valueOf(numberOfCACertificates));

    for (int i = 0; i < numberOfCACertificates; i++) {
      String certFile = certificateAuthorityCerts.get(i);
      jDigiDocConfiguration.put("DIGIDOC_CA_1_CERT" + (i + 1), certFile);
    }
  }

  @SuppressWarnings("unchecked")
  private ArrayList<String> getCACertsAsArray(LinkedHashMap jDigiDocCa) {
    logger.debug("");
    return (ArrayList<String>) jDigiDocCa.get("CERTS");
  }

  /**
   * get the TSL location
   * @return TSL location
   */
  public String getTslLocation() {
    logger.debug("");
    String tslLocation = getConfigurationParameter("tslLocation");
    logger.debug("TSL Location: " + tslLocation);
    return tslLocation;
  }

  /**
   * Set the TSL location
   * @param tslLocation TSL Location to be used
   */
  public void setTslLocation(String tslLocation) {
    logger.debug("TSL location: " + tslLocation);
    setConfigurationParameter("tslLocation", tslLocation);
  }

  /**
   * Get the TSP Source
   * @return TSP Source
   */
  public String getTspSource() {
    logger.debug("");
    String tspSource = getConfigurationParameter("tspSource");
    logger.debug("TSP Source: " + tspSource);
    return tspSource;
  }

  /**
   * Set the TSP Source
   * @param tspSource  TSPSource to be used
   */
  public void setTspSource(String tspSource) {
    logger.debug("TSP source: " + tspSource);
    setConfigurationParameter("tspSource", tspSource);
  }

  /**
   * Get the OCSP Source
   * @return OCSP Source
   */
  public String getOcspSource() {
    logger.debug("");
    String ocspSource = getConfigurationParameter("ocspSource");
    logger.debug("OCSP source: " + ocspSource);
    return ocspSource;
  }

  /**
   * Set the OCSP source
   * @param ocspSource  OCSP Source to be used
   */
  public void setOcspSource(String ocspSource) {
    logger.debug("OCSP source: " + ocspSource);
    setConfigurationParameter("ocspSource", ocspSource);
  }

  /**
   * Get the validation policy
   * @return Validation policy
   */
  public String getValidationPolicy() {
    logger.debug("");
    String validationPolicy = getConfigurationParameter("validationPolicy");
    logger.debug("Validation policy: " + validationPolicy);
    return validationPolicy;
  }

  /**
   * Set the validation policy
   * @param validationPolicy Policy to be used
   */
  public void setValidationPolicy(String validationPolicy) {
    logger.debug("Validation policy: " + validationPolicy);
    setConfigurationParameter("validationPolicy", validationPolicy);
  }

  String getPKCS11ModulePathForOS(OS os, String key) {
    logger.debug("");
    return getConfigurationParameter(key + os);
  }

  /**
   * Get the PKCS11 Module path
   * @return path
   */
  public String getPKCS11ModulePath() {
    logger.debug("");
    String path = getPKCS11ModulePathForOS(OS.Linux, "pkcs11Module");
    logger.debug("PKCS11 module path: " + path);
    return path;
  }

  private void setConfigurationParameter(String key, String value) {
    logger.debug("Key: " + key + ", value: " + value);
    configuration.get(mode).put(key, value);
  }

  private String getConfigurationParameter(String key) {
    logger.debug("Key: " + key);
    String value = configuration.get(mode).get(key);
    logger.debug("Value: " + value);
    return value;
  }
}
