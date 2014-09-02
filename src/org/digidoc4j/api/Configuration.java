package org.digidoc4j.api;

import org.digidoc4j.api.exceptions.ConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.*;

import static java.util.Arrays.asList;
import static org.apache.commons.lang.StringUtils.isNotEmpty;
import static org.apache.commons.lang.StringUtils.isNumeric;

/**
 * Possibility to create custom configurations for {@link org.digidoc4j.api.Container} implementation.
 * <p/>
 * You can specify the configuration mode, either {@link Configuration.Mode#TEST} or {@link Configuration.Mode#PROD}
 * configuration.
 * <p/>
 * Default is {@link Configuration.Mode#PROD}.
 * <p/>
 * It is also possible to set the mode using the System property. Setting the property "digidoc4j.mode" to "TEST" forces
 * the default mode to {@link Configuration.Mode#TEST}  mode
 * <p/>
 * The configuration file must be in yaml format.<br>
 * The configuration file must contain one or more Certificate Authorities under the heading DIGIDOC_CAS
 * similar to following format (values are examples only):<br>
 * DIGIDOC_CAS:
 * - DIGIDOC_CA:
 * NAME: CA name
 * TRADENAME: Tradename
 * CERTS:
 * - jar://certs/cert1.crt
 * - jar://certs/cert2.crt
 * <p/>
 * Each DIGIDOC_CA entry must contain one or more OCSP certificates under the heading "OCSPS"
 * similar to following format (values are examples only):<br>
 * <p>
 * <pre>
 * - OCSP:
 *   CA_CN: your certificate authority common name
 *   CA_CERT: jar://your ca_cn.crt
 *   CN: your common name
 *   CERTS:
 *   - jar://certs/Your first OCSP Certifications file.crt
 *   - jar://certs/Your second OCSP Certifications file.crt
 *   URL: http://ocsp.test.test
 * </pre>
 * <p>All entries must exist and be valid. Under CERTS must be at least one entry.</p>
 * <p/>
 * <p>The configuration file may contain the following additional settings:</p>
 * <p/>
 * DIGIDOC_LOG4J_CONFIG: File containing Log4J configuration parameters.
 * Default value: {@value #DEFAULT_LOG4J_CONFIGURATION}<br>
 * SIGN_OCSP_REQUESTS: Should OCSP requests be signed? Allowed values: true, false<br>
 * <p/>
 * DIGIDOC_SECURITY_PROVIDER: Security provider.
 * Default value: {@value #DEFAULT_SECURITY_PROVIDER}<br>
 * DIGIDOC_SECURITY_PROVIDER_NAME: Name of the security provider.
 * Default value: {@value #DEFAULT_SECURITY_PROVIDER_NAME}<br>
 * KEY_USAGE_CHECK: Should key usage be checked? Allowed values: true, false.
 * Default value: {@value #DEFAULT_KEY_USAGE_CHECK}<br>
 * DIGIDOC_OCSP_SIGN_CERT_SERIAL: OCSP Signing certificate serial number<br>
 * <p/>
 * DATAFILE_HASHCODE_MODE: Is the datafile containing only a hash (not the actual file)? Allowed values: true, false.
 * Default value: {@value #DEFAULT_DATAFILE_HASHCODE_MODE}<br>
 * CANONICALIZATION_FACTORY_IMPL: Canonicalization factory implementation.
 * Default value: {@value #DEFAULT_FACTORY_IMPLEMENTATION}<br>
 * DIGIDOC_MAX_DATAFILE_CACHED: Maximum datafile size that will be cached in MB. Must be numeric.
 * Default value: {@value #DEFAULT_MAX_DATAFILE_CACHED}<br>
 * DIGIDOC_USE_LOCAL_TSL: Use local TSL? Allowed values: true, false
 * Default value: {@value #DEFAULT_USE_LOCAL_TSL}
 * DIGIDOC_NOTARY_IMPL: Notary implementation.
 * Default value: {@value #DEFAULT_NOTARY_IMPLEMENTATION}<br>
 * DIGIDOC_TSLFAC_IMPL: TSL Factory implementation.
 * Default value: {@value #DEFAULT_TSL_FACTORY_IMPLEMENTATION}<br>
 * DIGIDOC_FACTORY_IMPL: Factory implementation.
 * Default value: {@value #DEFAULT_FACTORY_IMPLEMENTATION}<br>
 * <p/>
 * TSP_SOURCE: Time Stamp Protocol source address<br>
 * VALIDATION_POLICY: Validation policy source file<br>
 * PKCS11_MODULE: PKCS11 Module file<br>
 * OCSP_SOURCE: Online Certificate Service Protocol source<p/>
 */
public class Configuration {
  final Logger logger = LoggerFactory.getLogger(Configuration.class);

  public static final String DEFAULT_MAX_DATAFILE_CACHED = "4096";
  public static final String DEFAULT_CANONICALIZATION_FACTORY_IMPLEMENTATION
      = "ee.sk.digidoc.c14n.TinyXMLCanonicalizer";
  public static final String DEFAULT_SECURITY_PROVIDER = "org.bouncycastle.jce.provider.BouncyCastleProvider";
  public static final String DEFAULT_SECURITY_PROVIDER_NAME = "BC";
  public static final String DEFAULT_LOG4J_CONFIGURATION = "./log4j.properties";
  public static final String DEFAULT_NOTARY_IMPLEMENTATION = "ee.sk.digidoc.factory.BouncyCastleNotaryFactory";
  public static final String DEFAULT_TSL_FACTORY_IMPLEMENTATION = "ee.sk.digidoc.tsl.DigiDocTrustServiceFactory";
  public static final String DEFAULT_FACTORY_IMPLEMENTATION = "ee.sk.digidoc.factory.SAXDigiDocFactory";
  public static final String DEFAULT_KEY_USAGE_CHECK = "false";
  public static final String DEFAULT_DATAFILE_HASHCODE_MODE = "false";
  public static final String DEFAULT_USE_LOCAL_TSL = "true";

  private final Mode mode;
  //  private static final int JAR_FILE_NAME_BEGIN_INDEX = 6;
  private LinkedHashMap configurationFromFile;
  private String configurationFileName;
  private Hashtable<String, String> jDigiDocConfiguration = new Hashtable<String, String>();
  private ArrayList<String> fileParseErrors;

  /**
   * Application mode
   */
  public enum Mode {
    TEST,
    PROD
  }

  private void initDefaultValues() {
    logger.debug("");

    if (mode == Mode.TEST) {
      configuration.put("tslLocation", "http://10.0.25.57/tsl/trusted-test-mp.xml");
      configuration.put("tspSource", "http://tsa01.quovadisglobal.com/TSS/HttpTspServer");
      configuration.put("validationPolicy", "conf/constraint.xml");
      configuration.put("pkcs11Module", "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so");
      configuration.put("ocspSource", "http://www.openxades.org/cgi-bin/ocsp.cgi");
    } else {
      configuration.put("tslLocation", "http://10.0.25.57/tsl/trusted-test-mp.xml");
//      configuration.put("tslLocation", "http://sr.riik.ee/tsl/estonian-tsl.xml");
      configuration.put("tspSource", "http://tsa01.quovadisglobal.com/TSS/HttpTspServer");
      configuration.put("validationPolicy", "conf/constraint.xml");
      configuration.put("pkcs11Module", "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so");
      configuration.put("ocspSource", "http://ocsp.sk.ee/");
    }
    logger.debug(mode + "configuration:\n" + configuration);

    loadInitialConfigurationValues();
  }

  /**
   * Are requirements met for signing OCSP certificate?
   *
   * @return value indicating if requirements are met
   */
  public boolean isOCSPSigningConfigurationAvailable() {
    return isNotEmpty(getOCSPAccessCertificateFileName()) && getOCSPAccessCertificatePassword().length != 0;
  }

  /**
   * Get OCSP access certificate filename
   *
   * @return filename for the OCSP access certificate
   */
  public String getOCSPAccessCertificateFileName() {
    logger.debug("Loading OCSPAccessCertificateFile");
    String ocspAccessCertificateFile = getConfigurationParameter("OCSPAccessCertificateFile");
    logger.debug("OCSPAccessCertificateFile " + ocspAccessCertificateFile + " loaded");
    return ocspAccessCertificateFile;
  }

  /**
   * Get OSCP access certificate password
   *
   * @return password
   */
  public char[] getOCSPAccessCertificatePassword() {
    logger.debug("Loading OCSPAccessCertificatePassword");
    char[] result = {};
    String password = getConfigurationParameter("OCSPAccessCertificatePassword");
    if (isNotEmpty(password)) {
      result = password.toCharArray();
    }
    logger.debug("OCSPAccessCertificatePassword loaded");
    return result;
  }

  /**
   * Set OCSP access certificate filename
   *
   * @param fileName filename for the OCSP access certficate
   */
  public void setOCSPAccessCertificateFileName(String fileName) {
    logger.debug("Setting OCSPAccessCertificateFileName: " + fileName);
    setConfigurationParameter("OCSPAccessCertificateFile", fileName);
    logger.debug("OCSPAccessCertificateFile is set");
  }

  /**
   * Set OCSP access certificate password
   *
   * @param password password to set
   */
  public void setOCSPAccessCertificatePassword(char[] password) {
    logger.debug("Setting OCSPAccessCertificatePassword: ");
    setConfigurationParameter("OCSPAccessCertificatePassword", String.valueOf(password));
    logger.debug("OCSPAccessCertificatePassword is set");
  }

  Map<String, String> configuration = new HashMap<String, String>();

  /**
   * Create new configuration
   */
  public Configuration() {
    logger.debug("");
    if ("TEST".equalsIgnoreCase(System.getProperty("digidoc4j.mode")))
      mode = Mode.TEST;
    else
      mode = Mode.PROD;

    initDefaultValues();

    logger.info("Configuration loaded for " + mode + " mode");
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

  /**
   * Add configuration settings from a file
   *
   * @param file File name
   * @return configuration hashtable
   */
  public Hashtable<String, String> loadConfiguration(String file) {
    logger.debug("File " + file);
    configurationFromFile = new LinkedHashMap();
    Yaml yaml = new Yaml();
    configurationFileName = file;
    InputStream resourceAsStream = getResourceAsStream(file);
    if (resourceAsStream == null) {
      try {
        resourceAsStream = new FileInputStream(file);
      } catch (FileNotFoundException e) {
        throw new ConfigurationException(e);
      }
    }
    try {
      configurationFromFile = (LinkedHashMap) yaml.load(resourceAsStream);
    } catch (Exception e) {
      ConfigurationException exception = new ConfigurationException("Configuration file " + file + " "
          + "is not a correctly formatted yaml file");
      logger.error(exception.getMessage());
      throw exception;
    }
    return mapToJDigiDocConfiguration();
  }


//  Currently not used - if needed, then need to adjust for multiple CA's
//  /**
//   * Get CA Certificates
//   *
//   * @return list of X509 Certificates
//   */
//  public List<X509Certificate> getCACerts() {
//    logger.debug("");
//    List<X509Certificate> certificates = new ArrayList<X509Certificate>();
//    ArrayList<String> certificateAuthorityCerts =
//        getCACertsAsArray((LinkedHashMap) configurationFromFile.get("DIGIDOC_CA"));
//    for (String certFile : certificateAuthorityCerts) {
//      try {
//        certificates.add(getX509CertificateFromFile(certFile));
//      } catch (CertificateException e) {
//        logger.warn("Not able to read certificate from file " + certFile + ". " + e.getMessage());
//      }
//    }
//    return certificates;
//  }
//
//  X509Certificate getX509CertificateFromFile(String certFile) throws CertificateException {
//    logger.debug("File: " + certFile);
//    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
//
//    InputStream certAsStream = getResourceAsStream(certFile.substring(JAR_FILE_NAME_BEGIN_INDEX));
//    X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(certAsStream);
//    IOUtils.closeQuietly(certAsStream);
//
//    return cert;
//  }

  private InputStream getResourceAsStream(String certFile) {
    logger.debug("");
    return getClass().getClassLoader().getResourceAsStream(certFile);
  }

  /**
   * Gives back all configuration parameters needed for jDigiDoc
   *
   * @return Hashtable containing jDigiDoc configuration parameters
   */

  private Hashtable<String, String> mapToJDigiDocConfiguration() {
    logger.debug("loading JDigiDoc configuration");

    fileParseErrors = new ArrayList<String>();

    loadInitialConfigurationValues();
    loadCertificateAuthoritiesAndCertificates();
    reportFileParseErrors();

    return jDigiDocConfiguration;
  }

  private void loadCertificateAuthoritiesAndCertificates() {
    @SuppressWarnings("unchecked")
    ArrayList<LinkedHashMap> digiDocCAs = (ArrayList<LinkedHashMap>) configurationFromFile.get("DIGIDOC_CAS");
    if (digiDocCAs == null) {
      String errorMessage = "Empty or no DIGIDOC_CAS entry";
      logger.error(errorMessage);
      fileParseErrors.add(errorMessage);
      return;
    }

    int numberOfDigiDocCAs = digiDocCAs.size();
    jDigiDocConfiguration.put("DIGIDOC_CAS", String.valueOf(numberOfDigiDocCAs));
    for (int i = 0; i < numberOfDigiDocCAs; i++) {
      String caPrefix = "DIGIDOC_CA_" + (i + 1);
      LinkedHashMap digiDocCA = (LinkedHashMap) digiDocCAs.get(i).get("DIGIDOC_CA");
      if (digiDocCA == null) {
        String errorMessage = "Empty or no DIGIDOC_CA for entry " + (i + 1);
        logger.error(errorMessage);
        fileParseErrors.add(errorMessage);
      } else {
        loadCertificateAuthorityCerts(digiDocCA, caPrefix);
        loadOCSPCertificates(digiDocCA, caPrefix);
      }
    }
  }

  private void reportFileParseErrors() {
    logger.debug("");
    if (fileParseErrors.size() > 0) {
      StringBuilder errorMessage = new StringBuilder();
      errorMessage.append("Configuration file ");
      errorMessage.append(configurationFileName);
      errorMessage.append(" contains error(s):\n");
      for (String message : fileParseErrors) {
        errorMessage.append(message);
      }
      throw new ConfigurationException(errorMessage.toString());
    }
  }

  private void loadInitialConfigurationValues() {
    logger.debug("");
    setJDigiDocConfigurationValue("DIGIDOC_LOG4J_CONFIG", DEFAULT_LOG4J_CONFIGURATION);
    setJDigiDocConfigurationValue("SIGN_OCSP_REQUESTS", Boolean.toString(mode == Mode.PROD));
    setJDigiDocConfigurationValue("DIGIDOC_SECURITY_PROVIDER", DEFAULT_SECURITY_PROVIDER);
    setJDigiDocConfigurationValue("DIGIDOC_SECURITY_PROVIDER_NAME", DEFAULT_SECURITY_PROVIDER_NAME);
    setJDigiDocConfigurationValue("KEY_USAGE_CHECK", DEFAULT_KEY_USAGE_CHECK);
    setJDigiDocConfigurationValue("DIGIDOC_OCSP_SIGN_CERT_SERIAL", "");
    setJDigiDocConfigurationValue("DATAFILE_HASHCODE_MODE", DEFAULT_DATAFILE_HASHCODE_MODE);
    setJDigiDocConfigurationValue("CANONICALIZATION_FACTORY_IMPL", DEFAULT_CANONICALIZATION_FACTORY_IMPLEMENTATION);
    setJDigiDocConfigurationValue("DIGIDOC_MAX_DATAFILE_CACHED", DEFAULT_MAX_DATAFILE_CACHED);
    setJDigiDocConfigurationValue("DIGIDOC_USE_LOCAL_TSL", DEFAULT_USE_LOCAL_TSL);
    setJDigiDocConfigurationValue("DIGIDOC_NOTARY_IMPL", DEFAULT_NOTARY_IMPLEMENTATION);
    setJDigiDocConfigurationValue("DIGIDOC_TSLFAC_IMPL", DEFAULT_TSL_FACTORY_IMPLEMENTATION);
    setJDigiDocConfigurationValue("DIGIDOC_OCSP_RESPONDER_URL", getOcspSource());
    setJDigiDocConfigurationValue("DIGIDOC_FACTORY_IMPL", DEFAULT_FACTORY_IMPLEMENTATION);

    setConfigurationValue("TSL_LOCATION", "tslLocation");
    setConfigurationValue("TSP_SOURCE", "tspSource");
    setConfigurationValue("VALIDATION_POLICY", "validationPolicy");
    setConfigurationValue("PKCS11_MODULE", "pkcs11Module");
    setConfigurationValue("OCSP_SOURCE", "ocspSource");
  }

  private void setConfigurationValue(String fileKey, String configurationKey) {
    logger.debug("");
    if (configurationFromFile == null) return;
    Object fileValue = configurationFromFile.get(fileKey);
    if (fileValue != null) {
      configuration.put(configurationKey, fileValue.toString());
    }
  }

  private void setJDigiDocConfigurationValue(String key, String defaultValue) {
    logger.debug("Key: " + key + ", default value: " + defaultValue);
    jDigiDocConfiguration.put(key, defaultIfNull(key, defaultValue));
  }

  /**
   * Set the maximum size of data files to be cached. Used by DigiDoc4J and by JDigiDoc.
   *
   * @param maxDataFileCached Maximum size in MB
   */
  public void setMaxDataFileCachedinMB(long maxDataFileCached) {
    logger.debug("Set maximum datafile cached to: " + maxDataFileCached);
    jDigiDocConfiguration.put("DIGIDOC_MAX_DATAFILE_CACHED", Long.toString(maxDataFileCached));
  }

  /**
   * Returns configuration item must be OCSP request signed. Reads it from configuration parameter SIGN_OCSP_REQUESTS.
   * Default value is true for {@link Configuration.Mode#PROD} and false for {@link Configuration.Mode#TEST}
   *
   * @return must be OCSP request signed
   */
  public boolean hasToBeOCSPRequestSigned() {
    return Boolean.parseBoolean(jDigiDocConfiguration.get("SIGN_OCSP_REQUESTS"));
  }

  /**
   * Get the maximum size of data files to be cached. Used by DigiDoc4J and by JDigiDoc.
   *
   * @return Size in MB
   */
  public long getMaxDataFileCachedInMB() {
    String maxDataFileCached = jDigiDocConfiguration.get("DIGIDOC_MAX_DATAFILE_CACHED");
    logger.debug("Maximum datafile cached: " + maxDataFileCached);
    return Long.parseLong(maxDataFileCached);
  }

  private String defaultIfNull(String configParameter, String defaultValue) {
    logger.debug("Parameter: " + configParameter + ", default value: " + defaultValue);
    if (configurationFromFile == null) return defaultValue;
    Object value = configurationFromFile.get(configParameter);
    if (value != null) {
      return verifyValueIsAllowed(configParameter, value.toString()) ? value.toString() : "";
    }
    String configuredValue = jDigiDocConfiguration.get(configParameter);
    return configuredValue != null ? configuredValue : defaultValue;
  }

  private boolean verifyValueIsAllowed(String configParameter, String value) {
    logger.debug("");
    boolean errorFound = false;
    List<String> mustBeBooleans =
        asList("SIGN_OCSP_REQUESTS", "KEY_USAGE_CHECK", "DATAFILE_HASHCODE_MODE", "DIGIDOC_USE_LOCAL_TSL");
    List<String> mustBeNumerics = asList("DIGIDOC_MAX_DATAFILE_CACHED");

    if (mustBeBooleans.contains(configParameter)) {
      if (!("true".equals(value.toLowerCase()) || "false".equals(value.toLowerCase()))) {
        String errorMessage = "Configuration parameter " + configParameter + " should be set to true or false "
            + "but the actual value is: " + value + ". Configuration file: " + configurationFileName;
        logger.error(errorMessage);
        fileParseErrors.add(errorMessage);
        errorFound = true;
      }
    }

    if (mustBeNumerics.contains(configParameter)) {
      if (!isNumeric(value)) {
        String errorMessage = "Configuration parameter " + configParameter + " should have a numeric value "
            + "but the actual value is: " + value + ". Configuration file: " + configurationFileName;
        logger.error(errorMessage);
        fileParseErrors.add(errorMessage);
        errorFound = true;
      }
    }
    return (!errorFound);
  }

  private void loadOCSPCertificates(LinkedHashMap digiDocCA, String caPrefix) {
    String errorMessage;
    logger.debug("");

    @SuppressWarnings("unchecked")
    ArrayList<LinkedHashMap> ocsps = (ArrayList<LinkedHashMap>) digiDocCA.get("OCSPS");
    if (ocsps == null) {
      errorMessage = "No OCSPS entry found or OCSPS entry is empty. Configuration file: " + configurationFileName;
      logger.error(errorMessage);
      fileParseErrors.add(errorMessage);
      return;
    }

    int numberOfOCSPCertificates = ocsps.size();
    jDigiDocConfiguration.put(caPrefix + "_OCSPS", String.valueOf(numberOfOCSPCertificates));

    for (int i = 1; i <= numberOfOCSPCertificates; i++) {
      String prefix = caPrefix + "_OCSP" + i;
      LinkedHashMap ocsp = ocsps.get(i - 1);

      List<String> entries = asList("CA_CN", "CA_CERT", "CN", "URL");
      for (String entry : entries) {
        if (!loadOCSPCertificateEntry(entry, ocsp, prefix)) {
          errorMessage = "OCSPS list entry " + i + " does not have an entry for " + entry
              + " or the entry is empty\n";
          logger.error(errorMessage);
          fileParseErrors.add(errorMessage);
        }
      }

      if (!getOCSPCertificates(prefix, ocsp)) {
        errorMessage = "OCSPS list entry " + i + " does not have an entry for CERTS or the entry is empty\n";
        logger.error(errorMessage);
        fileParseErrors.add(errorMessage);
      }
    }
  }

  private boolean loadOCSPCertificateEntry(String ocspsEntryName, LinkedHashMap ocsp, String prefix) {

    Object ocspEntry = ocsp.get(ocspsEntryName);
    if (ocspEntry == null) return false;
    jDigiDocConfiguration.put(prefix + "_" + ocspsEntryName, ocspEntry.toString());
    return true;
  }

  @SuppressWarnings("unchecked")
  private boolean getOCSPCertificates(String prefix, LinkedHashMap ocsp) {
    logger.debug("");
    ArrayList<String> certificates = (ArrayList<String>) ocsp.get("CERTS");
    if (certificates == null) return false;
    for (int j = 0; j < certificates.size(); j++) {
      if (j == 0) {
        jDigiDocConfiguration.put(prefix + "_CERT", certificates.get(0));
      } else {
        jDigiDocConfiguration.put(prefix + "_CERT_" + j, certificates.get(j));
      }
    }
    return true;
  }

  private void loadCertificateAuthorityCerts(LinkedHashMap digiDocCA, String caPrefix) {
    logger.debug("");
    ArrayList<String> certificateAuthorityCerts = getCACertsAsArray(digiDocCA);

    jDigiDocConfiguration.put(caPrefix + "_NAME", digiDocCA.get("NAME").toString());
    jDigiDocConfiguration.put(caPrefix + "_TRADENAME", digiDocCA.get("TRADENAME").toString());
    int numberOfCACertificates = certificateAuthorityCerts.size();
    jDigiDocConfiguration.put(caPrefix + "_CERTS", String.valueOf(numberOfCACertificates));

    for (int i = 0; i < numberOfCACertificates; i++) {
      String certFile = certificateAuthorityCerts.get(i);
      jDigiDocConfiguration.put(caPrefix + "_CERT" + (i + 1), certFile);
    }
  }

  @SuppressWarnings("unchecked")
  private ArrayList<String> getCACertsAsArray(LinkedHashMap digiDocCa) {
    logger.debug("");
    return (ArrayList<String>) digiDocCa.get("CERTS");
  }

  /**
   * get the TSL location
   *
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
   *
   * @param tslLocation TSL Location to be used
   */
  public void setTslLocation(String tslLocation) {
    logger.debug("Set TSL location: " + tslLocation);
    setConfigurationParameter("tslLocation", tslLocation);
  }

  /**
   * Get the TSP Source
   *
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
   *
   * @param tspSource TSPSource to be used
   */
  public void setTspSource(String tspSource) {
    logger.debug("Set TSP source: " + tspSource);
    setConfigurationParameter("tspSource", tspSource);
  }

  /**
   * Get the OCSP Source
   *
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
   *
   * @param ocspSource OCSP Source to be used
   */
  public void setOcspSource(String ocspSource) {
    logger.debug("Set OCSP source: " + ocspSource);
    setConfigurationParameter("ocspSource", ocspSource);
  }

  /**
   * Get the validation policy
   *
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
   *
   * @param validationPolicy Policy to be used
   */
  public void setValidationPolicy(String validationPolicy) {
    logger.debug("Set validation policy: " + validationPolicy);
    setConfigurationParameter("validationPolicy", validationPolicy);
  }

  /**
   * Get the PKCS11 Module path
   *
   * @return path
   */
  public String getPKCS11ModulePath() {
    logger.debug("");
    String path = getConfigurationParameter("pkcs11Module");
    logger.debug("PKCS11 module path: " + path);
    return path;
  }

  private void setConfigurationParameter(String key, String value) {
    logger.debug("Key: " + key + ", value: " + value);
    configuration.put(key, value);
  }

  private String getConfigurationParameter(String key) {
    logger.debug("Key: " + key);
    String value = configuration.get(key);
    logger.debug("Value: " + value);
    return value;
  }
}
