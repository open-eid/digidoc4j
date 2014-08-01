package org.digidoc4j.api;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Possibility to create custom configurations for {@link org.digidoc4j.api.Container} implementation.
 * <p/>
 * You cas specify configuration mode. Is it {@link Configuration.Mode#TEST} or {@link Configuration.Mode#PROD}
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
  private LinkedHashMap configurationFromFile;

  public enum Mode {
    TEST,
    PROD
  }

  protected enum OS {
    Linux,
    Win,
    OSX
  }

  Map<String, String> testConfiguration = new HashMap<String, String>();
  Map<String, String> productionConfiguration = new HashMap<String, String>();
  Map<Mode, Map<String, String>> configuration = new HashMap<Mode, Map<String, String>>();

  public Configuration() {
    logger.debug("");
    if ("TEST".equalsIgnoreCase(System.getProperty("digidoc4j.mode")))
      mode = Mode.TEST;
    else
      mode = Mode.PROD;

    logger.info("Configuration loaded for " + mode + " mode");

    initDefaultValues();
  }

  public Configuration(Mode mode) {
    logger.debug("Mode: " + mode);
    this.mode = mode;
    initDefaultValues();
  }

  private void initDefaultValues() {
    logger.debug("");
//    testConfiguration.put("tslLocation", "http://ftp.id.eesti.ee/pub/id/tsl/trusted-test-mp.xml");
    testConfiguration.put("tslLocation", "file:conf/trusted-test-tsl.xml");
    productionConfiguration.put("tslLocation", "http://sr.riik.ee/tsl/estonian-tsl.xml");

    testConfiguration.put("tspSource", "http://tsa01.quovadisglobal.com/TSS/HttpTspServer");
    productionConfiguration.put("tspSource", "http://tsa01.quovadisglobal.com/TSS/HttpTspServer");

    testConfiguration.put("validationPolicy", "conf/constraint.xml");
    productionConfiguration.put("validationPolicy", "conf/constraint.xml");

    testConfiguration.put("pkcs11ModuleLinux", "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so");
    productionConfiguration.put("pkcs11ModuleLinux", "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so");

    testConfiguration.put("ocspSource", "http://www.openxades.org/cgi-bin/ocsp.cgi");
    productionConfiguration.put("ocspSource", "http://ocsp.org.ee");

    configuration.put(Mode.TEST, testConfiguration);
    configuration.put(Mode.PROD, productionConfiguration);

    logger.debug("Test configuration:\n" + configuration.get(Mode.TEST));
    logger.debug("Prod configuration:\n" + configuration.get(Mode.PROD));
  }

  public void addConfiguration(String file) {
    logger.debug("File " + file);
    Yaml yaml = new Yaml();
    configurationFromFile = (LinkedHashMap) yaml.load(this.getClass().getClassLoader().getResourceAsStream(file));
  }

  public List<X509Certificate> getCACerts() {
    logger.debug("");
    List<X509Certificate> certificates = new ArrayList<X509Certificate>();
    ArrayList<String> certificateAuthorityCerts = getCACertsAsArray((LinkedHashMap) configurationFromFile.get("DIGIDOC_CA"));
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

    InputStream certAsStream = getClass().getClassLoader().getResourceAsStream(certFile.substring(6));
    X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(certAsStream);
    IOUtils.closeQuietly(certAsStream);

    return cert;
  }

  public Hashtable<String, String> getJDigiDocConf() {
    logger.debug("loading JDigiDoc configuration");
    Hashtable<String, String> configuration = new Hashtable<String, String>();

    configuration.put("DIGIDOC_LOG4J_CONFIG", defaultIfNull("DIGIDOC_LOG4J_CONFIG", "./log4j.properties"));
    configuration.put("DIGIDOC_SECURITY_PROVIDER", defaultIfNull("DIGIDOC_SECURITY_PROVIDER", "org.bouncycastle.jce.provider.BouncyCastleProvider"));
    configuration.put("DIGIDOC_SECURITY_PROVIDER_NAME", defaultIfNull("DIGIDOC_SECURITY_PROVIDER_NAME", "BC"));
    configuration.put("DATAFILE_HASHCODE_MODE", defaultIfNull("DATAFILE_HASHCODE_MODE", "false"));
    configuration.put("CANONICALIZATION_FACTORY_IMPL", defaultIfNull("CANONICALIZATION_FACTORY_IMPL", "ee.sk.digidoc.c14n.TinyXMLCanonicalizer"));
    configuration.put("DIGIDOC_MAX_DATAFILE_CACHED", defaultIfNull("DIGIDOC_MAX_DATAFILE_CACHED", "4096"));
    configuration.put("DIGIDOC_USE_LOCAL_TSL", defaultIfNull("DIGIDOC_USE_LOCAL_TSL", "true"));
    configuration.put("DIGIDOC_NOTARY_IMPL", defaultIfNull("DIGIDOC_NOTARY_IMPL", "ee.sk.digidoc.factory.BouncyCastleNotaryFactory"));
    configuration.put("DIGIDOC_TSLFAC_IMPL", defaultIfNull("DIGIDOC_TSLFAC_IMPL", "ee.sk.digidoc.tsl.DigiDocTrustServiceFactory"));
    configuration.put("DIGIDOC_OCSP_RESPONDER_URL", getOcspSource());
    configuration.put("DIGIDOC_FACTORY_IMPL", defaultIfNull("DIGIDOC_FACTORY_IMPL", "ee.sk.digidoc.factory.SAXDigiDocFactory"));
    configuration.put("SIGN_OCSP_REQUESTS", defaultIfNull("SIGN_OCSP_REQUESTS=false", "false"));

    loadCertificateAutorityCerts(configuration);
    loadOCSPCertificates(configuration);

    return configuration;
  }

  private String defaultIfNull(String configParameter, String defaultValue) {
    logger.debug("Parameter: " + configParameter + ", default value: " + defaultValue);
    Object value = configurationFromFile.get(configParameter);
    return value != null ? value.toString() : defaultValue;
  }

  private void loadOCSPCertificates(Hashtable<String, String> configuration) {
    logger.debug("");
    LinkedHashMap digidocCA = (LinkedHashMap) configurationFromFile.get("DIGIDOC_CA");
    @SuppressWarnings("unchecked")
    ArrayList<LinkedHashMap> ocsps = (ArrayList<LinkedHashMap>) digidocCA.get("OCSPS");
    int numberOfOCSPCertificates = ocsps.size();
    configuration.put("DIGIDOC_CA_1_OCSPS", String.valueOf(numberOfOCSPCertificates));

    for (int i = 1; i <= numberOfOCSPCertificates; i++) {
      LinkedHashMap ocsp = ocsps.get(i - 1);
      String prefix = "DIGIDOC_CA_1_OCSP" + i;
      configuration.put(prefix + "_CA_CN", ocsp.get("CA_CN").toString());
      configuration.put(prefix + "_CA_CERT", ocsp.get("CA_CERT").toString());
      configuration.put(prefix + "_CN", ocsp.get("CN").toString());
      getOCSPCertificates(configuration, prefix, ocsp);
      configuration.put(prefix + "_URL", ocsp.get("URL").toString());
    }
  }

  private void getOCSPCertificates(Hashtable<String, String> configuration, String prefix, LinkedHashMap ocsp) {
    logger.debug("");
    ArrayList<String> certificates = (ArrayList<String>) ocsp.get("CERTS");
    for (int j = 0; j < certificates.size(); j++) {
      if (j == 0) {
        configuration.put(prefix + "_CERT", certificates.get(0));
      } else {
        configuration.put(prefix + "_CERT_" + j, certificates.get(j));
      }
    }
  }

  private void loadCertificateAutorityCerts(Hashtable<String, String> configuration) {
    logger.debug("");
    LinkedHashMap digidocCA = (LinkedHashMap) configurationFromFile.get("DIGIDOC_CA");
    ArrayList<String> certificateAuthorityCerts = getCACertsAsArray(digidocCA);

    configuration.put("DIGIDOC_CAS", "1");
    configuration.put("DIGIDOC_CA_1_NAME", digidocCA.get("NAME").toString());
    configuration.put("DIGIDOC_CA_1_TRADENAME", digidocCA.get("TRADENAME").toString());
    int numberOfCACertificates = certificateAuthorityCerts.size();
    configuration.put("DIGIDOC_CA_1_CERTS", String.valueOf(numberOfCACertificates));

    for (int i = 0; i < numberOfCACertificates; i++) {
      String certFile = certificateAuthorityCerts.get(i);
      configuration.put("DIGIDOC_CA_1_CERT" + (i + 1), certFile);
    }
  }

  @SuppressWarnings("unchecked")
  private ArrayList<String> getCACertsAsArray(LinkedHashMap jDigiDocCa) {
    logger.debug("");
    return (ArrayList<String>) jDigiDocCa.get("CERTS");
  }

  public String getTslLocation() {
    logger.debug("");
    String tslLocation = getConfigurationParameter("tslLocation");
    logger.debug("TSL Location: " + tslLocation);
    return tslLocation;
  }

  public void setTslLocation(String tslLocation) {
    logger.debug("TSL location: " + tslLocation);
    setConfigurationParameter("tslLocation", tslLocation);
  }

  public String getTspSource() {
    logger.debug("");
    String tspSource = getConfigurationParameter("tspSource");
    logger.debug("TSP Source: " + tspSource);
    return tspSource;
  }

  public void setTspSource(String tspSource) {
    logger.debug("TSP source: " + tspSource);
    setConfigurationParameter("tspSource", tspSource);
  }

  public String getOcspSource() {
    logger.debug("");
    String ocspSource = getConfigurationParameter("ocspSource");
    logger.debug("OCSP source: " + ocspSource);
    return ocspSource;
  }

  public void setOcspSource(String ocspSource) {
    logger.debug("OCSP source: " + ocspSource);
    setConfigurationParameter("ocspSource", ocspSource);
  }

  public String getValidationPolicy() {
    logger.debug("");
    String validationPolicy = getConfigurationParameter("validationPolicy");
    logger.debug("Validation policy: " + validationPolicy);
    return validationPolicy;
  }

  public void setValidationPolicy(String validationPolicy) {
    logger.debug("Validation policy: " + validationPolicy);
    setConfigurationParameter("validationPolicy", validationPolicy);
  }

  String getPKCS11ModulePathForOS(OS os, String key) {
    logger.debug("");
    return getConfigurationParameter(key + os);
  }

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
