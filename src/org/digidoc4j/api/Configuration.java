package org.digidoc4j.api;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

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
    logger.debug("");
    this.mode = mode;
    logger.info("Configuration loaded for " + mode + " mode");
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

    configuration.put(Mode.TEST, testConfiguration);
    configuration.put(Mode.PROD, productionConfiguration);

    logger.debug("Test configuration:\n" + configuration.get(Mode.TEST));
    logger.debug("Prod configuration:\n" + configuration.get(Mode.PROD));
  }

  public String getTslLocation() {
    logger.debug("");
    String tslLocation = getConfigurationParameter("tslLocation");
    logger.debug("TSL Location: " + tslLocation);
    return tslLocation;
  }

  public void setTslLocation(String tslLocation) {
    logger.debug("");
    setConfigurationParameter("tslLocation", tslLocation);
    logger.debug("TSL Location set to: " + tslLocation);
  }

  public String getTspSource() {
    logger.debug("");
    String tspSource = getConfigurationParameter("tspSource");
    logger.debug("TSP Source: " + tspSource);
    return tspSource;
  }

  public void setTspSource(String tspSource) {
    logger.debug("");
    setConfigurationParameter("tspSource", tspSource);
    logger.debug("TSP Source set to " + tspSource);
  }

  public String getValidationPolicy() {
    logger.debug("");
    String validationPolicy = getConfigurationParameter("validationPolicy");
    logger.debug("Validation policy: " + validationPolicy);
    return validationPolicy;
  }

  public void setValidationPolicy(String validationPolicy) {
    logger.debug("");
    setConfigurationParameter("validationPolicy", validationPolicy);
    logger.debug("Validation policy set to: " + validationPolicy);
  }

  String getPKCS11ModulePathForOS(OS os, String key) {
    return getConfigurationParameter(key + os);
  }

  public String getPKCS11ModulePath() {
    logger.debug("");
    String path = getPKCS11ModulePathForOS(OS.Linux, "pkcs11Module");
    logger.debug("PKCS11 module path: " + path);
    return path;
  }

  private void setConfigurationParameter(String key, String value) {
    logger.debug("");
    configuration.get(mode).put(key, value);
    logger.debug("Configuration set: Key = " + key + ", value = " + value);
  }

  private String getConfigurationParameter(String key) {
    logger.debug("");
    String value = configuration.get(mode).get(key);
    logger.debug("Configuration value for key: " + key + " is: " + value);
    return value;
  }
}
