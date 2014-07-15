package org.digidoc4j.api;

import java.util.HashMap;
import java.util.Map;

/**
 * Possibility to create custom configurations for {@link Container} implementation.
 * <p>
 * You cas specify configuration mode. Is it {link Mode.TEST#TEST} or PROD configuration. Default is PROD.
 * Also it is possible to set mode by System property. Setting property "digidoc4j.mode" to TEST forces default mode to TEST mode
 */
public class Configuration {
  private final Mode mode;

  public enum Mode {
    TEST,
    PROD
  }

  Map<String, String> testConfiguration = new HashMap<String, String>();
  Map<String, String> productionConfiguration = new HashMap<String, String>();
  Map<Mode, Map<String, String>> configuration = new HashMap<Mode, Map<String, String>>();

  public Configuration() {
    if ("TEST".equalsIgnoreCase(System.getProperty("digidoc4j.mode")))
      mode = Mode.TEST;
    else
      mode = Mode.PROD;

    initDefaultValues();
  }

  public Configuration(Mode mode) {
    this.mode = mode;
    initDefaultValues();
  }

  private void initDefaultValues() {
//    testConfiguration.put("tslLocation", "http://ftp.id.eesti.ee/pub/id/tsl/trusted-test-mp.xml");
    testConfiguration.put("tslLocation", "file:conf/trusted-test-tsl.xml");
    productionConfiguration.put("tslLocation", "http://sr.riik.ee/tsl/estonian-tsl.xml");

    testConfiguration.put("tspSource", "http://tsa01.quovadisglobal.com/TSS/HttpTspServer");
    productionConfiguration.put("tspSource", "http://tsa01.quovadisglobal.com/TSS/HttpTspServer");

    testConfiguration.put("validationPolicy", "conf/constraint.xml");
    productionConfiguration.put("validationPolicy", "conf/constraint.xml");

    configuration.put(Mode.TEST, testConfiguration);
    configuration.put(Mode.PROD, productionConfiguration);
  }

  public String getTslLocation() {
    return getConfigurationParameter("tslLocation");
  }

  public void setTslLocation(String tslLocation) {
    setConfigurationParameter("tslLocation", tslLocation);
  }

  public String getTspSource() {
    return getConfigurationParameter("tspSource");
  }

  public void setTspSource(String tspSource) {
    setConfigurationParameter("tspSource", tspSource);
  }

  public String getValidationPolicy() {
    return getConfigurationParameter("validationPolicy");
  }

  public void setValidationPolicy(String validationPolicy) {
    setConfigurationParameter("validationPolicy", validationPolicy);
  }

  private void setConfigurationParameter(String key, String value) {
    configuration.get(mode).put(key, value);
  }

  private String getConfigurationParameter(String key) {
    return configuration.get(mode).get(key);
  }
}
