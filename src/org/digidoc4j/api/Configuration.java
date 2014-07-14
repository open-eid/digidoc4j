package org.digidoc4j.api;

public class Configuration {
  private String tslLocation = "file:conf/trusted-test-tsl.xml";
  private String tspSource = "http://tsa01.quovadisglobal.com/TSS/HttpTspServer";
  private String validationPolicy = "conf/constraint.xml";

  public Configuration() {
  }

  public String getTslLocation() {
    return tslLocation;
  }

  public void setTslLocation(String tslLocation) {
    this.tslLocation = tslLocation;
  }

  public String getTspSource() {
    return tspSource;
  }

  public void setTspSource(String tspSource) {
    this.tspSource = tspSource;
  }

  public String getValidationPolicy() {
    return validationPolicy;
  }

  public void setValidationPolicy(String validationPolicy) {
    this.validationPolicy = validationPolicy;
  }
}
