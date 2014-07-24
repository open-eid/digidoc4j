package org.digidoc4j.api;

import org.junit.Before;
import org.junit.Test;

import static org.digidoc4j.api.Configuration.Mode.PROD;
import static org.digidoc4j.api.Configuration.Mode.TEST;
import static org.junit.Assert.assertEquals;

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
  public void defaultConstructorWithUnSetSystemProperty() throws Exception {
    Configuration configuration = new Configuration();
    assertEquals("http://sr.riik.ee/tsl/estonian-tsl.xml", configuration.getTslLocation());
  }

  @Test
  public void testGetPKCS11ModulePath() throws Exception {
    assertEquals("/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so", configuration.getPKCS11ModulePath());
  }
}