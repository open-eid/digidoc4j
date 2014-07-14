package org.digidoc4j.api;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ConfigurationTest {
  private Configuration configuration;

  @Before
  public void setUp() {
    configuration = new Configuration();
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
}