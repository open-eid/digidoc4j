package org.digidoc4j;

import org.junit.BeforeClass;

public class DigiDoc4JTestHelper {

  @BeforeClass
  public static void setConfigurationToTest() {
    System.setProperty("digidoc4j.mode", "TEST");
  }


}
