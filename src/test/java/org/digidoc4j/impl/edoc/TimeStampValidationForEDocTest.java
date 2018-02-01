package org.digidoc4j.impl.edoc;

import java.nio.file.Paths;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.junit.Assert;
import org.junit.Test;

/**
 * Created by kamlatm on 4.05.2017.
 */

public class TimeStampValidationForEDocTest extends AbstractTest {

  private static final String EDOC_LOCATION = "src/test/resources/testFiles/valid-containers/latvian_signed_container.edoc";
  private static final String ASICE_LOCATION = "src/test/resources/testFiles/valid-containers/latvian_signed_container.asice";

  @Test
  public void invalidTimestampMsgIsNotExistForEDOC() {
    Assert.assertEquals(0, this.openContainerByConfiguration(Paths.get(EDOC_LOCATION)).validate().getErrors().size());
  }

  @Test
  public void invalidTimestampMsgIsNotExistForASICE() {
    Assert.assertEquals(0, this.openContainerByConfiguration(Paths.get(ASICE_LOCATION)).validate().getErrors().size());
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.setGlobalMode(Configuration.Mode.PROD);
    this.configuration = new Configuration(Configuration.Mode.PROD);
  }

}
