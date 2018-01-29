package org.digidoc4j.impl.edoc;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.test.Refactored;
import org.junit.Assert;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Created by kamlatm on 4.05.2017.
 */

@Category(Refactored.class)
public class TimeStampValidationForEDocTest extends AbstractTest {

  private static final String EDOC_LOCATION = "src/test/resources/testFiles/valid-containers/latvian_signed_container.edoc";
  private static final String ASICE_LOCATION = "src/test/resources/testFiles/valid-containers/latvian_signed_container.asice";

  @Test
  public void invalidTimestampMsgIsNotExistForEDOC() {
    Container container = ContainerOpener.open(EDOC_LOCATION, this.configuration);
    Assert.assertEquals(0, container.validate().getErrors().size());
  }

  @Test
  public void invalidTimestampMsgIsNotExistForASICE() {
    Container container = ContainerOpener.open(ASICE_LOCATION, this.configuration);
    Assert.assertEquals(0, container.validate().getErrors().size());
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.configuration = new Configuration(Configuration.Mode.PROD);
  }

}
