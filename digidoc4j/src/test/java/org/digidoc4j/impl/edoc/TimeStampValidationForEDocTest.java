package org.digidoc4j.impl.edoc;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.exceptions.TimestampAfterOCSPResponseTimeException;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import java.nio.file.Paths;

/**
 * Created by kamlatm on 4.05.2017.
 */

public class TimeStampValidationForEDocTest extends AbstractTest {

  private static final String EDOC_LOCATION = "src/test/resources/testFiles/invalid-containers/latvian_signed_container.edoc";
  private static final String ASICE_LOCATION = "src/test/resources/testFiles/valid-containers/latvian_signed_container.asice";

  @Test
  public void timestampAfterOcspResponseTimeShouldResultInInvalidContainerForEDOC() {
    ContainerValidationResult validationResult = this.openContainerByConfiguration(Paths.get(EDOC_LOCATION)).validate();
    Assert.assertFalse("Signature should be invalid if timestamp was taken after OCSP", validationResult.isValid());
    Assert.assertEquals(2, validationResult.getErrors().size());
    Assert.assertTrue("Validation result should contain " + TimestampAfterOCSPResponseTimeException.class.getSimpleName(),
            validationResult.getErrors().get(1) instanceof TimestampAfterOCSPResponseTimeException);
  }

  @Test
  public void invalidTimestampMsgIsNotExistForASICE() {
    Assert.assertEquals(1, this.openContainerByConfiguration(Paths.get(ASICE_LOCATION)).validate().getErrors().size());
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.configuration = new Configuration(Configuration.Mode.PROD);
  }

}
