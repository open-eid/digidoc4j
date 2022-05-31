package org.digidoc4j.impl.edoc;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.exceptions.TimestampAfterOCSPResponseTimeException;
import org.digidoc4j.test.TestAssert;
import org.junit.Assert;
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
    TestAssert.assertContainsExactSetOfErrors(validationResult.getErrors(),
            "Timestamp time is after OCSP response production time",
            "The certificate is not related to a TSA/QTST!"
    );
    Assert.assertTrue("Validation result should contain " + TimestampAfterOCSPResponseTimeException.class.getSimpleName(),
            validationResult.getErrors().stream().anyMatch(e -> e instanceof TimestampAfterOCSPResponseTimeException));
  }

  @Test
  public void invalidTimestampMsgIsNotExistForASICE() {
    ContainerValidationResult validationResult = this.openContainerByConfiguration(Paths.get(ASICE_LOCATION)).validate();
    TestAssert.assertContainsExactSetOfErrors(validationResult.getErrors(),
            "The certificate is not related to a TSA/QTST!"
    );
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.configuration = new Configuration(Configuration.Mode.PROD);
  }

}
