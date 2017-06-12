package org.digidoc4j.impl.edoc;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import java.util.List;

import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.TimestampAndOcspResponseTimeDeltaTooLargeException;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by kamlatm on 4.05.2017.
 */
public class TimeStampValidationForEDocTest {

  private final static Logger logger = LoggerFactory.getLogger(TimeStampValidationForEDocTest.class);

  private static final String EDOC_LOCATION = "testFiles/valid-containers/latvian_signed_container.edoc";
  private static final String ASICE_LOCATION = "testFiles/valid-containers/latvian_signed_container.asice";
  private Configuration configuration;


  @Before
  public void setUp() {
    configuration = new Configuration(Configuration.Mode.PROD);
  }

  @Test
  public void invalidTimestampMsgIsNotExistForEDOC() {

    Container container = ContainerOpener.open(EDOC_LOCATION, configuration);
    ValidationResult validate = container.validate();
    // We expect that there are no errors in tested container
    assertEquals(0, validate.getErrors().size());
  }

  @Test
  public void invalidTimestampMsgIsNotExistForASICE() {

    Container container = ContainerOpener.open(ASICE_LOCATION, configuration);
    ValidationResult validate = container.validate();
    // We expect that there are no errors in tested container
    assertEquals(0, validate.getErrors().size());
  }

  // TODO: Find or create test container with specific error
}
