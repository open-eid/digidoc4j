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

  private static final String EDOC_CONTAINER_TYPE = "BDOC";
  // private static final String EDOC_LOCATION = "testFiles/valid-containers/valid_edoc2_lv-eId_sha256.edoc";
  private static final String EDOC_LOCATION = "testFiles/valid-containers/latvian_signed_container.edoc";
  // TODO: select container for negative test from directory "testFiles/invalid-containers/"
  // private final String EDOC_LOCATION_WRONG_TIME = "testFiles/valid-containers/valid_edoc2_lv-eId_sha256.edoc";
  private Configuration configuration;


  @Before
  public void setUp() {
    configuration = new Configuration(Configuration.Mode.PROD);
  }

  @Test
  public void invalidTimestampMsgIsNotExist() {

    Container container = ContainerOpener.open(EDOC_LOCATION, configuration);
    ValidationResult validate = container.validate();
    // We expect that there are no errors in tested container
    assertEquals(0, validate.getErrors().size());
  }

  // TODO: Find or create test container with specific error
  /*
  @Test
  public void invalidTimestampMsgExist(){

    Container container = ContainerBuilder.
        aContainer(BDOC).
        fromExistingFile(EDOC_LOCATION_WRONG_TIME)
        .withConfiguration(configuration)
        .build();
    ValidationResult validate = container.validate();

    String ERROR_MESSAGE = getErrorMessage(validate);

    //Message is: The difference between the OCSP response time and the signature time stamp is too large
    assertEquals(TimestampAndOcspResponseTimeDeltaTooLargeException.MESSAGE, ERROR_MESSAGE);

  }

  private String getErrorMessage(ValidationResult validate) {

    logger.info(validate.getReport());

    String ERROR_MESSAGE= "";
    List<DigiDoc4JException> validateErrors = validate.getErrors();
    for (DigiDoc4JException digiDoc4JException : validateErrors) {
      if (TimestampAndOcspResponseTimeDeltaTooLargeException.MESSAGE.equals(digiDoc4JException.getMessage())) {
        logger.error(digiDoc4JException.getMessage());
        ERROR_MESSAGE = digiDoc4JException.getMessage();
        break;
      }
    }
    return ERROR_MESSAGE;
  }
  */

}
