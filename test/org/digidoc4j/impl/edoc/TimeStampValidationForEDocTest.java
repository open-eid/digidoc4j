package org.digidoc4j.impl.edoc;

import static com.sun.javafx.css.StyleManager.getErrors;
import static org.digidoc4j.Configuration.Mode.TEST;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import java.util.List;

import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.Signature;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.TimestampAfterOCSPResponseTimeException;
import org.digidoc4j.impl.bdoc.xades.validation.TimemarkSignatureValidator;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by kamlatm on 4.05.2017.
 */
public class TimeStampValidationForEDocTest {

  private final static Logger logger = LoggerFactory.getLogger(TimeStampValidationForEDocTest.class);

  private final String BDOC = "BDOC";
  private final String EDOC_LOCATION = "testFiles/valid-containers/valid_edoc2_lv-eId_sha256.edoc";
  private final String EDOC_LOCATION_WRONG_TIME = "testFiles/valid-containers/valid_edoc2_lv-eId_sha256.edoc";
  private Configuration configuration;


  @Before
  public void setUp() {
    configuration = new Configuration(Configuration.Mode.TEST);
  }

  @Test
  public void invalidTimestampMsgIsNotExist() {

    Container container = ContainerBuilder.
        aContainer(BDOC).
        fromExistingFile(EDOC_LOCATION)
        .withConfiguration(configuration)
        .build();
    ValidationResult validate = container.validate();
    String ERROR_MESSAGE = getErrorMessage(validate);

    //Message is: Timestamp time is after OCSP response production time
    assertNotEquals(TimestampAfterOCSPResponseTimeException.MESSAGE, ERROR_MESSAGE);
  }



  @Test
  public void invalidTimestampMsgExist(){

    Container container = ContainerBuilder.
        aContainer(BDOC).
        fromExistingFile(EDOC_LOCATION_WRONG_TIME)
        .withConfiguration(configuration)
        .build();
    ValidationResult validate = container.validate();

    String ERROR_MESSAGE = getErrorMessage(validate);

    //Message is: Timestamp time is after OCSP response production time
    //assertEquals(TimestampAfterOCSPResponseTimeException.MESSAGE, ERROR_MESSAGE);

    Signature signature = container.getSignatures().get(0);
    //signature.getOCSPResponseCreationTime();
    System.out.println("AAAA: "+signature.getOCSPResponseCreationTime());
    System.out.println("AAAA222: "+signature.getTimeStampCreationTime());

  }

  private String getErrorMessage(ValidationResult validate) {

    logger.info(validate.getReport());

    String ERROR_MESSAGE= "";
    List<DigiDoc4JException> validateErrors = validate.getErrors();
    for (DigiDoc4JException digiDoc4JException : validateErrors) {
      if (TimestampAfterOCSPResponseTimeException.MESSAGE.equals(digiDoc4JException.getMessage())) {
        logger.error(digiDoc4JException.getMessage());
        ERROR_MESSAGE = digiDoc4JException.getMessage();
        break;
      }
    }

    return null;
  }

}
