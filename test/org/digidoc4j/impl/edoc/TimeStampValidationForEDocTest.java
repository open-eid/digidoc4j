package org.digidoc4j.impl.edoc;

import static com.sun.javafx.css.StyleManager.getErrors;
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
  private Configuration configuration = new Configuration(Configuration.Mode.TEST);


  @Test
  public void invalidTimestampMsgIsNotExist() {

    String ERROR_MESSAGE = "";

    Container container = ContainerBuilder.
        aContainer(BDOC).
        fromExistingFile(EDOC_LOCATION)
        .withConfiguration(configuration)
        .build();

    ValidationResult validate = container.validate();
    logger.info(validate.getReport());

    List<DigiDoc4JException> validateErrors = validate.getErrors();

    for (DigiDoc4JException digiDoc4JException : validateErrors) {
      if (TimestampAfterOCSPResponseTimeException.MESSAGE.equals(digiDoc4JException.getMessage())) {
        logger.error(digiDoc4JException.getMessage());
        ERROR_MESSAGE = digiDoc4JException.getMessage();
        break;
      }
    }

    //Message is: Timestamp time is after OCSP response production time
    assertNotEquals(TimestampAfterOCSPResponseTimeException.MESSAGE, ERROR_MESSAGE);
  }

  //TODO: puuduolevad testid ajavahemiku testimiseks

}
