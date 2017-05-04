package org.digidoc4j.impl.edoc;

import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.Signature;
import org.digidoc4j.ValidationResult;
import org.junit.Test;

/**
 * Created by kamlatm on 4.05.2017.
 */
public class TimeStampValidationForEDocTest {

  private final String BDOC = "BDOC";
  private final String EDOC_LOCATION = "testFiles/valid-containers/valid_edoc2_lv-eId_sha256.edoc";
  private Configuration configuration = new Configuration(Configuration.Mode.TEST);


  @Test
  public void edocTest(){

    Container container = ContainerBuilder.
        aContainer(BDOC).
        fromExistingFile(EDOC_LOCATION)
        .withConfiguration(configuration)
        .build();

    Signature signature = container.getSignatures().get(0);
    System.out.println("ARVUTI KELL:" + signature.getClaimedSigningTime());
    System.out.println("USALDATUD KELL:" + signature.getTrustedSigningTime());

    ValidationResult validate = container.validate();

    System.out.println("MESSAGE: "+validate.getErrors());
  }

}
