package org.digidoc4j;

import java.util.List;

import org.digidoc4j.exceptions.DigiDoc4JException;
import org.junit.Before;
import org.junit.Test;

public class TLWellSignedParameterTest {

    private Configuration eIDASConfiguration = new Configuration(Configuration.Mode.TEST);
    private Configuration defaultConfiguration = new Configuration(Configuration.Mode.TEST);

    private final String EIDAS_CONF = "conf/eIDAS_test_constraint.xml";
    private final String VALID_CONTAINER = "src/test/resources/testFiles/valid-containers/bdoc-tm-with-large-data-file.bdoc";

    @Before
    public void setUp() throws Exception {
        eIDASConfiguration.setValidationPolicy(EIDAS_CONF);
    }

    @Test
    public void eIDASConfigurationTest(){
        Container container = ContainerOpener.open(VALID_CONTAINER, eIDASConfiguration);
        ValidationResult result = container.validate();
        System.out.println("aaa: "+result.getReport());
        List<DigiDoc4JException> errors = result.getErrors();

    }

    @Test
    public void defaultConfigurationTest(){

        Container container = ContainerOpener.open(VALID_CONTAINER, defaultConfiguration);
        ValidationResult result = container.validate();
        System.out.println("aaa: "+result.getReport());
        List<DigiDoc4JException> errors = result.getErrors();

    }

}
