package org.digidoc4j;

import java.util.List;

import org.digidoc4j.exceptions.DigiDoc4JException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class TLWellSignedParameterTest {

    private Configuration eIDASConfiguration = new Configuration(Configuration.Mode.TEST);
    private Configuration defaultConfiguration = new Configuration(Configuration.Mode.TEST);

    private final String EIDAS_CONF = "src/test/resources/testFiles/constraints/eIDAS_test_constraint.xml";
    private final String VALID_CONTAINER = "src/test/resources/testFiles/valid-containers/bdoc-tm-with-large-data-file.bdoc";

    @Before
    public void setUp() throws Exception {
        eIDASConfiguration.setValidationPolicy(EIDAS_CONF);
    }

    @Test
    public void eIDASConfigurationTest(){
        Container container = ContainerOpener.open(VALID_CONTAINER, eIDASConfiguration);
        ValidationResult result = container.validate();
        List<DigiDoc4JException> errors = result.getErrors();
        List<DigiDoc4JException> warnings = result.getWarnings();
        Assert.assertFalse(result.isValid());
        Assert.assertTrue(errors.size() == 2);
        Assert.assertTrue(warnings.size() == 0);
        Assert.assertTrue(result.getReport().contains("The trusted list is not acceptable"));
        Assert.assertTrue(result.getReport().contains("The trusted list has not the expected version"));
    }

    @Test
    public void defaultConfigurationTest(){
        Container container = ContainerOpener.open(VALID_CONTAINER, defaultConfiguration);
        ValidationResult result = container.validate();
        List<DigiDoc4JException> errors = result.getErrors();
        Assert.assertTrue(errors.size() == 0);
        Assert.assertTrue(result.isValid());
    }

}
