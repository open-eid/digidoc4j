package org.digidoc4j.impl.ddoc;

import org.digidoc4j.*;
import org.digidoc4j.test.TestAssert;
import org.junit.Assert;
import org.junit.Test;

public class ValidationTests extends AbstractTest {

  @Test
  public void setInvalidOcspResponder() {
    this.configuration.setAllowedOcspRespondersForTM("INVALID OCSP RESPONDER");
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
    Container container = ContainerOpener
            .open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    SignatureValidationResult result = container.validate();
    TestAssert.assertContainsError("OCSP Responder does not meet TM requirements", result.getErrors());
  }

  @Test
  public void defaultOcspResponderSuccessful(){
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
    Container container = ContainerOpener
            .open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    SignatureValidationResult result = container.validate();
    Assert.assertTrue("Result is not valid", result.isValid());
  }

  @Test
  public void setInvalidOcspResponderConfigurationYamlParameter() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_invalid_ocsp_responders.yaml");
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
    Container container = ContainerOpener
            .open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    SignatureValidationResult result = container.validate();
    TestAssert.assertContainsError("OCSP Responder does not meet TM requirements", result.getErrors());
  }

  @Test
  public void testValidateDDoc10Hashcode() {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    this.configuration.getDDoc4JConfiguration().put("DATAFILE_HASHCODE_MODE", "true");
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
    Container container = ContainerOpener
             .open("src/test/resources/prodFiles/valid-containers/SK-XML1_0_hashcode.ddoc");
    SignatureValidationResult result = container.validate();
    Assert.assertTrue(result.isValid());
    Assert.assertTrue(result.hasWarnings());
    Assert.assertEquals(177, result.getWarnings().get(0).getErrorCode());
    Assert.assertTrue(result.getReport().contains("Old and unsupported format:"));
  }


    /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
  }
}
