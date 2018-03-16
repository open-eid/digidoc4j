package org.digidoc4j.impl.pades;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.main.DigiDoc4J;
import org.digidoc4j.test.TestAssert;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.ExpectedSystemExit;
import org.junit.contrib.java.lang.system.SystemOutRule;

import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;

/**
 * Created by Andrei on 20.11.2017.
 */

public class PadesValidationTest extends AbstractTest {

  @Rule
  public final ExpectedSystemExit systemExit = ExpectedSystemExit.none();

  @Rule
  public final SystemOutRule stdOut = new SystemOutRule().enableLog();

  @Test
  public void padesValidationTestTwoSignature() {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.PADES).withConfiguration(this.configuration).
        fromExistingFile("src/test/resources/testFiles/invalid-containers/hello_signed_INCSAVE_signed_EDITED.pdf").build();
    SignatureValidationResult result = container.validate();
    Assert.assertFalse(result.isValid());
    Assert.assertEquals(4, result.getErrors().size());
    TestAssert.assertContainsError("The certificate chain for signature is not trusted, there is no trusted anchor.", result.getErrors());
    TestAssert.assertContainsError("The certificate path is not trusted!", result.getErrors());
    TestAssert.assertContainsError("The reference data object(s) is not intact!", result.getErrors());
  }

  @Test
  public void padesValidationTestOneSignature() {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.PADES).
        withConfiguration(this.configuration).fromExistingFile("src/test/resources/testFiles/invalid-containers/EE_AS-P-BpLT-V-009.pdf").
        build();
    SignatureValidationResult result = container.validate();
    Assert.assertFalse(result.isValid());
    Assert.assertEquals(3, result.getErrors().size());
    Assert.assertEquals(3, result.getWarnings().size());
    TestAssert.assertContainsError("The certificate chain for signature is not trusted, there is no trusted anchor.", result.getErrors());
    TestAssert.assertContainsError("The certificate path is not trusted!", result.getErrors());
    TestAssert.assertContainsError("The certificate chain for timestamp is not trusted, there is no trusted anchor.", result.getWarnings());
    TestAssert.assertContainsError("The signature/seal is an INDETERMINATE AdES!", result.getWarnings());
    TestAssert.assertContainsError("Authority info access is not present!", result.getWarnings());
    Assert.assertEquals(Indication.INDETERMINATE, result.getIndication("id-6bff661b4349d8cf539d00127c163bdb780e552845d04b66868301a5cf0ed8ba"));
    Assert.assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, result.getSubIndication("id-6bff661b4349d8cf539d00127c163bdb780e552845d04b66868301a5cf0ed8ba"));
  }

  @Test
  public void verboseMode() throws Exception {
    this.setGlobalMode(Configuration.Mode.TEST);
    this.systemExit.expectSystemExitWithStatus(1);
    DigiDoc4J.main(new String[]{"-in", "src/test/resources/testFiles/invalid-containers/hello_signed_INCSAVE_signed_EDITED.pdf", "-verify"});
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.configuration = new Configuration(Configuration.Mode.TEST);
  }

}