/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.pades;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.main.DigiDoc4J;
import org.digidoc4j.test.TestAssert;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.ExpectedSystemExit;
import org.junit.contrib.java.lang.system.SystemOutRule;

/**
 * Created by Andrei on 20.11.2017.
 */
public class PadesValidationTest extends AbstractTest {

  @Rule
  public final ExpectedSystemExit systemExit = ExpectedSystemExit.none();

  @Rule
  public final SystemOutRule stdOut = new SystemOutRule().enableLog();

  @Test(expected = DigiDoc4JException.class)
  public void invalidPDFProvided_shouldThrowException() {
    Container container = new PadesContainer(this.configuration, "src/test/resources/prodFiles/valid-containers/valid_prod_bdoc_eid.bdoc");
    SignatureValidationResult result = container.validate();
  }

  @Test
  public void validPadesLT_shouldSucceed() {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.PADES).withConfiguration(Configuration.of(Configuration.Mode.PROD)).
            fromExistingFile("src/test/resources/prodFiles/valid-containers/hellopades-pades-lt-sha256-sign.pdf").build();
    SignatureValidationResult result = container.validate();
    Assert.assertTrue(result.isValid());
  }

  @Test
  public void PadesT_shouldFail() {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.PADES).withConfiguration(Configuration.of(Configuration.Mode.PROD)).
            fromExistingFile("src/test/resources/prodFiles/invalid-containers/PadesProfileT.pdf").build();
    SignatureValidationResult result = container.validate();
    Assert.assertFalse(result.isValid());
    TestAssert.assertContainsErrors(result.getErrors(),
            "The certificate validation is not conclusive!",
            "No revocation data found for the certificate!"
    );
  }

  @Test
  public void PadesLTAndPadesB_shouldFail() {
    /*
    Given PDF contains two signatures from the same certificate : B and LT
    Only LT signature contains revocation aand somehow it gets included while validating B level signature
    */
    Container container = ContainerBuilder.aContainer(Container.DocumentType.PADES).withConfiguration(Configuration.of(Configuration.Mode.PROD)).
            fromExistingFile("src/test/resources/prodFiles/valid-containers/hellopades-lt-b.pdf").build();
    SignatureValidationResult result = container.validate();
    Assert.assertFalse(result.isValid());
    TestAssert.assertContainsErrors(result.getErrors(),
            "The certificate validation is not conclusive!",
            "The current time is not in the validity range of the signer's certificate!",
            "The best-signature-time is not before the expiration date of the signing certificate!",
            "The past signature validation is not conclusive!",
            "The certificate is not related to a qualified certificate issuing trust service with valid status!"
    );
  }

  @Test
  public void padesLTWithCRL_shouldFail() {
    /**
     * @see org.digidoc4j.impl.asic.xades.validation.TimestampSignatureValidator#addRevocationErrors() for Xades
     */
    Container container = ContainerBuilder.aContainer(Container.DocumentType.PADES).withConfiguration(Configuration.of(Configuration.Mode.PROD)).
            fromExistingFile("src/test/resources/prodFiles/invalid-containers/PadesProfileLtWithCrl.pdf").build();
    SignatureValidationResult result = container.validate();
    Assert.assertFalse(result.isValid());
    TestAssert.assertContainsError("Signing certificate revocation source is not trusted", result.getErrors());
  }

  @Test
  public void verboseMode() throws Exception {
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