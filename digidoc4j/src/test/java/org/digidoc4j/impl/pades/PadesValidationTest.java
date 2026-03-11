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
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.test.TestAssert;
import org.junit.Rule;
import org.junit.contrib.java.lang.system.SystemOutRule;
import org.junit.jupiter.api.Test;

import static org.digidoc4j.main.TestDigiDoc4JUtil.invokeDigiDoc4jAndReturnExitStatus;
import static org.digidoc4j.test.TestAssert.assertContainerIsInvalid;
import static org.digidoc4j.test.TestAssert.assertContainerIsValid;
import static org.digidoc4j.test.TestAssert.assertContainsErrors;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Created by Andrei on 20.11.2017.
 */
public class PadesValidationTest extends AbstractTest {

  @Rule
  public final SystemOutRule stdOut = new SystemOutRule().enableLog();

  @Test
  public void invalidPDFProvided_shouldThrowException() {
    Container container = new PadesContainer(configuration, "src/test/resources/prodFiles/valid-containers/valid_prod_bdoc_eid.bdoc");

    assertThrows(DigiDoc4JException.class, container::validate);
  }

  @Test
  public void validPadesLT_shouldSucceed() {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.PADES).withConfiguration(Configuration.of(Configuration.Mode.PROD)).
            fromExistingFile("src/test/resources/prodFiles/valid-containers/hellopades-pades-lt-sha256-sign.pdf").build();
    ContainerValidationResult result = container.validate();
    assertContainerIsValid(result);
  }

  @Test
  public void PadesT_shouldFail() {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.PADES).withConfiguration(Configuration.of(Configuration.Mode.PROD)).
            fromExistingFile("src/test/resources/prodFiles/invalid-containers/PadesProfileT.pdf").build();
    ContainerValidationResult result = container.validate();
    assertContainerIsInvalid(result);
    assertContainsErrors(result.getErrors(),
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
    ContainerValidationResult result = container.validate();
    assertContainerIsInvalid(result);
    TestAssert.assertContainsExactSetOfErrors(result.getErrors(),
            "The certificate validation is not conclusive!",
            "The current time is not in the validity range of the signer's certificate!",
            "The best-signature-time is not before the expiration date of the signing certificate!",
            "No long term availability and integrity of validation material is present!",
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
    ContainerValidationResult result = container.validate();
    assertContainerIsInvalid(result);
    TestAssert.assertContainsError("Signing certificate revocation source is not trusted", result.getErrors());
  }

  @Test
  public void verboseMode() throws Exception {
    int result = invokeDigiDoc4jAndReturnExitStatus(
            "-in", "src/test/resources/testFiles/invalid-containers/hello_signed_INCSAVE_signed_EDITED.pdf",
            "-verify"
    );
    assertEquals(1, result);
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    configuration = new Configuration(Configuration.Mode.TEST);
  }

}
