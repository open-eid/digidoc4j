/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.edoc;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.exceptions.TimestampAfterOCSPResponseTimeException;
import org.digidoc4j.test.TestAssert;
import org.junit.jupiter.api.Test;

import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Created by kamlatm on 4.05.2017.
 */

class TimeStampValidationForEDocTest extends AbstractTest {

  private static final String EDOC_LOCATION = "src/test/resources/testFiles/invalid-containers/latvian_signed_container.edoc";
  private static final String ASICE_LOCATION = "src/test/resources/testFiles/valid-containers/latvian_signed_container.asice";

  @Test
  void timestampAfterOcspResponseTimeShouldResultInInvalidContainerForEDOC() {
    ContainerValidationResult validationResult = openContainerByConfiguration(Paths.get(EDOC_LOCATION)).validate();
    assertFalse(validationResult.isValid(), "Signature should be invalid if timestamp was taken after OCSP");
    TestAssert.assertContainsExactSetOfErrors(validationResult.getErrors(),
            "Timestamp time is after OCSP response production time",
            "The certificate is not related to a TSA/QTST!",
            "The certificate is not related to a qualified certificate issuing trust service with valid status!",
            "The trust service(s) related to the time-stamp does not have the expected type identifier!",
            "Signature has an invalid timestamp",
            "The best-signature-time is not before the expiration date of the signing certificate!",
            "No long term availability and integrity of validation material is present!",
            "The current time is not in the validity range of the signer's certificate!",
            "The certificate validation is not conclusive!"
    );
    assertTrue(validationResult.getErrors().stream().anyMatch(e -> e instanceof TimestampAfterOCSPResponseTimeException),
            "Validation result should contain " + TimestampAfterOCSPResponseTimeException.class.getSimpleName());
  }

  @Test
  void invalidTimestampMsgIsNotExistForASICE() {
    ContainerValidationResult validationResult = openContainerByConfiguration(Paths.get(ASICE_LOCATION)).validate();
    TestAssert.assertContainsExactSetOfErrors(validationResult.getErrors(),
            "The certificate is not related to a TSA/QTST!",
            "The trust service(s) related to the time-stamp does not have the expected type identifier!",
            "Signature has an invalid timestamp",
            "The best-signature-time is not before the expiration date of the signing certificate!",
            "No long term availability and integrity of validation material is present!",
            "The current time is not in the validity range of the signer's certificate!",
            "The certificate validation is not conclusive!"
    );
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    configuration = new Configuration(Configuration.Mode.PROD);
  }

}
