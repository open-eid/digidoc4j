/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.digidoc4j.exceptions.ContainerWithoutSignaturesException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.InvalidTimestampException;
import org.digidoc4j.exceptions.TimestampAfterOCSPResponseTimeException;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.junit.Test;

import ch.qos.logback.classic.pattern.LineSeparatorConverter;

public class ValidationTests extends DigiDoc4JTestHelper {

  @Test
  public void asicValidationShouldFail_ifTimeStampHashDoesntMatchSignature() throws Exception {
    ValidationResult result = validateContainer("testFiles/TS-02_23634_TS_wrong_SignatureValue.asice");
    assertFalse(result.isValid());
    assertEquals(InvalidTimestampException.MESSAGE, result.getErrors().get(0).getMessage());
  }

  @Test(expected = ContainerWithoutSignaturesException.class)
  public void asicContainerWithoutSignatures_isNotValid() throws Exception {
    ValidationResult result = validateContainer("testFiles/asics_without_signatures.bdoc");
    assertFalse(result.isValid());
  }

  @Test
  public void asicOcspTimeShouldBeAfterTimestamp() throws Exception {
    ValidationResult result = validateContainer("testFiles/TS-08_23634_TS_OCSP_before_TS.asice");
    assertFalse(result.isValid());
    assertTrue(result.getErrors().size() >= 1);
    List<String> errorMessages = new ArrayList<>();
    for (DigiDoc4JException error : result.getErrors()) {
      errorMessages.add(error.getMessage());
    }
    assertTrue(errorMessages.contains(TimestampAfterOCSPResponseTimeException.MESSAGE));
  }

  private ValidationResult validateContainer(String containerPath) {
    Container container = ContainerBuilder.
        aContainer("BDOC").
        fromExistingFile(containerPath).
        build();
    return container.validate();
  }




}
