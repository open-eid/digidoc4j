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

import static org.junit.Assert.assertFalse;

import org.digidoc4j.exceptions.ContainerWithoutSignaturesException;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.junit.Test;

public class ValidationTests extends DigiDoc4JTestHelper {

  @Test
  public void asicValidationShouldFail_ifTimeStampHashDoesntMatchSignature() throws Exception {
    ValidationResult result = validateContainer("testFiles/TS-02_23634_TS_wrong_SignatureValue.asice");
    assertFalse(result.isValid());
  }

  @Test(expected = ContainerWithoutSignaturesException.class)
  public void asicContainerWithoutSignatures_isNotValid() throws Exception {
    ValidationResult result = validateContainer("testFiles/asics_without_signatures.bdoc");
    assertFalse(result.isValid());
  }

  private ValidationResult validateContainer(String containerPath) {
    Container container = ContainerBuilder.
        aContainer("BDOC").
        fromExistingFile(containerPath).
        build();
    return container.validate();
  }




}
