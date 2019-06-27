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

import org.digidoc4j.test.TestAssert;
import org.junit.Test;

public class LibraryInteroperabilityTest extends AbstractTest {

  @Test
  public void verifySignatureWithDigiDoc4j_BC_unsafe_integer_by_default() {
    Container container = ContainerBuilder.aContainer().
        fromExistingFile("src/test/resources/prodFiles/valid-containers/InvestorToomas.bdoc").
        withConfiguration(Configuration.of(Configuration.Mode.PROD)).build();
    TestAssert.assertContainerIsValid(container);
  }
}
