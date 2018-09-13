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

import org.digidoc4j.impl.ddoc.ConfigManagerInitializer;
import org.digidoc4j.test.TestAssert;
import org.junit.BeforeClass;
import org.junit.Test;

public class LibraryInteroperabilityTest extends AbstractTest {

  private static final ConfigManagerInitializer configManagerInitializer = new ConfigManagerInitializer();

  @BeforeClass
  public static void beforeClass() throws Exception {
    LibraryInteroperabilityTest.configManagerInitializer.initConfigManager(Configuration.of(Configuration.Mode.TEST));
  }

  @Test
  public void verifySignatureWithDigiDoc4j_BC_unsafe_integer_from_yaml() {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    configuration.loadConfiguration
        ("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_bs_allow_unsafe_integer.yaml");
    Container container = ContainerBuilder.aContainer().
        fromExistingFile("src/test/resources/prodFiles/valid-containers/InvestorToomas.bdoc").
        withConfiguration(configuration).
        build();
    TestAssert.assertContainerIsValid(container);
  }

  @Test
  public void verifySignatureWithDigiDoc4j_BC_unsafe_integer_by_default() {
    this.setGlobalMode(Configuration.Mode.PROD);
    Container container = ContainerBuilder.aContainer().
        fromExistingFile("src/test/resources/prodFiles/valid-containers/InvestorToomas.bdoc").
        withConfiguration(Configuration.of(Configuration.Mode.PROD)).build();
    TestAssert.assertContainerIsInvalid(container);
  }

  /*
   * RESTRICTED METHODS
   */

  private void createSignedNonEmptyContainer(String containerLocation) {
    Container container = ContainerBuilder.aContainer().withConfiguration(Configuration.of(Configuration.Mode.TEST)).
        withDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain").build();
    this.createSignatureBy(container, SignatureProfile.LT_TM, this.pkcs12SignatureToken);
    this.createSignatureBy(container, SignatureProfile.LT_TM, this.pkcs12SignatureToken);
    container.saveAsFile(containerLocation);
  }

}
