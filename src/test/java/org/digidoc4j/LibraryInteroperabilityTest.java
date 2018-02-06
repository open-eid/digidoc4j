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

import java.io.FileInputStream;
import java.nio.file.Paths;

import org.digidoc4j.impl.ddoc.ConfigManagerInitializer;
import org.digidoc4j.test.TestAssert;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.digidoc4j.test.util.TestFileUtil;
import org.junit.BeforeClass;
import org.junit.Test;

public class LibraryInteroperabilityTest extends AbstractTest {

  private static final ConfigManagerInitializer configManagerInitializer = new ConfigManagerInitializer();

  @BeforeClass
  public static void beforeClass() throws Exception {
    LibraryInteroperabilityTest.configManagerInitializer.initConfigManager(Configuration.of(Configuration.Mode.TEST));
  }

  @Test
  public void verifyWithJDigidoc() throws Exception {
    String file = this.getFileBy("bdoc");
    createSignedNonEmptyContainer(file);
    TestAssert.assertContainerIsValidWithJDigiDoc(file);
  }

  @Test
  public void verifyLibdigidocTS_SignatureWithDigiDoc4j() {
    this.setGlobalMode(Configuration.Mode.PROD);
    Container container = ContainerBuilder.aContainer().
        fromExistingFile("src/test/resources/testFiles/invalid-containers/Libdigidoc_created_tsa_signature_TS.bdoc").
        withConfiguration(Configuration.of(Configuration.Mode.PROD)).build();
    TestAssert.assertContainerIsValid(container);
  }

  @Test
  public void verifyAddingSignatureToJDigiDocContainer() throws Exception {
    Container container = ContainerBuilder.aContainer().
        fromExistingFile("src/test/resources/testFiles/valid-containers/DigiDocService_spec_est.pdf-TM-j.bdoc").
        withConfiguration(Configuration.of(Configuration.Mode.TEST)).build();
    TestDataBuilderUtil.signContainer(container);
    TestAssert.assertContainerIsValid(container);
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    container = TestDataBuilderUtil.open(file);
    TestAssert.assertContainerIsValid(container);
    TestAssert.assertContainerIsValidWithJDigiDoc(file);
  }

  @Test
  public void verifyAddingMobileIdSignature_extractedByjDigidoc_shouldBeValid() throws Exception {
    Container container = ContainerBuilder.aContainer().withConfiguration(Configuration.of(Configuration.Mode.PROD)).
        withDataFile(new FileInputStream("src/test/resources/testFiles/special-char-files/pdf-containing-xml.pdf"), "Sularaha sissemakse.pdf", "application/octet-stream").
        build();
    container.addSignature(TestFileUtil.openAdESSignature(container, "src/test/resources/testFiles/xades/bdoc-tm-jdigidoc-mobile-id.xml"));
    TestAssert.assertContainerIsValid(container);
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    TestAssert.assertContainerIsValidWithJDigiDoc(file);
  }

  @Test
  public void extendEpesToLtTm_validateWithJdigidoc() throws Exception {
    Container container = this.createNonEmptyContainer();
    TestDataBuilderUtil.signContainer(container, SignatureProfile.B_EPES);
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    container = this.openContainerBy(Paths.get(file));
    container.extendSignatureProfile(SignatureProfile.LT_TM);
    file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    TestAssert.assertContainerIsValidWithJDigiDoc(file);
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
