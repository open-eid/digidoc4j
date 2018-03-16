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

import java.io.File;
import java.io.FileInputStream;

import org.apache.commons.io.FileUtils;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.test.TestAssert;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

public class ContainerOpenerTest extends AbstractTest {

  private static final String BDOC_TEST_FILE = "src/test/resources/testFiles/valid-containers/one_signature.bdoc";
  private static final String DDOC_TEST_FILE = "src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc";

  @Test
  public void openBDocContainer() throws Exception {
    Container container = ContainerOpener.open(BDOC_TEST_FILE, this.configuration);
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.BDOC);
  }

  @Test
  public void openDDocContainer() throws Exception {
    Container container = ContainerOpener.open(DDOC_TEST_FILE, this.configuration);
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.DDOC);
  }

  @Test
  public void openBDocContainerAsStream() throws Exception {
    FileInputStream stream = FileUtils.openInputStream(new File(BDOC_TEST_FILE));
    Container container = ContainerOpener.open(stream, this.configuration);
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.ASICE);
  }

  @Test
  public void openDDocContainerAsStream() throws Exception {
    FileInputStream stream = FileUtils.openInputStream(new File(DDOC_TEST_FILE));
    Container container = ContainerOpener.open(stream, this.configuration);
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.DDOC);
  }

  @Test
  public void openBDocContainerAsStream_WithBigFilesNotSupported() throws Exception {
    FileInputStream stream = FileUtils.openInputStream(new File(BDOC_TEST_FILE));
    Container container = ContainerOpener.open(stream, false);
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.ASICE);
  }

  @Test
  public void testErrorTextDDOCInvalidFileFormat() {
    try {
      ContainerBuilder.aContainer().fromExistingFile("src/test/resources/testFiles/invalid-containers/error75.ddoc").build();

    } catch (DigiDoc4JException e) {
      Assert.assertTrue(e.getMessage().contains("Invalid input file format."));
    }
  }

  @Test
  public void testErrorText75NotChanged() {
    try {
      ContainerBuilder.aContainer()
          .fromExistingFile("src/test/resources/testFiles/invalid-containers/23181_SignedInfo_topelt_D1_lisatud.ddoc").
          build();

    } catch (DigiDoc4JException e) {
      Assert.assertTrue(e.getMessage().contains("Multiple elements: SignatureValue not allowed under: Signature"));
    }
  }

  @Test
  public void testErrorText75ChangedAndNullPointer() {
    try {
      ContainerBuilder.aContainer().fromExistingFile("src/test/resources/testFiles/invalid-containers/23133_ddoc-12.ddoc").
          build();
    } catch (DigiDoc4JException e) {
      Assert.assertTrue(e.getMessage().contains("Invalid input file format."));
    }
  }

  @Test
  @Ignore("TODO: solve anomaly where results are different")
  public void testErrorText75NotChangedInvalidXmlElement() {
    try {
      ContainerBuilder.aContainer().fromExistingFile("src/test/resources/testFiles/invalid-containers/BOF.ddoc").build();
    } catch (DigiDoc4JException e) {
      Assert.assertTrue(e.getMessage().contains("Invalid xml element"));
    }
  }

  @Test
  public void testSignatureXMLContainsTrailingContent() {
    ContainerOpener.open("src/test/resources/testFiles/valid-containers/signature_xml_contains_trailing_content.bdoc");
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.configuration = new Configuration(Configuration.Mode.TEST);
  }

}