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

import org.apache.commons.io.FileUtils;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.test.TestAssert;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class ContainerOpenerTest extends AbstractTest {

  @Test
  public void openBDocContainer() throws Exception {
    Container container = ContainerOpener.open(BDOC_WITH_TM_SIG, this.configuration);
    assertBDocContainer(container);
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.BDOC);
  }

  @Test
  public void openAsicEContainer() {
    Container container = ContainerOpener.open(ASICE_WITH_TS_SIG, this.configuration);
    assertAsicEContainer(container);
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.ASICE);
  }

  @Test
  public void openAsicSContainer() {
    Container container = ContainerOpener.open(ASICS_WITH_TS, this.configuration);
    assertAsicSContainer(container);
    Assert.assertTrue(container.getSignatures().isEmpty());
  }

  @Test
  public void openDDocContainer() throws Exception {
    Container container = ContainerOpener.open(DDOC_TEST_FILE, this.configuration);
    assertDDocContainer(container);
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.DDOC);
  }

  @Test
  public void openAsicContainerWithNoSignatures_alwaysReturnsAsicEContainer() {
    Container container = ContainerOpener.open(ASIC_WITH_NO_SIG, this.configuration);
    assertAsicEContainer(container);
    Assert.assertTrue(container.getSignatures().isEmpty());
  }

  @Test
  public void openBDocContainerAsStream() throws Exception {
    FileInputStream stream = FileUtils.openInputStream(new File(BDOC_WITH_TM_SIG));
    Container container = ContainerOpener.open(stream, this.configuration);
    assertBDocContainer(container);
    Assert.assertSame(1, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.BDOC);
  }

  @Test
  public void openBDocContainerWithTMAndTSSignaturesAsStream() throws Exception {
    FileInputStream stream = FileUtils.openInputStream(new File(BDOC_WITH_TM_AND_TS_SIG));
    Container container = ContainerOpener.open(stream, this.configuration);
    assertBDocContainer(container);
    Assert.assertSame(2, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));
    assertTimestampSignature(container.getSignatures().get(1));
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.BDOC);
  }

  @Test
  public void openBDocContainerWithBEpesSignaturesAsStream() throws Exception {
    FileInputStream stream = FileUtils.openInputStream(new File(BDOC_WITH_B_EPES_SIG));
    Container container = ContainerOpener.open(stream, this.configuration);
    assertBDocContainer(container);
    Assert.assertSame(1, container.getSignatures().size());
    assertBEpesSignature(container.getSignatures().get(0));
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.BDOC);
  }

  @Test
  public void openAsicEContainerAsStream() throws Exception {
    FileInputStream stream = FileUtils.openInputStream(new File(ASICE_WITH_TS_SIG));
    Container container = ContainerOpener.open(stream, this.configuration);
    assertAsicEContainer(container);
    Assert.assertSame(1, container.getSignatures().size());
    assertTimestampSignature(container.getSignatures().get(0));
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.ASICE);
  }

  @Test
  public void openDDocContainerAsStream() throws Exception {
    FileInputStream stream = FileUtils.openInputStream(new File(DDOC_TEST_FILE));
    Container container = ContainerOpener.open(stream, this.configuration);
    assertDDocContainer(container);
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.DDOC);
  }

  @Test
  public void openAsicContainerWithNoSignaturesAsStream_alwaysReturnsAsicEContainer() throws IOException {
    FileInputStream stream = FileUtils.openInputStream(new File(ASIC_WITH_NO_SIG));
    Container container = ContainerOpener.open(stream, this.configuration);
    assertAsicEContainer(container);
    Assert.assertTrue(container.getSignatures().isEmpty());
  }

  @Test
  public void openBDocContainerAsStream_WithBigFilesNotSupported() throws Exception {
    FileInputStream stream = FileUtils.openInputStream(new File(BDOC_WITH_TM_SIG));
    Container container = ContainerOpener.open(stream, false);
    assertBDocContainer(container);
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.BDOC);
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
  public void testErrorText75AndInvalidPath() {
    try {
      ContainerBuilder.aContainer().fromExistingFile("src/test/resources/testFiles/invalid-containers/23033_D1_lisatud.ddoc").
              build();
    } catch (DigiDoc4JException e) {
      Assert.assertTrue(e.getMessage().contains("ERROR: 75 - Invalid path"));
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