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
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.test.TestAssert;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ContainerOpenerTest extends AbstractTest {

  @Test
  void openBDocContainer() {
    Container container = ContainerOpener.open(BDOC_WITH_TM_SIG, configuration);
    assertBDocContainer(container);
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.BDOC);
  }

  @Test
  void openAsicEContainer() {
    Container container = ContainerOpener.open(ASICE_WITH_TS_SIG, configuration);
    assertAsicEContainer(container);
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.ASICE);
  }

  @Test
  void openAsicSContainer() {
    Container container = ContainerOpener.open(ASICS_WITH_TS, configuration);
    assertAsicSContainer(container);
    assertTrue(container.getSignatures().isEmpty());
  }

  @Test
  void openDDocContainer() {
    Container container = ContainerOpener.open(DDOC_TEST_FILE, configuration);
    assertDDocContainer(container);
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.DDOC);
  }

  @Test
  void openAsicContainerWithNoSignatures_alwaysReturnsAsicEContainer() {
    Container container = ContainerOpener.open(ASIC_WITH_NO_SIG, configuration);
    assertAsicEContainer(container);
    assertTrue(container.getSignatures().isEmpty());
  }

  @Test
  void openBDocContainerAsStream() throws Exception {
    FileInputStream stream = FileUtils.openInputStream(new File(BDOC_WITH_TM_SIG));
    Container container = ContainerOpener.open(stream, configuration);
    assertBDocContainer(container);
    assertSame(1, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.BDOC);
  }

  @Test
  void openBDocContainerWithTMAndTSSignaturesAsStream() throws Exception {
    FileInputStream stream = FileUtils.openInputStream(new File(BDOC_WITH_TM_AND_TS_SIG));
    Container container = ContainerOpener.open(stream, configuration);
    assertBDocContainer(container);
    assertSame(2, container.getSignatures().size());
    assertTimemarkSignature(container.getSignatures().get(0));
    assertLtSignature(container.getSignatures().get(1));
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.BDOC);
  }

  @Test
  void openBDocContainerWithBEpesSignaturesAsStream() throws Exception {
    FileInputStream stream = FileUtils.openInputStream(new File(BDOC_WITH_B_EPES_SIG));
    Container container = ContainerOpener.open(stream, configuration);
    assertBDocContainer(container);
    assertSame(1, container.getSignatures().size());
    assertBEpesSignature(container.getSignatures().get(0));
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.BDOC);
  }

  @Test
  void openAsicEContainerAsStream() throws Exception {
    FileInputStream stream = FileUtils.openInputStream(new File(ASICE_WITH_TS_SIG));
    Container container = ContainerOpener.open(stream, configuration);
    assertAsicEContainer(container);
    assertSame(1, container.getSignatures().size());
    assertLtSignature(container.getSignatures().get(0));
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.ASICE);
  }

  @Test
  void openDDocContainerAsStream() throws Exception {
    FileInputStream stream = FileUtils.openInputStream(new File(DDOC_TEST_FILE));
    Container container = ContainerOpener.open(stream, configuration);
    assertDDocContainer(container);
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.DDOC);
  }

  @Test
  void openAsicContainerWithNoSignaturesAsStream_alwaysReturnsAsicEContainer() throws IOException {
    FileInputStream stream = FileUtils.openInputStream(new File(ASIC_WITH_NO_SIG));
    Container container = ContainerOpener.open(stream, configuration);
    assertAsicEContainer(container);
    assertTrue(container.getSignatures().isEmpty());
  }

  @Test
  void openBDocContainerAsStream_WithBigFilesNotSupported() throws Exception {
    FileInputStream stream = FileUtils.openInputStream(new File(BDOC_WITH_TM_SIG));
    Container container = ContainerOpener.open(stream, false);
    assertBDocContainer(container);
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.BDOC);
  }

  @Test
  void testErrorTextDDOCInvalidFileFormat() {
    try {
      ContainerBuilder.aContainer().fromExistingFile("src/test/resources/testFiles/invalid-containers/error75.ddoc").build();

    } catch (DigiDoc4JException e) {
      assertTrue(e.getMessage().contains("Invalid input file format."));
    }
  }

  @Test
  void testErrorText75NotChanged() {
    try {
      ContainerBuilder.aContainer()
          .fromExistingFile("src/test/resources/testFiles/invalid-containers/23181_SignedInfo_topelt_D1_lisatud.ddoc").
          build();

    } catch (DigiDoc4JException e) {
      assertTrue(e.getMessage().contains("Multiple elements: SignatureValue not allowed under: Signature"));
    }
  }

  @Test
  void testErrorText75AndInvalidPath() {
    try {
      ContainerBuilder.aContainer().fromExistingFile("src/test/resources/testFiles/invalid-containers/23033_D1_lisatud.ddoc").
              build();
    } catch (DigiDoc4JException e) {
      assertTrue(e.getMessage().contains("ERROR: 75 - Invalid path"));
    }
  }

  @Test
  @Disabled("TODO: solve anomaly where results are different")
  void testErrorText75NotChangedInvalidXmlElement() {
    try {
      ContainerBuilder.aContainer().fromExistingFile("src/test/resources/testFiles/invalid-containers/BOF.ddoc").build();
    } catch (DigiDoc4JException e) {
      assertTrue(e.getMessage().contains("Invalid xml element"));
    }
  }

  @Test
  void testSignatureXMLContainsTrailingContent() {
    ContainerOpener.open("src/test/resources/testFiles/valid-containers/signature_xml_contains_trailing_content.bdoc");
  }

  @Test
  void containerOpener_fileWithZipBomb() {
    TechnicalException exception = assertThrows(
            TechnicalException.class,
            () -> ContainerOpener.open("src/test/resources/testFiles/invalid-containers/zip-bomb-package-zip-1gb.bdoc")
    );

    assertThat(exception.getMessage(), equalTo("Zip Bomb detected in the ZIP container. Validation is interrupted."));
  }

  @Test
  void containerOpener_fileWithZipBomb_fileCachedInMemory() {
    configuration.setMaxFileSizeCachedInMemoryInMB(1);

    TechnicalException exception = assertThrows(
            TechnicalException.class,
            () -> ContainerOpener.open("src/test/resources/testFiles/invalid-containers/zip-bomb-package-zip-1gb.bdoc")
    );

    assertThat(exception.getMessage(), equalTo("Zip Bomb detected in the ZIP container. Validation is interrupted."));
  }

  @Test
  void containerOpener_streamWithZipBomb() {
    TechnicalException exception = assertThrows(
            TechnicalException.class,
            () -> ContainerOpener.open(new FileInputStream("src/test/resources/testFiles/invalid-containers/zip-bomb-package-zip-1gb.bdoc"), configuration)
    );

    assertThat(exception.getMessage(), equalTo("Zip Bomb detected in the ZIP container. Validation is interrupted."));
  }

  @Test
  void containerOpener_streamWithZipBomb_fileCachedInMemory() {
    configuration.setMaxFileSizeCachedInMemoryInMB(1);

    TechnicalException exception = assertThrows(
            TechnicalException.class,
            () -> ContainerOpener.open(new FileInputStream("src/test/resources/testFiles/invalid-containers/zip-bomb-package-zip-1gb.bdoc"), configuration)
    );

    assertThat(exception.getMessage(), equalTo("Zip Bomb detected in the ZIP container. Validation is interrupted."));
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    configuration = new Configuration(Configuration.Mode.TEST);
  }

}
