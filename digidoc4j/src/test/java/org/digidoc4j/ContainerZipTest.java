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

import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import org.digidoc4j.ddoc.Manifest;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.test.util.TestZipUtil;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class ContainerZipTest extends AbstractTest {

  @Test
  public void newBdocContainerSavedAsStreamShouldHaveStoredMimeTypeAsFirstEntry() throws Exception {
    Container container = createNonEmptyContainerBy(Container.DocumentType.BDOC);
    readAndAssertFirstEntryStoredMimeType(container.saveAsStream());
  }

  @Test
  public void newAsiceContainerSavedAsStreamShouldHaveStoredMimeTypeAsFirstEntry() throws Exception {
    Container container = createNonEmptyContainerBy(Container.DocumentType.ASICE);
    readAndAssertFirstEntryStoredMimeType(container.saveAsStream());
  }

  @Test
  public void newAsicsContainerSavedAsStreamShouldHaveStoredMimeTypeAsFirstEntry() throws Exception {
    Container container = createNonEmptyContainerBy(Container.DocumentType.ASICS);
    readAndAssertFirstEntryStoredMimeType(container.saveAsStream());
  }

  @Test
  public void newBdocContainerSavedAsFileShouldHaveStoredMimeTypeAsFirstEntry() throws Exception {
    File testFile = createTestContainerFile(createNonEmptyContainerBy(Container.DocumentType.BDOC), "new-unsigned-bdoc.bdoc");
    readAndAssertFirstEntryStoredMimeType(new FileInputStream(testFile));
  }

  @Test
  public void newAsiceContainerSavedAsFileShouldHaveStoredMimeTypeAsFirstEntry() throws Exception {
    File testFile = createTestContainerFile(createNonEmptyContainerBy(Container.DocumentType.ASICE), "new-unsigned-asice.asice");
    readAndAssertFirstEntryStoredMimeType(new FileInputStream(testFile));
  }

  @Test
  public void newAsicsContainerSavedAsFileShouldHaveStoredMimeTypeAsFirstEntry() throws Exception {
    File testFile = createTestContainerFile(createNonEmptyContainerBy(Container.DocumentType.ASICS), "new-unsigned-asics.asics");
    readAndAssertFirstEntryStoredMimeType(new FileInputStream(testFile));
  }

  @Test
  public void loadedBdocContainerSavedAsStreamShouldHaveStoredMimeTypeAsFirstEntry() throws Exception {
    Container container = ContainerOpener.open(createTestUnsignedBdocFile().getPath());
    readAndAssertFirstEntryStoredMimeType(container.saveAsStream());
  }

  @Test
  public void loadedAsiceContainerSavedAsStreamShouldHaveStoredMimeTypeAsFirstEntry() throws Exception {
    Container container = ContainerOpener.open(createTestUnsignedAsiceFile().getPath());
    readAndAssertFirstEntryStoredMimeType(container.saveAsStream());
  }

  @Test
  public void loadedAsicsContainerSavedAsStreamShouldHaveStoredMimeTypeAsFirstEntry() throws Exception {
    Container container = ContainerOpener.open(createTestUnsignedAsicsFile().getPath());
    readAndAssertFirstEntryStoredMimeType(container.saveAsStream());
  }

  @Test
  public void loadedBdocContainerSavedAsFileShouldHaveStoredMimeTypeAsFirstEntry() throws Exception {
    Container container = ContainerOpener.open(createTestUnsignedBdocFile().getPath());
    File testFile = createTestContainerFile(container, "loaded-unsigned-bdoc.bdoc");
    readAndAssertFirstEntryStoredMimeType(new FileInputStream(testFile));
  }

  @Test
  public void loadedAsiceContainerSavedAsFileShouldHaveStoredMimeTypeAsFirstEntry() throws Exception {
    Container container = ContainerOpener.open(createTestUnsignedAsiceFile().getPath());
    File testFile = createTestContainerFile(container, "loaded-unsigned-asice.asice");
    readAndAssertFirstEntryStoredMimeType(new FileInputStream(testFile));
  }

  @Test
  public void loadedAsicsContainerSavedAsFileShouldHaveStoredMimeTypeAsFirstEntry() throws Exception {
    Container container = ContainerOpener.open(createTestUnsignedAsicsFile().getPath());
    File testFile = createTestContainerFile(container, "loaded-unsigned-asics.asics");
    readAndAssertFirstEntryStoredMimeType(new FileInputStream(testFile));
  }

  @Test
  public void loadedBdocWithDeflatedMimeTypeSavedAsStreamShouldHaveStoredMimeTypeAsFirstEntry() throws Exception {
    Container container = ContainerOpener.open(createTestDeflatedMimeTypeBdocFile().getPath());
    readAndAssertFirstEntryStoredMimeType(container.saveAsStream());
  }

  @Test
  public void loadedAsiceWithDeflatedMimeTypeSavedAsStreamShouldHaveStoredMimeTypeAsFirstEntry() throws Exception {
    Container container = ContainerOpener.open(createTestDeflatedMimeTypeAsiceFile().getPath());
    readAndAssertFirstEntryStoredMimeType(container.saveAsStream());
  }

  @Test
  public void loadedAsicsWithDeflatedMimeTypeSavedAsStreamShouldHaveStoredMimeTypeAsFirstEntry() throws Exception {
    Container container = ContainerOpener.open(createTestDeflatedMimeTypeAsicsFile().getPath());
    readAndAssertFirstEntryStoredMimeType(container.saveAsStream());
  }

  @Test
  public void loadedBdocWithDeflatedMimeTypeSavedAsFileShouldHaveStoredMimeTypeAsFirstEntry() throws Exception {
    Container container = ContainerOpener.open(createTestDeflatedMimeTypeBdocFile().getPath());
    File testFile = createTestContainerFile(container, "loaded-unsigned-bdoc.bdoc");
    readAndAssertFirstEntryStoredMimeType(new FileInputStream(testFile));
  }

  @Test
  public void loadedAsiceWithDeflatedMimeTypeSavedAsFileShouldHaveStoredMimeTypeAsFirstEntry() throws Exception {
    Container container = ContainerOpener.open(createTestDeflatedMimeTypeAsiceFile().getPath());
    File testFile = createTestContainerFile(container, "loaded-unsigned-asice.asice");
    readAndAssertFirstEntryStoredMimeType(new FileInputStream(testFile));
  }

  @Test
  public void loadedAsicsWithDeflatedMimeTypeSavedAsFileShouldHaveStoredMimeTypeAsFirstEntry() throws Exception {
    Container container = ContainerOpener.open(createTestDeflatedMimeTypeAsicsFile().getPath());
    File testFile = createTestContainerFile(container, "loaded-unsigned-asics.asics");
    readAndAssertFirstEntryStoredMimeType(new FileInputStream(testFile));
  }

  @Test
  public void loadedBdocWithNonFirstMimeTypeSavedAsStreamShouldHaveStoredMimeTypeAsFirstEntry() throws Exception {
    File testNonFirstMimeTypeBdocFile = testFolder.newFile("original-non-first-mimetype-bdoc.bdoc");
    saveDegenerateContainerWithNonFirstMimeType(testNonFirstMimeTypeBdocFile, Manifest.MANIFEST_BDOC_MIME_2_0);
    Container container = ContainerOpener.open(testNonFirstMimeTypeBdocFile.getPath());
    readAndAssertFirstEntryStoredMimeType(container.saveAsStream());
  }

  @Test
  public void loadedAsiceWithNonFirstMimeTypeSavedAsStreamShouldHaveStoredMimeTypeAsFirstEntry() throws Exception {
    File testNonFirstMimeTypeAsiceFile = testFolder.newFile("original-non-first-mimetype-asice.asice");
    saveDegenerateContainerWithNonFirstMimeType(testNonFirstMimeTypeAsiceFile, MimeTypeEnum.ASICE.getMimeTypeString());
    Container container = ContainerOpener.open(testNonFirstMimeTypeAsiceFile.getPath());
    readAndAssertFirstEntryStoredMimeType(container.saveAsStream());
  }

  @Test
  public void loadedAsicsWithNonFirstMimeTypeSavedAsStreamShouldHaveStoredMimeTypeAsFirstEntry() throws Exception {
    File testNonFirstMimeTypeAsicsFile = testFolder.newFile("original-non-first-mimetype-asics.asics");
    saveDegenerateContainerWithNonFirstMimeType(testNonFirstMimeTypeAsicsFile, MimeTypeEnum.ASICS.getMimeTypeString());
    Container container = ContainerOpener.open(testNonFirstMimeTypeAsicsFile.getPath());
    readAndAssertFirstEntryStoredMimeType(container.saveAsStream());
  }

  @Test
  public void loadedBdocWithNonFirstMimeTypeSavedAsFileShouldHaveStoredMimeTypeAsFirstEntry() throws Exception {
    File testNonFirstMimeTypeBdocFile = testFolder.newFile("original-non-first-mimetype-bdoc.bdoc");
    saveDegenerateContainerWithNonFirstMimeType(testNonFirstMimeTypeBdocFile, Manifest.MANIFEST_BDOC_MIME_2_0);
    File testFile = createTestContainerFile(ContainerOpener.open(testNonFirstMimeTypeBdocFile.getPath()), "loaded-non-first-mimetype-bdoc.bdoc");
    readAndAssertFirstEntryStoredMimeType(new FileInputStream(testFile));
  }

  @Test
  public void loadedAsiceWithNonFirstMimeTypeSavedAsFileShouldHaveStoredMimeTypeAsFirstEntry() throws Exception {
    File testNonFirstMimeTypeAsiceFile = testFolder.newFile("original-non-first-mimetype-asice.asice");
    saveDegenerateContainerWithNonFirstMimeType(testNonFirstMimeTypeAsiceFile, MimeTypeEnum.ASICE.getMimeTypeString());
    File testFile = createTestContainerFile(ContainerOpener.open(testNonFirstMimeTypeAsiceFile.getPath()), "loaded-non-first-mimetype-asice.asice");
    readAndAssertFirstEntryStoredMimeType(new FileInputStream(testFile));
  }

  @Test
  public void loadedAsicsWithNonFirstMimeTypeSavedAsFileShouldHaveStoredMimeTypeAsFirstEntry() throws Exception {
    File testNonFirstMimeTypeAsicsFile = testFolder.newFile("original-non-first-mimetype-asics.asics");
    saveDegenerateContainerWithNonFirstMimeType(testNonFirstMimeTypeAsicsFile, MimeTypeEnum.ASICS.getMimeTypeString());
    File testFile = createTestContainerFile(ContainerOpener.open(testNonFirstMimeTypeAsicsFile.getPath()), "loaded-non-first-mimetype-asics.asics");
    readAndAssertFirstEntryStoredMimeType(new FileInputStream(testFile));
  }

  @Test
  public void loadingBdocWithTwoMimeTypesShouldFail() {
    expectedException.expect(DigiDoc4JException.class);
    expectedException.expectMessage("Multiple mimetype files disallowed");
    openContainerBy(Paths.get("src/test/resources/testFiles/degenerate-containers/2-mimetypes.bdoc"));
  }

  @Test
  public void loadingAsiceWithTwoMimeTypesShouldFail() {
    expectedException.expect(DigiDoc4JException.class);
    expectedException.expectMessage("Multiple mimetype files disallowed");
    openContainerBy(Paths.get("src/test/resources/testFiles/degenerate-containers/2-mimetypes.asice"));
  }

  @Test
  public void loadingAsicsWithTwoMimeTypesShouldFail() {
    expectedException.expect(DigiDoc4JException.class);
    expectedException.expectMessage("Multiple mimetype files disallowed");
    openContainerBy(Paths.get("src/test/resources/testFiles/degenerate-containers/2-mimetypes.asics"));
  }

  private File createTestUnsignedBdocFile() throws Exception {
    File testUnsignedBdocFile = testFolder.newFile("original-unsigned-bdoc.bdoc");
    createNonEmptyContainerBy(Container.DocumentType.BDOC).saveAsFile(testUnsignedBdocFile.getPath());
    return testUnsignedBdocFile;
  }

  private File createTestUnsignedAsiceFile() throws Exception {
    File testUnsignedAsiceFile = testFolder.newFile("original-unsigned-asice.asice");
    createNonEmptyContainerBy(Container.DocumentType.ASICE).saveAsFile(testUnsignedAsiceFile.getPath());
    return testUnsignedAsiceFile;
  }

  private File createTestUnsignedAsicsFile() throws Exception {
    File testUnsignedAsicsFile = testFolder.newFile("original-unsigned-asics.asics");
    createNonEmptyContainerBy(Container.DocumentType.ASICS).saveAsFile(testUnsignedAsicsFile.getPath());
    return testUnsignedAsicsFile;
  }

  private File createTestDeflatedMimeTypeBdocFile() throws Exception {
    File testDeflatedMimeTypeBdocFile = testFolder.newFile("original-deflated-mimetype-bdoc.bdoc");
    saveDegenerateContainerWithDeflatedMimeType(testDeflatedMimeTypeBdocFile, Manifest.MANIFEST_BDOC_MIME_2_0);
    return testDeflatedMimeTypeBdocFile;
  }

  private File createTestDeflatedMimeTypeAsiceFile() throws Exception {
    File testDeflatedMimeTypeAsiceFile = testFolder.newFile("original-deflated-mimetype-asice.asice");
    saveDegenerateContainerWithDeflatedMimeType(testDeflatedMimeTypeAsiceFile, MimeTypeEnum.ASICE.getMimeTypeString());
    return testDeflatedMimeTypeAsiceFile;
  }

  private File createTestDeflatedMimeTypeAsicsFile() throws Exception {
    File testDeflatedMimeTypeAsicsFile = testFolder.newFile("original-deflated-mimetype-asics.asics");
    saveDegenerateContainerWithDeflatedMimeType(testDeflatedMimeTypeAsicsFile, MimeTypeEnum.ASICS.getMimeTypeString());
    return testDeflatedMimeTypeAsicsFile;
  }

  private File createTestContainerFile(Container container, String fileName) throws Exception {
    File testFile = testFolder.newFile(fileName);
    container.saveAsFile(testFile.getPath());
    return testFile;
  }

  private static void saveDegenerateContainerWithDeflatedMimeType(File destinationFile, String mimeTypeContent) throws Exception {
    try (ZipOutputStream zipOutputStream = new ZipOutputStream(new FileOutputStream(destinationFile))) {
      TestZipUtil.writeEntries(zipOutputStream, TestZipUtil.createDeflatedEntry(
              ASiCUtils.MIME_TYPE, mimeTypeContent.getBytes(StandardCharsets.US_ASCII)
      ));
    }
  }

  private static void saveDegenerateContainerWithNonFirstMimeType(File destinationFile, String mimeTypeContent) throws Exception {
    try (ZipOutputStream zipOutputStream = new ZipOutputStream(new FileOutputStream(destinationFile))) {
      zipOutputStream.putNextEntry(new ZipEntry("Some-other-entry"));
      zipOutputStream.write("\tSome other entry content.\n".getBytes(StandardCharsets.UTF_8));
      zipOutputStream.closeEntry();

      writeValidMimeTypeTo(zipOutputStream, mimeTypeContent);
    }
  }

  private static void writeValidMimeTypeTo(ZipOutputStream zipOutputStream, String mimeTypeContent) {
    TestZipUtil.writeEntries(zipOutputStream, TestZipUtil.createStoredEntry(
            ASiCUtils.MIME_TYPE, mimeTypeContent.getBytes(StandardCharsets.US_ASCII)
    ));
  }

  private static void readAndAssertFirstEntryStoredMimeType(InputStream inputStream) throws Exception {
    try (ZipInputStream zipInputStream = new ZipInputStream(inputStream)) {
      ZipEntry firstZipEntry = zipInputStream.getNextEntry();
      assertStoredMimeTypeZipEntry(firstZipEntry);
    }
  }

  private static void assertStoredMimeTypeZipEntry(ZipEntry mimeTypeZipEntry) {
    Assert.assertEquals(ASiCUtils.MIME_TYPE, mimeTypeZipEntry.getName());
    Assert.assertEquals(ZipEntry.STORED, mimeTypeZipEntry.getMethod());
  }

}
