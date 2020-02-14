package org.digidoc4j;

import eu.europa.esig.dss.model.MimeType;
import org.digidoc4j.ddoc.Manifest;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class ContainerZipTest extends AbstractTest {

  private static final String MIME_TYPE_ENTRY_NAME = "mimetype";

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
    saveDegenerateContainerWithNonFirstMimeType(testNonFirstMimeTypeAsiceFile, MimeType.ASICE.getMimeTypeString());
    Container container = ContainerOpener.open(testNonFirstMimeTypeAsiceFile.getPath());
    readAndAssertFirstEntryStoredMimeType(container.saveAsStream());
  }

  @Test
  public void loadedAsicsWithNonFirstMimeTypeSavedAsStreamShouldHaveStoredMimeTypeAsFirstEntry() throws Exception {
    File testNonFirstMimeTypeAsicsFile = testFolder.newFile("original-non-first-mimetype-asics.asics");
    saveDegenerateContainerWithNonFirstMimeType(testNonFirstMimeTypeAsicsFile, MimeType.ASICS.getMimeTypeString());
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
    saveDegenerateContainerWithNonFirstMimeType(testNonFirstMimeTypeAsiceFile, MimeType.ASICE.getMimeTypeString());
    File testFile = createTestContainerFile(ContainerOpener.open(testNonFirstMimeTypeAsiceFile.getPath()), "loaded-non-first-mimetype-asice.asice");
    readAndAssertFirstEntryStoredMimeType(new FileInputStream(testFile));
  }

  @Test
  public void loadedAsicsWithNonFirstMimeTypeSavedAsFileShouldHaveStoredMimeTypeAsFirstEntry() throws Exception {
    File testNonFirstMimeTypeAsicsFile = testFolder.newFile("original-non-first-mimetype-asics.asics");
    saveDegenerateContainerWithNonFirstMimeType(testNonFirstMimeTypeAsicsFile, MimeType.ASICS.getMimeTypeString());
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
    saveDegenerateContainerWithDeflatedMimeType(testDeflatedMimeTypeAsiceFile, MimeType.ASICE.getMimeTypeString());
    return testDeflatedMimeTypeAsiceFile;
  }

  private File createTestDeflatedMimeTypeAsicsFile() throws Exception {
    File testDeflatedMimeTypeAsicsFile = testFolder.newFile("original-deflated-mimetype-asics.asics");
    saveDegenerateContainerWithDeflatedMimeType(testDeflatedMimeTypeAsicsFile, MimeType.ASICS.getMimeTypeString());
    return testDeflatedMimeTypeAsicsFile;
  }

  private File createTestContainerFile(Container container, String fileName) throws Exception {
    File testFile = testFolder.newFile(fileName);
    container.saveAsFile(testFile.getPath());
    return testFile;
  }

  private static void saveDegenerateContainerWithDeflatedMimeType(File destinationFile, String mimeTypeContent) throws Exception {
    try (ZipOutputStream zipOutputStream = new ZipOutputStream(new FileOutputStream(destinationFile))) {
      ZipEntry zipEntry = new ZipEntry(MIME_TYPE_ENTRY_NAME);
      zipEntry.setMethod(ZipEntry.DEFLATED);

      zipOutputStream.putNextEntry(zipEntry);
      zipOutputStream.setMethod(ZipOutputStream.DEFLATED);
      zipOutputStream.write(mimeTypeContent.getBytes(StandardCharsets.US_ASCII));
      zipOutputStream.closeEntry();
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

  private static ZipEntry writeValidMimeTypeTo(ZipOutputStream zipOutputStream, String mimeTypeContent) throws Exception {
    ZipEntry zipEntry = new ZipEntry(MIME_TYPE_ENTRY_NAME);
    zipEntry.setMethod(ZipEntry.STORED);

    byte[] content = mimeTypeContent.getBytes(StandardCharsets.US_ASCII);
    zipEntry.setCrc(calculateCrc32(content));
    zipEntry.setCompressedSize(content.length);
    zipEntry.setSize(content.length);

    zipOutputStream.putNextEntry(zipEntry);
    zipOutputStream.write(content);
    zipOutputStream.closeEntry();

    return zipEntry;
  }

  private static long calculateCrc32(byte[] content) {
    CRC32 crc32 = new CRC32();
    crc32.update(content);
    return crc32.getValue();
  }

  private static void readAndAssertFirstEntryStoredMimeType(InputStream inputStream) throws Exception {
    try (ZipInputStream zipInputStream = new ZipInputStream(inputStream)) {
      ZipEntry firstZipEntry = zipInputStream.getNextEntry();
      assertStoredMimeTypeZipEntry(firstZipEntry);
    }
  }

  private static void assertStoredMimeTypeZipEntry(ZipEntry mimeTypeZipEntry) {
    Assert.assertEquals(MIME_TYPE_ENTRY_NAME, mimeTypeZipEntry.getName());
    Assert.assertEquals(ZipEntry.STORED, mimeTypeZipEntry.getMethod());
  }

}
