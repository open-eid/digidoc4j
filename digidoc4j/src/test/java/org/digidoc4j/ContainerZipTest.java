package org.digidoc4j;

import eu.europa.esig.dss.model.MimeType;
import org.digidoc4j.ddoc.Manifest;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
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
