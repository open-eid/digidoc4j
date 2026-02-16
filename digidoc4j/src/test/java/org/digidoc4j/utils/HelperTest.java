/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.utils;

import org.apache.commons.io.FileUtils;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class HelperTest extends AbstractTest {

  @Test
  void testIsXMLFileWhenFileIsNotXMLFile() throws Exception {
    assertFalse(Helper.isXMLFile(new File("src/test/resources/testFiles/helper-files/test.txt")));
  }

  @Test
  public void testIsXMLFileWhenFileIsXMLFile() throws Exception {
    assertTrue(Helper.isXMLFile(new File(createXMLFile())));
  }

  @Test
  public void testIsZIPFileWhenFileIsNotZIPFile() throws Exception {
    assertFalse(Helper.isZipFile(new File("src/test/resources/testFiles/helper-files/test.txt")));
  }

  @Test
  public void testIsZIPFileWhenFileIsZIPFile() throws Exception {
    String file = getFileBy("zip");
    try (FileOutputStream stream = new FileOutputStream(file)) {
      ZipOutputStream zipStream = new ZipOutputStream(stream);
      zipStream.putNextEntry(new ZipEntry("src/test/resources/testFiles/helper-files/test.txt"));
      zipStream.closeEntry();
      assertTrue(Helper.isZipFile(new File(file)));
    }
  }

  @Test
  public void testDeleteFileIfExists() throws Exception {
    String filePath = getFileBy("txt", true);
    File file = new File(filePath);
    assertTrue(file.exists());
    Helper.deleteFile(filePath);
    assertFalse(file.exists());
  }

  @Test
  public void testDeleteFileIfNotExists() throws Exception {
    Helper.deleteFile("testDeleteNotExists.txt");
    assertFalse(new File("testDeleteNotExists.txt").exists());
  }

  @Test
  public void extractSignatureS0() throws Exception {
    assertEquals("A", Helper.extractSignature(createZIPFile(), 0));
  }

  @Test
  public void extractSignatureS1() throws Exception {
    assertEquals("B", Helper.extractSignature(createZIPFile(), 1));
  }

  @Test(expected = IOException.class)
  public void extractSignatureThrowsErrorWhenSignatureIsNotFound() throws Exception {
    String file = getFileBy("zip");
    try (
        FileOutputStream fileStream = new FileOutputStream(file);
        ZipOutputStream zipStream = new ZipOutputStream(fileStream)) {
      ZipEntry zipEntry = new ZipEntry("test");
      zipStream.putNextEntry(zipEntry);
      zipStream.write(0x42);
      zipStream.closeEntry();
    }
    Helper.extractSignature(file, 0);
  }

  @Test(expected = DigiDoc4JException.class)
  public void deserializeThrowsException() {
    Helper.deserializer((File) null);
  }

  @Test(expected = DigiDoc4JException.class)
  public void serializeThrowsException() {
    Helper.serialize(ContainerBuilder.aContainer().build(), (File) null);
  }

  @Test
  public void testSaveFileNamesFromString() {
    String pathToContainer = "src/test/resources/testFiles/valid-containers/DigiDocService_spec_est.pdf-TM-j.bdoc";
    String folder = this.testFolder.getRoot().getPath();
    Helper.saveAllFilesFromContainerPathToFolder(pathToContainer, folder);
    assertTrue(new File(folder + File.separator + "DigiDocService_spec_est.pdf").exists());
    assertTrue(new File(folder + File.separator + "sample_file.pdf").exists());
  }

  @Test
  public void testSaveFileNamesFromContainer() {
    Container container = ContainerBuilder.aContainer().
        fromExistingFile("src/test/resources/testFiles/valid-containers/DigiDocService_spec_est.pdf-TM-j.bdoc").build();
    String folder = this.testFolder.getRoot().getPath();
    Helper.saveAllFilesFromContainerToFolder(container, folder);
    assertTrue(new File(folder + File.separator + "DigiDocService_spec_est.pdf").exists());
    assertTrue(new File(folder + File.separator + "sample_file.pdf").exists());
  }

  @Test
  public void testGetFilesFromString() {
    Container container = ContainerBuilder.aContainer().
        fromExistingFile("src/test/resources/testFiles/valid-containers/DigiDocService_spec_est.pdf-TM-j.bdoc").        build();
    String folder = this.testFolder.getRoot().getPath();
    String helperFolder = "src/test/resources/testFiles/helper-files";
    List<byte[]> files = Helper.getAllFilesFromContainerAsBytes(container);
    assertEquals(2, files.size());
    try {
      FileUtils.writeByteArrayToFile(new File(folder + File.separator + "DigiDocService_spec_est.pdf"), files.get(0));
      FileUtils.writeByteArrayToFile(new File(folder + File.separator + "sample_file.pdf"), files.get(1));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    compareFileSize(folder, helperFolder);
  }

  @Test
  public void testGetFilesFromContainer() {
    String containerFile = "src/test/resources/testFiles/valid-containers/DigiDocService_spec_est.pdf-TM-j.bdoc";
    String folder = this.testFolder.getRoot().getPath();
    String helperFolder = "src/test/resources/testFiles/helper-files";
    List<byte[]> files = Helper.getAllFilesFromContainerPathAsBytes(containerFile);
    assertEquals(2, files.size());
    try {
      FileUtils.writeByteArrayToFile(new File(folder + File.separator + "DigiDocService_spec_est.pdf"), files.get(0));
      FileUtils.writeByteArrayToFile(new File(folder + File.separator + "sample_file.pdf"), files.get(1));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    compareFileSize(folder, helperFolder);
  }

  @Test
  public void testPDFContainer() {
    assertTrue(Helper.isPdfFile("src/test/resources/testFiles/invalid-containers/EE_AS-P-BpLT-V-009.pdf"));
    assertFalse(Helper.isPdfFile("src/test/resources/testFiles/valid-containers/one_signature.bdoc"));
  }

  /*
   * RESTRICTED METHODS
   */

  private String createXMLFile() throws IOException {
    String xmlFile = getFileBy("xml", true);
    try (FileWriter writer = new FileWriter(xmlFile)) {
      writer.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?><test></test>");
      writer.flush();
    }
    return xmlFile;
  }

  private String createZIPFile() throws IOException {
    String zipFile = getFileBy("zip", true);
    try (FileOutputStream stream = new FileOutputStream(zipFile);
         ZipOutputStream zipStream = new ZipOutputStream(stream)) {
      ZipEntry signature0 = new ZipEntry("META-INF/signatures0.xml");
      zipStream.putNextEntry(signature0);
      zipStream.write(0x41);
      zipStream.closeEntry();
      ZipEntry signature1 = new ZipEntry("META-INF/signatures1.xml");
      zipStream.putNextEntry(signature1);
      zipStream.write(0x42);
      zipStream.closeEntry();
    }
    return zipFile;
  }

  private void compareFileSize(String folder, String helperFolder) {
    File helperFile1 = new File(helperFolder + File.separator + "DigiDocService_spec_est.pdf");
    File helperFile2 = new File(helperFolder + File.separator + "sample_file.pdf");
    File file1 = new File(folder + File.separator + "DigiDocService_spec_est.pdf");
    File file2 = new File(folder + File.separator + "sample_file.pdf");
    assertEquals(FileUtils.sizeOf(helperFile1), FileUtils.sizeOf(file1));
    assertEquals(FileUtils.sizeOf(helperFile2), FileUtils.sizeOf(file2));
    assertTrue(file1.exists());
    assertTrue(file2.exists());
  }

}
