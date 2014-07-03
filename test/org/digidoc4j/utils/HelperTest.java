package org.digidoc4j.utils;

import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.digidoc4j.utils.Helper.deleteFile;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class HelperTest {

  @Test
  public void testIsXMLFileWhenFileIsNotXMLFile() throws Exception {
    assertFalse(Helper.isXMLFile(new File("testFiles/test.txt")));
  }

  @Test
  public void testIsXMLFileWhenFileIsXMLFile() throws Exception {
    createXMLFile("testIsXMLFileWhenFileIsXMLFile.xml");
    assertTrue(Helper.isXMLFile(new File("testIsXMLFileWhenFileIsXMLFile.xml")));
    Files.deleteIfExists(Paths.get("testIsXMLFileWhenFileIsXMLFile.xml"));
  }

  private void createXMLFile(String fileName) throws IOException {
    FileWriter writer = new FileWriter(fileName);
    writer.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?><test></test>");
    writer.flush();
    writer.close();
  }

  @Test
  public void testIsZIPFileWhenFileIsNotZIPFile() throws Exception {
    assertFalse(Helper.isZipFile(new File("testFiles/test.txt")));
  }

  @Test
  public void testIsZIPFileWhenFileIsZIPFile() throws Exception {
    FileOutputStream fileOutputStream = new FileOutputStream("test.zip");
    ZipOutputStream zipOutputStream = new ZipOutputStream(fileOutputStream);
    zipOutputStream.putNextEntry(new ZipEntry("testFiles/test.txt"));
    zipOutputStream.closeEntry();

    assertTrue(Helper.isZipFile(new File("test.zip")));

    deleteFile("test.zip");
  }

  @Test
  public void testDeleteFileIfExists() throws Exception {
    File file = new File("testDelete.txt");
    file.createNewFile();
    assertTrue(file.exists());
    deleteFile("testDelete.txt");
    assertFalse(file.exists());
  }

  @Test
  public void testDeleteFileIfNotExists() throws Exception {
    deleteFile("testDeleteNotExists.txt");
    assertFalse(new File("testDeleteNotExists.txt").exists());
  }
}