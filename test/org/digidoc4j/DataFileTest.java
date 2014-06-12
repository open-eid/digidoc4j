package org.digidoc4j;

import eu.europa.ec.markt.dss.DSSUtils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;

import org.apache.commons.io.FileUtils;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class DataFileTest {
  private static DataFile dataFile;

  @BeforeClass
  public static void setUp() throws Exception {
    dataFile = new DataFile("test.txt", "text/plain");
  }

  @Test
  public void testGetFileSize() throws Exception {
    assertEquals(16, dataFile.getFileSize());
  }

  @Test
  public void testGetMediaType() throws Exception {
    assertEquals("text/plain", dataFile.getMediaType());
  }

  @Test
  public void testGetFileName() throws Exception {
    assertEquals(new File("test.txt").getAbsolutePath(), dataFile.getFileName());
  }

  @Test
  public void testCalculateDigest() throws Exception {
    assertEquals("tYpuWTmktpzSwRM8cxRlZfY4aw4wqr4vkXKPs9lwxP4=", DSSUtils.base64Encode(dataFile.calculateDigest()));
  }

  @Test
  public void testSaveToFile() throws IOException {
    String fileName = "testSaveToFile.txt";
    dataFile.saveAs(fileName);
    assertTrue(new File(fileName).exists());

    byte[] testFileContent = FileUtils.readFileToByteArray(new File("test.txt"));
    byte[] savedFileContent = FileUtils.readFileToByteArray(new File("testSaveToFile.txt"));
    assertArrayEquals(testFileContent, savedFileContent);
  }

  @Test
  public void testSaveToOutputStream() throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    dataFile.saveAs(out);
    out.flush();

    assertEquals("see on testfail\n", out.toString());
  }

  @Test(expected = DigiDoc4JException.class)
  public void testThrowsFileNotFoundExceptionIfFileDoesNotExists() throws Exception {
    new DataFile("NOT_EXISTS.TXT", "text/plain");
  }

  @Test(expected = Exception.class)
  public void testThrowsExceptionOnUnknownError() throws Exception {
    new DataFile(null, "none/none");
  }

  @Test
  public void testInMemoryDocumentRetrievesFileName() {
    DataFile dataFile = new DataFile(new byte[]{0x042}, "suura.txt", "text/plain");
    assertEquals("suura.txt", dataFile.getFileName());
  }

  @Test
  public void testDigestIsCalculatedOnlyOnce() throws Exception {
  }
}
