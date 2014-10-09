package org.digidoc4j;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import org.apache.commons.io.FileUtils;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.digidoc4j.utils.Helper.deleteFile;
import static org.junit.Assert.*;

public class DataFileTest {
  private static DataFile dataFile;

  @Before
  public void setUp() throws Exception {
    dataFile = new DataFile("testFiles/test.txt", "text/plain");
  }

  @Test
  public void testGetFileSize() throws Exception {
    assertEquals(16, dataFile.getFileSize());
  }

  @Test
  public void testGetFileSizeForInMemoryDocument() {
    DataFile mockDataFile = new MockDataFile(new byte[]{1, 2}, "fileName", "text/plain");
    assertEquals(2, mockDataFile.getFileSize());
  }

  @Test
  public void testGetMediaType() throws Exception {
    assertEquals("text/plain", dataFile.getMediaType());
  }

  @Test
  public void testGetFileName() throws Exception {
    assertEquals("test.txt", dataFile.getName());
  }

  @Test
  public void testCalculateDigest() throws Exception {
    assertEquals("tYpuWTmktpzSwRM8cxRlZfY4aw4wqr4vkXKPs9lwxP4=", DSSUtils.base64Encode(dataFile.calculateDigest()));
  }

  @Test
  public void testCalculateDigestWithEnumTypeSHA256() throws Exception {
    assertEquals("tYpuWTmktpzSwRM8cxRlZfY4aw4wqr4vkXKPs9lwxP4=",
        DSSUtils.base64Encode(dataFile.calculateDigest(DigestAlgorithm.SHA256)));
  }

  @Test
  public void testCalculateDigestWithEnumTypeSHA1() throws Exception {
    assertEquals("VNdqcg8SQlmbqk0MCl3rpxAN5qs=", DSSUtils.base64Encode(dataFile.calculateDigest(DigestAlgorithm.SHA1)));
  }

  @Test
  public void testSaveToFile() throws IOException {
    String fileName = "testSaveToFile.txt";
    dataFile.saveAs(fileName);
    assertTrue(new File(fileName).exists());

    byte[] testFileContent = FileUtils.readFileToByteArray(new File("testFiles/test.txt"));

    byte[] savedFileContent = FileUtils.readFileToByteArray(new File(fileName));
    assertArrayEquals(testFileContent, savedFileContent);

    deleteFile(fileName);
  }

  @Test
  public void testSaveToOutputStream() throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    dataFile.saveAs(out);
    out.flush();

    assertEquals("see on testfail\n", out.toString());
  }

  @Test(expected = DigiDoc4JException.class)
  public void incorrectMimeType() {
    dataFile = new DataFile("testFiles/test.txt", "incorrect");
  }

  @Test(expected = DigiDoc4JException.class)
  public void incorrectMimeTypeByteArrayConstructor() {
    dataFile = new DataFile(new byte[]{0x041}, "testFiles/test.txt", "incorrect");
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
    DataFile dataFile = new DataFile(new byte[]{0x041}, "suura.txt", "text/plain");
    assertEquals("suura.txt", dataFile.getName());
  }

  @Test
  public void testGetBytes() throws Exception {
    DataFile dataFile = new DataFile(new byte[]{0x041}, "suura.txt", "text/plain");
    assertArrayEquals(new byte[]{0x041}, dataFile.getBytes());
  }

  @Test
  public void createDocumentFromStream() throws Exception {
    ByteArrayInputStream inputStream = new ByteArrayInputStream("tere tere tipajalga".getBytes());
    DataFile dataFile = new DataFile(inputStream, "test.txt", "text/plain");
    dataFile.saveAs("createDocumentFromStream.txt");

    DataFile dataFileToCompare = new DataFile("createDocumentFromStream.txt", "text/plain");
    assertArrayEquals("tere tere tipajalga".getBytes(), dataFileToCompare.getBytes());

    Files.deleteIfExists(Paths.get("createDocumentFromStream.txt"));
  }

  @Test(expected = DigiDoc4JException.class)
  public void createDocumentFromInoutStreamThrowsException() {
    ByteArrayInputStream inputStream = new ByteArrayInputStream("test".getBytes());
    new DataFile(inputStream, "test.txt", "unknown");
  }

  @Test
  public void calculateSizeForStreamedFile() throws Exception {
    ByteArrayInputStream inputStream = new ByteArrayInputStream("tere tere tipajalga".getBytes());
    DataFile dataFile = new DataFile(inputStream, "test.txt", "text/plain");

    assertEquals(19, dataFile.getFileSize());
  }

  @Test(expected = DigiDoc4JException.class)
  public void askingDataFileSizeWhenTemporoaryFileIsDeleted() throws Exception {
    ByteArrayInputStream inputStream = new ByteArrayInputStream("tere tere tipajalga".getBytes());
    DataFile dataFile = new DataFile(inputStream, "test.txt", "text/plain");
    Files.deleteIfExists(Paths.get(dataFile.document.getAbsolutePath()));
    dataFile.getFileSize();
  }

  @Test
  public void testDigestIsCalculatedOnlyOnce() throws Exception {
    byte[] digest = dataFile.calculateDigest();
    assertEquals(digest, dataFile.calculateDigest(new URL("http://NonExisting.test")));
  }

  private class MockDataFile extends DataFile {
    public MockDataFile(byte[] data, String fileName, String mimeType) {
      super(data, fileName, mimeType);
      document = new InMemoryDocument(data, mimeType);
    }
  }
}
