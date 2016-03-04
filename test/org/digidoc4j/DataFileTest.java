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

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.junit.Before;
import org.junit.Ignore;
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

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;

public class DataFileTest {
  private static DataFile dataFile;

  @Before
  public void setUp() throws Exception {
    dataFile = new DataFile("testFiles/test.txt", "text/plain");
  }

  @Test
  public void testGetFileSize() throws Exception {
    assertEquals(15, dataFile.getFileSize());
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
    assertEquals("RqDqtqi3rTsWj07rrWc5kATAZIw7T1XHP/NPLCF05RU=", Base64.encodeBase64String(dataFile.calculateDigest()));
  }

  @Test
  public void testCalculateDigestWithEnumTypeSHA256() throws Exception {
    assertEquals("RqDqtqi3rTsWj07rrWc5kATAZIw7T1XHP/NPLCF05RU=",
        Base64.encodeBase64String(dataFile.calculateDigest(DigestAlgorithm.SHA256)));
  }

  @Test
  public void testCalculateDigestWithEnumTypeSHA1() throws Exception {
    assertEquals("OQj17m9Rt2vPXYrry+v/KHpf98Q=", Base64.encodeBase64String(dataFile.calculateDigest(DigestAlgorithm.SHA1)));
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

    assertEquals("see on testfail", out.toString());
    out.close();
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
    try(ByteArrayInputStream inputStream = new ByteArrayInputStream("tere tere tipajalga".getBytes())) {
      DataFile dataFile = new DataFile(inputStream, "test.txt", "text/plain");
      dataFile.saveAs("createDocumentFromStream.txt");

      DataFile dataFileToCompare = new DataFile("createDocumentFromStream.txt", "text/plain");
      assertArrayEquals("tere tere tipajalga".getBytes(), dataFileToCompare.getBytes());
    }

    Files.deleteIfExists(Paths.get("createDocumentFromStream.txt"));
  }

  @Test(expected = DigiDoc4JException.class)
  public void createDocumentFromInoutStreamThrowsException() throws IOException {
    try(ByteArrayInputStream inputStream = new ByteArrayInputStream("test".getBytes())) {
      new DataFile(inputStream, "test.txt", "unknown");
    }
  }

  @Test
  public void calculateSizeForStreamedFile() throws Exception {
    try(ByteArrayInputStream inputStream = new ByteArrayInputStream("tere tere tipajalga".getBytes())) {
      DataFile dataFile = new DataFile(inputStream, "test.txt", "text/plain");

      assertEquals(19, dataFile.getFileSize());
    }
  }

  @Ignore("Data files are not written on disk")
  @Test(expected = DigiDoc4JException.class)
  public void askingDataFileSizeWhenTemporoaryFileIsDeleted() throws Exception {
    try(ByteArrayInputStream inputStream = new ByteArrayInputStream("tere tere tipajalga".getBytes())) {
      DataFile dataFile = new DataFile(inputStream, "test.txt", "text/plain");
      Files.deleteIfExists(Paths.get(dataFile.getDocument().getAbsolutePath()));
      dataFile.getFileSize();
    }
  }

  @Test
  public void testDigestIsCalculatedOnlyOnce() throws Exception {
    byte[] digest = dataFile.calculateDigest();
    assertEquals(digest, dataFile.calculateDigest(new URL("http://NonExisting.test")));
  }

  private class MockDataFile extends DataFile {
    public MockDataFile(byte[] data, String fileName, String mimeType) {
      super(data, fileName, mimeType);
      DSSDocument document = new InMemoryDocument(data, mimeType);
      setDocument(document);
    }
  }
}
