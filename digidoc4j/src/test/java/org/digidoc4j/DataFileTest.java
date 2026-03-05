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
import org.digidoc4j.exceptions.InvalidDataFileException;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DataFileTest extends AbstractTest {

  private static final String TEST_FILE_NAME = "test.txt";
  private static final String TEST_FILE_MIMETYPE = "text/plain";
  private static final String TEST_FILE_PATH = "src/test/resources/testFiles/helper-files/test.txt";
  private static final String EMPTY_FILE_PATH = "src/test/resources/testFiles/helper-files/empty.txt";

  @Test
  void testGetFileSize() {
    DataFile dataFile = new DataFile(TEST_FILE_PATH, TEST_FILE_MIMETYPE);
    assertEquals(15, dataFile.getFileSize());
  }

  @Test
  void testIsFileEmpty() {
    DataFile dataFile = new DataFile(TEST_FILE_PATH, TEST_FILE_MIMETYPE);
    assertFalse(dataFile.isFileEmpty());
  }

  @Test
  void testIsFileEmptyForEmptyFile() {
    DataFile dataFile = new DataFile(EMPTY_FILE_PATH, TEST_FILE_MIMETYPE);
    assertTrue(dataFile.isFileEmpty());
  }

  @Test
  void testGetFileSizeForInMemoryDocument() {
    DataFile dataFile = new DataFile(new byte[]{1, 2}, TEST_FILE_NAME, TEST_FILE_MIMETYPE);
    assertEquals(2, dataFile.getFileSize());
  }

  @Test
  void testIsFileEmptyForInMemoryDocument() {
    DataFile dataFile = new DataFile(new byte[]{1, 2}, TEST_FILE_NAME, TEST_FILE_MIMETYPE);
    assertFalse(dataFile.isFileEmpty());
  }

  @Test
  void testIsFileEmptyForEmptyInMemoryDocument() {
    DataFile dataFile = new DataFile(new byte[0], TEST_FILE_NAME, TEST_FILE_MIMETYPE);
    assertTrue(dataFile.isFileEmpty());
  }

  @Test
  void testGetMediaType() {
    DataFile dataFile = new DataFile(TEST_FILE_PATH, TEST_FILE_MIMETYPE);
    assertEquals(TEST_FILE_MIMETYPE, dataFile.getMediaType());
  }

  @Test
  void testGetFileName() {
    DataFile dataFile = new DataFile(TEST_FILE_PATH, TEST_FILE_MIMETYPE);
    assertEquals(TEST_FILE_NAME, dataFile.getName());
  }

  @Test
  void testCalculateDigest() {
    DataFile dataFile = new DataFile(TEST_FILE_PATH, TEST_FILE_MIMETYPE);
    assertArrayEquals(
            Base64.decodeBase64("RqDqtqi3rTsWj07rrWc5kATAZIw7T1XHP/NPLCF05RU="),
            dataFile.calculateDigest()
    );
  }

  @Test
  void testCalculateDigestWithEnumTypeSHA1() {
    DataFile dataFile = new DataFile(TEST_FILE_PATH, TEST_FILE_MIMETYPE);
    assertArrayEquals(
            Base64.decodeBase64("OQj17m9Rt2vPXYrry+v/KHpf98Q="),
            dataFile.calculateDigest(DigestAlgorithm.SHA1)
    );
  }

  @Test
  void testCalculateDigestWithEnumTypeSHA224() {
    DataFile dataFile = new DataFile(TEST_FILE_PATH, TEST_FILE_MIMETYPE);
    assertArrayEquals(
            Base64.decodeBase64("w/fpCafC/Rcn3uKW2ExwxyzTW42KAhfU8eljcQ=="),
            dataFile.calculateDigest(DigestAlgorithm.SHA224)
    );
  }

  @Test
  void testCalculateDigestWithEnumTypeSHA256() {
    DataFile dataFile = new DataFile(TEST_FILE_PATH, TEST_FILE_MIMETYPE);
    assertArrayEquals(
            Base64.decodeBase64("RqDqtqi3rTsWj07rrWc5kATAZIw7T1XHP/NPLCF05RU="),
            dataFile.calculateDigest(DigestAlgorithm.SHA256)
    );
  }

  @Test
  void testCalculateDigestWithEnumTypeSHA384() {
    DataFile dataFile = new DataFile(TEST_FILE_PATH, TEST_FILE_MIMETYPE);
    assertArrayEquals(
            Base64.decodeBase64("i6PjAerb6Wuzt21+fISlv2SngAxfFfh+ZxrZDhdtwv0x8t8zXAPrtW/mi5aqpFig"),
            dataFile.calculateDigest(DigestAlgorithm.SHA384)
    );
  }

  @Test
  void testCalculateDigestWithEnumTypeSHA512() {
    DataFile dataFile = new DataFile(TEST_FILE_PATH, TEST_FILE_MIMETYPE);
    assertArrayEquals(
            Base64.decodeBase64("ucUB3sbDkP0cjlo+T0PSLMfICMQm9P6pHq+byFo7Ytw0cG9uiA1QoAPQihQKDsBoInbgFpFZftPvghS3AgsM+A=="),
            dataFile.calculateDigest(DigestAlgorithm.SHA512)
    );
  }

  @Test
  void testSaveToFile() throws IOException {
    DataFile dataFile = new DataFile(TEST_FILE_PATH, TEST_FILE_MIMETYPE);
    String file = getFileBy("txt");
    dataFile.saveAs(file);
    assertTrue(new File(file).exists());
    byte[] testFileContent = FileUtils.readFileToByteArray(new File(TEST_FILE_PATH));
    byte[] savedFileContent = FileUtils.readFileToByteArray(new File(file));
    assertArrayEquals(testFileContent, savedFileContent);
  }

  @Test
  void testSaveToOutputStream() throws IOException {
    DataFile dataFile = new DataFile(TEST_FILE_PATH, TEST_FILE_MIMETYPE);
    try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
      dataFile.saveAs(stream);
      stream.flush();
      assertEquals("see on testfail", stream.toString());
    }
  }

  @Test
  void incorrectMimeType() {
    DataFile dataFile = new DataFile(TEST_FILE_PATH, "incorrect");
    assertNotNull(dataFile.getMediaType());
  }

  @Test
  void incorrectMimeTypeByteArrayConstructor() {
    DataFile dataFile = new DataFile(new byte[]{0x041}, TEST_FILE_PATH, "incorrect");
    assertNotNull(dataFile.getMediaType());
  }

  @Test
  void testThrowsFileNotFoundExceptionIfFileDoesNotExists() {
    assertThrows(
            DigiDoc4JException.class,
            () ->  new DataFile("NOT_EXISTS.TXT", TEST_FILE_MIMETYPE)
    );
  }

  @Test
  void testThrowsExceptionOnUnknownError() {
    assertThrows(
            InvalidDataFileException.class,
            () -> new DataFile(null, "none/none")
    );
  }

  @Test
  void testInMemoryDocumentRetrievesFileName() {
    DataFile dataFile = new DataFile(new byte[]{0x041}, "suura.txt", "text/plain");
    assertEquals("suura.txt", dataFile.getName());
  }

  @Test
  void testInMemoryDocumentFileNameEscaping() {
    testFileNameEscaping(fileName -> new DataFile(new byte[]{0x041}, fileName, "text/plain"));
  }

  @Test
  void testGetBytes() {
    DataFile dataFile = new DataFile(new byte[]{0x041}, "suura.txt", "text/plain");
    assertArrayEquals(new byte[]{0x041}, dataFile.getBytes());
  }

  @Test
  void createDocumentFromStream() throws Exception {
    String file = getFileBy("txt");
    try (ByteArrayInputStream stream = new ByteArrayInputStream("tere tere tipajalga".getBytes())) {
      DataFile dataFile = new DataFile(stream, "test.txt", "text/plain");
      dataFile.saveAs(file);
      DataFile dataFileToCompare = new DataFile(file, "text/plain");
      assertArrayEquals("tere tere tipajalga".getBytes(), dataFileToCompare.getBytes());
    }
  }

  @Test
  void createDocumentFromInoutStreamThrowsException() throws IOException {
    try (ByteArrayInputStream stream = new ByteArrayInputStream("test".getBytes())) {
      DataFile dataFile = new DataFile(stream, "test.txt", "unknown");
      assertNotNull(dataFile.getMediaType());
      assertArrayEquals("test".getBytes(), dataFile.getBytes());
    }
  }

  @Test
  void testGetFileNameForStreamedFile() throws Exception {
    try (ByteArrayInputStream stream = new ByteArrayInputStream("tere tere tipajalga".getBytes())) {
      DataFile dataFile = new DataFile(stream, "test.txt", "text/plain");
      assertEquals("test.txt", dataFile.getName());
    }
  }

  @Test
  void testFileNameEscapingForStreamedFile() {
    testFileNameEscaping(fileName -> {
      try (ByteArrayInputStream stream = new ByteArrayInputStream("tere tere tipajalga".getBytes())) {
        return new DataFile(stream, fileName, "text/plain");
      } catch (IOException e) {
        throw new IllegalStateException("Failed to open stream", e);
      }
    });
  }

  @Test
  void calculateSizeForStreamedFile() throws Exception {
    try (ByteArrayInputStream stream = new ByteArrayInputStream("tere tere tipajalga".getBytes())) {
      DataFile dataFile = new DataFile(stream, "test.txt", "text/plain");
      assertEquals(19, dataFile.getFileSize());
    }
  }

  /*
   * RESTRICTED METHODS
   */

  private static void testFileNameEscaping(Function<String, DataFile> dataFileFactory) {
    String fileName = "file-name.ext";
    DataFile dataFile;

    dataFile = dataFileFactory.apply(fileName);
    assertEquals(fileName, dataFile.getName());

    dataFile = dataFileFactory.apply(String.format("dir%s%s", File.separator, fileName));
    assertEquals(fileName, dataFile.getName());

    dataFile = dataFileFactory.apply(String.format("..%s%s", File.separator, fileName));
    assertEquals(fileName, dataFile.getName());

    dataFile = dataFileFactory.apply(String.format("..%s..%sdir%s..%s%s", File.separator, File.separator, File.separator, File.separator, fileName));
    assertEquals(fileName, dataFile.getName());
  }

}
