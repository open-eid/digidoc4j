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
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.function.Function;

public class DataFileTest extends AbstractTest {

  private static final String TEST_FILE_NAME = "test.txt";
  private static final String TEST_FILE_MIMETYPE = "text/plain";
  private static final String TEST_FILE_PATH = "src/test/resources/testFiles/helper-files/test.txt";
  private static final String EMPTY_FILE_PATH = "src/test/resources/testFiles/helper-files/empty.txt";

  @Test
  public void testGetFileSize() {
    DataFile dataFile = new DataFile(TEST_FILE_PATH, TEST_FILE_MIMETYPE);
    Assert.assertEquals(15, dataFile.getFileSize());
  }

  @Test
  public void testIsFileEmpty() {
    DataFile dataFile = new DataFile(TEST_FILE_PATH, TEST_FILE_MIMETYPE);
    Assert.assertFalse(dataFile.isFileEmpty());
  }

  @Test
  public void testIsFileEmptyForEmptyFile() {
    DataFile dataFile = new DataFile(EMPTY_FILE_PATH, TEST_FILE_MIMETYPE);
    Assert.assertTrue(dataFile.isFileEmpty());
  }

  @Test
  public void testGetFileSizeForInMemoryDocument() {
    DataFile dataFile = new DataFile(new byte[]{1, 2}, TEST_FILE_NAME, TEST_FILE_MIMETYPE);
    Assert.assertEquals(2, dataFile.getFileSize());
  }

  @Test
  public void testIsFileEmptyForInMemoryDocument() {
    DataFile dataFile = new DataFile(new byte[]{1, 2}, TEST_FILE_NAME, TEST_FILE_MIMETYPE);
    Assert.assertFalse(dataFile.isFileEmpty());
  }

  @Test
  public void testIsFileEmptyForEmptyInMemoryDocument() {
    DataFile dataFile = new DataFile(new byte[0], TEST_FILE_NAME, TEST_FILE_MIMETYPE);
    Assert.assertTrue(dataFile.isFileEmpty());
  }

  @Test
  public void testGetMediaType() {
    DataFile dataFile = new DataFile(TEST_FILE_PATH, TEST_FILE_MIMETYPE);
    Assert.assertEquals(TEST_FILE_MIMETYPE, dataFile.getMediaType());
  }

  @Test
  public void testGetFileName() {
    DataFile dataFile = new DataFile(TEST_FILE_PATH, TEST_FILE_MIMETYPE);
    Assert.assertEquals(TEST_FILE_NAME, dataFile.getName());
  }

  @Test
  public void testCalculateDigest() {
    DataFile dataFile = new DataFile(TEST_FILE_PATH, TEST_FILE_MIMETYPE);
    Assert.assertArrayEquals(
            Base64.decodeBase64("RqDqtqi3rTsWj07rrWc5kATAZIw7T1XHP/NPLCF05RU="),
            dataFile.calculateDigest()
    );
  }

  @Test
  public void testCalculateDigestWithEnumTypeSHA256() {
    DataFile dataFile = new DataFile(TEST_FILE_PATH, TEST_FILE_MIMETYPE);
    Assert.assertArrayEquals(
            Base64.decodeBase64("RqDqtqi3rTsWj07rrWc5kATAZIw7T1XHP/NPLCF05RU="),
            dataFile.calculateDigest(DigestAlgorithm.SHA256)
    );
  }

  @Test
  public void testCalculateDigestWithEnumTypeSHA1() {
    DataFile dataFile = new DataFile(TEST_FILE_PATH, TEST_FILE_MIMETYPE);
    Assert.assertArrayEquals(
            Base64.decodeBase64("OQj17m9Rt2vPXYrry+v/KHpf98Q="),
            dataFile.calculateDigest(DigestAlgorithm.SHA1)
    );
  }

  @Test
  public void testSaveToFile() throws IOException {
    DataFile dataFile = new DataFile(TEST_FILE_PATH, TEST_FILE_MIMETYPE);
    String file = this.getFileBy("txt");
    dataFile.saveAs(file);
    Assert.assertTrue(new File(file).exists());
    byte[] testFileContent = FileUtils.readFileToByteArray(new File(TEST_FILE_PATH));
    byte[] savedFileContent = FileUtils.readFileToByteArray(new File(file));
    Assert.assertArrayEquals(testFileContent, savedFileContent);
  }

  @Test
  public void testSaveToOutputStream() throws IOException {
    DataFile dataFile = new DataFile(TEST_FILE_PATH, TEST_FILE_MIMETYPE);
    try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
      dataFile.saveAs(stream);
      stream.flush();
      Assert.assertEquals("see on testfail", stream.toString());
    }
  }

  @Test
  public void incorrectMimeType() {
    DataFile dataFile = new DataFile(TEST_FILE_PATH, "incorrect");
    Assert.assertNotNull(dataFile.getMediaType());
  }

  @Test
  public void incorrectMimeTypeByteArrayConstructor() {
    DataFile dataFile = new DataFile(new byte[]{0x041}, TEST_FILE_PATH, "incorrect");
    Assert.assertNotNull(dataFile.getMediaType());
  }

  @Test(expected = DigiDoc4JException.class)
  public void testThrowsFileNotFoundExceptionIfFileDoesNotExists() {
    new DataFile("NOT_EXISTS.TXT", TEST_FILE_MIMETYPE);
  }

  @Test(expected = Exception.class)
  public void testThrowsExceptionOnUnknownError() {
    new DataFile(null, "none/none");
  }

  @Test
  public void testInMemoryDocumentRetrievesFileName() {
    DataFile dataFile = new DataFile(new byte[]{0x041}, "suura.txt", "text/plain");
    Assert.assertEquals("suura.txt", dataFile.getName());
  }

  @Test
  public void testInMemoryDocumentFileNameEscaping() {
    testFileNameEscaping(fileName -> new DataFile(new byte[]{0x041}, fileName, "text/plain"));
  }

  @Test
  public void testGetBytes() throws Exception {
    DataFile dataFile = new DataFile(new byte[]{0x041}, "suura.txt", "text/plain");
    Assert.assertArrayEquals(new byte[]{0x041}, dataFile.getBytes());
  }

  @Test
  public void createDocumentFromStream() throws Exception {
    String file = this.getFileBy("txt");
    try (ByteArrayInputStream stream = new ByteArrayInputStream("tere tere tipajalga".getBytes())) {
      DataFile dataFile = new DataFile(stream, "test.txt", "text/plain");
      dataFile.saveAs(file);
      DataFile dataFileToCompare = new DataFile(file, "text/plain");
      Assert.assertArrayEquals("tere tere tipajalga".getBytes(), dataFileToCompare.getBytes());
    }
  }

  @Test
  public void createDocumentFromInoutStreamThrowsException() throws IOException {
    try (ByteArrayInputStream stream = new ByteArrayInputStream("test".getBytes())) {
      DataFile dataFile = new DataFile(stream, "test.txt", "unknown");
      Assert.assertNotNull(dataFile.getMediaType());
      Assert.assertArrayEquals("test".getBytes(), dataFile.getBytes());
    }
  }

  @Test
  public void testGetFileNameForStreamedFile() throws Exception {
    try (ByteArrayInputStream stream = new ByteArrayInputStream("tere tere tipajalga".getBytes())) {
      DataFile dataFile = new DataFile(stream, "test.txt", "text/plain");
      Assert.assertEquals("test.txt", dataFile.getName());
    }
  }

  @Test
  public void testFileNameEscapingForStreamedFile() {
    testFileNameEscaping(fileName -> {
      try (ByteArrayInputStream stream = new ByteArrayInputStream("tere tere tipajalga".getBytes())) {
        return new DataFile(stream, fileName, "text/plain");
      } catch (IOException e) {
        throw new IllegalStateException("Failed to open stream", e);
      }
    });
  }

  @Test
  public void calculateSizeForStreamedFile() throws Exception {
    try (ByteArrayInputStream stream = new ByteArrayInputStream("tere tere tipajalga".getBytes())) {
      DataFile dataFile = new DataFile(stream, "test.txt", "text/plain");
      Assert.assertEquals(19, dataFile.getFileSize());
    }
  }

  @Test
  public void testDigestIsCalculatedOnlyOnce() throws Exception {
    DataFile dataFile = new DataFile(TEST_FILE_PATH, TEST_FILE_MIMETYPE);
    byte[] digest = dataFile.calculateDigest();
    Assert.assertEquals(digest, dataFile.calculateDigest(new URL("http://NonExisting.test")));
  }

  /*
   * RESTRICTED METHODS
   */

  private static void testFileNameEscaping(Function<String, DataFile> dataFileFactory) {
    String fileName = "file-name.ext";
    DataFile dataFile;

    dataFile = dataFileFactory.apply(fileName);
    Assert.assertEquals(fileName, dataFile.getName());

    dataFile = dataFileFactory.apply(String.format("dir%s%s", File.separator, fileName));
    Assert.assertEquals(fileName, dataFile.getName());

    dataFile = dataFileFactory.apply(String.format("..%s%s", File.separator, fileName));
    Assert.assertEquals(fileName, dataFile.getName());

    dataFile = dataFileFactory.apply(String.format("..%s..%sdir%s..%s%s", File.separator, File.separator, File.separator, File.separator, fileName));
    Assert.assertEquals(fileName, dataFile.getName());
  }

}
