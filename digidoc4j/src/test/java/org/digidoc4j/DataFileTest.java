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

  private DataFile dataFile;

  @Test
  public void testGetFileSize() throws Exception {
    Assert.assertEquals(15, this.dataFile.getFileSize());
  }

  @Test
  public void testGetFileSizeForInMemoryDocument() {
    Assert.assertEquals(2, new DataFile(new byte[]{1, 2}, "fileName", "text/plain").getFileSize());
  }

  @Test
  public void testGetMediaType() throws Exception {
    Assert.assertEquals("text/plain", this.dataFile.getMediaType());
  }

  @Test
  public void testGetFileName() throws Exception {
    Assert.assertEquals("test.txt", this.dataFile.getName());
  }

  @Test
  public void testCalculateDigest() throws Exception {
    Assert.assertEquals("RqDqtqi3rTsWj07rrWc5kATAZIw7T1XHP/NPLCF05RU=", Base64.encodeBase64String(this.dataFile.calculateDigest()));
  }

  @Test
  public void testCalculateDigestWithEnumTypeSHA256() throws Exception {
    Assert.assertEquals("RqDqtqi3rTsWj07rrWc5kATAZIw7T1XHP/NPLCF05RU=",
        Base64.encodeBase64String(this.dataFile.calculateDigest(DigestAlgorithm.SHA256)));
  }

  @Test
  public void testCalculateDigestWithEnumTypeSHA1() throws Exception {
    Assert.assertEquals("OQj17m9Rt2vPXYrry+v/KHpf98Q=", Base64.encodeBase64String(this.dataFile.calculateDigest(DigestAlgorithm.SHA1)));
  }

  @Test
  public void testSaveToFile() throws IOException {
    String file = this.getFileBy("txt");
    this.dataFile.saveAs(file);
    Assert.assertTrue(new File(file).exists());
    byte[] testFileContent = FileUtils.readFileToByteArray(new File("src/test/resources/testFiles/helper-files/test.txt"));
    byte[] savedFileContent = FileUtils.readFileToByteArray(new File(file));
    Assert.assertArrayEquals(testFileContent, savedFileContent);
  }

  @Test
  public void testSaveToOutputStream() throws IOException {
    try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
      this.dataFile.saveAs(stream);
      stream.flush();
      Assert.assertEquals("see on testfail", stream.toString());
    }
  }

  @Test
  public void incorrectMimeType() {
    this.dataFile = new DataFile("src/test/resources/testFiles/helper-files/test.txt", "incorrect");
    Assert.assertNotNull(this.dataFile.getMediaType());
  }

  @Test
  public void incorrectMimeTypeByteArrayConstructor() {
    this.dataFile = new DataFile(new byte[]{0x041}, "src/test/resources/testFiles/helper-files/test.txt", "incorrect");
    Assert.assertNotNull(this.dataFile.getMediaType());
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
      this.dataFile = new DataFile(stream, "test.txt", "unknown");
      Assert.assertNotNull(this.dataFile.getMediaType());
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
    byte[] digest = this.dataFile.calculateDigest();
    Assert.assertEquals(digest, this.dataFile.calculateDigest(new URL("http://NonExisting.test")));
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.dataFile = new DataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
  }

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
