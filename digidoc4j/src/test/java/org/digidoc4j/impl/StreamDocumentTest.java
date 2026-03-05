/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import org.apache.commons.io.IOUtils;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.DataFile;
import org.digidoc4j.test.MockStreamDocument;
import org.digidoc4j.utils.Helper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StreamDocumentTest extends AbstractTest {

  private static final Logger logger = LoggerFactory.getLogger(StreamDocumentTest.class);
  private static Path readOnlyPath;
  private StreamDocument document;

  @BeforeAll
   static void beforeClass(@TempDir Path tempDir) throws IOException {
    readOnlyPath = tempDir.resolve("readOnly");
    Files.createDirectories(readOnlyPath);

    if (Files.isWritable(StreamDocumentTest.readOnlyPath)) {
      // setting directory testFiles/tmp/readonly permissions to "read only"
      if (System.getProperty("os.name").startsWith("Windows")) {
        // deny write permission for all the users
        String command = String.format("icacls %s /deny Everyone:(WD,WA) /T /Q", StreamDocumentTest.readOnlyPath.toFile().getAbsolutePath());
        logger.debug(command);
        Runtime.getRuntime().exec(command);
      } else {
        Set<PosixFilePermission> perms = new HashSet<>();
        //add owners permission
        perms.add(PosixFilePermission.OWNER_READ);
        perms.add(PosixFilePermission.OWNER_EXECUTE);
        //add group permissions
        perms.add(PosixFilePermission.GROUP_READ);
        perms.add(PosixFilePermission.GROUP_EXECUTE);
        //add others permissions
        perms.add(PosixFilePermission.OTHERS_READ);
        perms.add(PosixFilePermission.OTHERS_EXECUTE);
        Files.setPosixFilePermissions(StreamDocumentTest.readOnlyPath, perms);
      }
    }
  }

  /*@AfterClass
   static void resetTemporaryRODir() throws IOException {
    if (System.getProperty("os.name").startsWith("Windows")) {
      File file = new File(roDir);
      Runtime.getRuntime().exec("icacls " + file.getAbsolutePath() + " /remove:d Everyone /T /Q");
    } else {
      Set<PosixFilePermission> perms = new HashSet<PosixFilePermission>();
      //add owners permission
      perms.add(PosixFilePermission.OWNER_READ);
      perms.add(PosixFilePermission.OWNER_WRITE);
      perms.add(PosixFilePermission.OWNER_EXECUTE);
      //add group permissions
      perms.add(PosixFilePermission.GROUP_READ);
      perms.add(PosixFilePermission.GROUP_WRITE);
      perms.add(PosixFilePermission.GROUP_EXECUTE);
      //add others permissions
      perms.add(PosixFilePermission.OTHERS_READ);
      perms.add(PosixFilePermission.OTHERS_WRITE);
      perms.add(PosixFilePermission.OTHERS_EXECUTE);
      Files.setPosixFilePermissions(Paths.get(roDir), perms);
    }
  }*/

  @Test
   void openStream() throws Exception {
    assertEquals(65, document.openStream().read());
  }

  @Test
   void getName() throws Exception {
    assertEquals("suur_a.txt", document.getName());
  }

  @Test
   void getAbsolutePath() {
    assertTrue(document.temporaryFile.getAbsolutePath().matches(".*digidoc4j.*.\\.tmp"), document.temporaryFile.getAbsolutePath());
  }

  @Test
   void getMimeType() {
    assertEquals("text/plain", document.getMimeType().getMimeTypeString());
  }

  @Test
   void setMimeType() {
    document.setMimeType(MimeTypeEnum.XML);
    assertEquals("text/xml", document.getMimeType().getMimeTypeString());
  }

  @Test
   void save() throws Exception {
    document.save("streamDocumentSaveTest.txt");
    assertTrue(Files.exists(Paths.get("streamDocumentSaveTest.txt")));
    FileReader fileReader = new FileReader("streamDocumentSaveTest.txt");
    int read = fileReader.read();
    fileReader.close();
    assertEquals(65, read);
    Files.deleteIfExists(Paths.get("streamDocumentSaveTest.txt"));
  }

  @Test
   void createDocumentFromStreamedDataFile() throws Exception {
    String file = getFileBy("txt");
    try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(new byte[]{0x041})) {
      DataFile dataFile = new DataFile(byteArrayInputStream, file, "text/plain");
      StreamDocument streamDocument = new StreamDocument(dataFile.getStream(),
          dataFile.getName(),
          MimeType.fromMimeTypeString(dataFile.getMediaType()));
      streamDocument.save(file);
    }
    try (FileInputStream fileInputStream = new FileInputStream(file)) {
      assertArrayEquals(new byte[]{0x041}, IOUtils.toByteArray(fileInputStream));
    }
  }

  @Test
   void documentManualDeletion() {
    File dir = new File(System.getProperty("java.io.tmpdir"));
    FilenameFilter filenameFilter = (dir1, name) -> name.toLowerCase().startsWith("digidoc4j")
        && name.toLowerCase().endsWith(".tmp");
    Helper.deleteTmpFiles(10000000);
    int count = dir.listFiles(filenameFilter).length;
    assertTrue(count >= 1);
    Helper.deleteTmpFiles(0);
    count = dir.listFiles(filenameFilter).length;
    assertEquals(0, count);
  }

  @Test
   void getDigest_WhenAlgorithmIsSha256_ReturnsSha256DigestWithExpectedBase64Value() {
    Digest result = document.getDigest(DigestAlgorithm.SHA256);

    assertThat(result, notNullValue());
    assertThat(result.getAlgorithm(), sameInstance(DigestAlgorithm.SHA256));
    assertThat(result.getBase64Value(), equalTo("VZrq0IJk1XldOQlxjN0Fq9SVcuhP5VWQ7vMaiKCP3/0="));
  }

  /*
    NB! If this test fails then ensure that directory testFiles/tmp/readonly is read-only!
   */
  @Test
   void saveWhenNoAccessRights() {
    File tmp = StreamDocumentTest.readOnlyPath.toFile();
    String dataFileName = tmp.getAbsolutePath() + File.separator + "no_access.txt";

    assertTrue(tmp.isDirectory() && tmp.exists(), "Invalid directory " + StreamDocumentTest.readOnlyPath);
    assertThrows(
            FileNotFoundException.class,
            () -> document.save(dataFileName)
    );
  }

  @Test
  void constructorThrowsException() {
    InputStream stream = new InputStream() {

      @Override
      public int read() throws IOException {
        throw new IOException();
      }

    };

    assertThrows(
            DSSException.class,
            () -> new StreamDocument(stream, "suur_a.txt", MimeTypeEnum.TEXT)
    );
  }

  @Test
   void testGetBytesThrowsException() {
    assertThrows(DSSException.class, () -> new MockStreamDocument().openStream());
  }

  @Test
   void testOpenStreamThrowsException() {
    assertThrows(DSSException.class, () -> new MockStreamDocument().openStream());
  }

  @Test
   void testGetDigestThrowsException() {
    assertThrows(DSSException.class, () -> new MockStreamDocument().getDigest(DigestAlgorithm.SHA1));
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    try (ByteArrayInputStream stream = new ByteArrayInputStream(new byte[]{0x041})) {
      document = new StreamDocument(stream, "suur_a.txt", MimeTypeEnum.TEXT);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

}
