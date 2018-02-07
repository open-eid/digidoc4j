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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.io.IOUtils;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.DataFile;
import org.digidoc4j.test.MockStreamDocument;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.MimeType;

public class StreamDocumentTest extends AbstractTest {

  private static final Logger logger = LoggerFactory.getLogger(StreamDocumentTest.class);
  private static final Path readOnlyPath = Paths.get("target/tmp/readOnly");
  private StreamDocument document;

  @BeforeClass
  public static void beforeClass() throws IOException {
    if (!Files.exists(StreamDocumentTest.readOnlyPath)) {
      Files.createDirectory(StreamDocumentTest.readOnlyPath);
    }
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
  public static void resetTemporaryRODir() throws IOException {
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
  public void openStream() throws Exception {
    Assert.assertEquals(65, this.document.openStream().read());
  }

  @Test
  public void getName() throws Exception {
    Assert.assertEquals("suur_a.txt", this.document.getName());
  }

  @Test
  public void getAbsolutePath() throws Exception {
    Assert.assertTrue(this.document.getAbsolutePath(), this.document.getAbsolutePath().matches(".*digidoc4j.*.\\.tmp"));
  }

  @Test
  public void getMimeType() throws Exception {
    Assert.assertEquals("text/plain", this.document.getMimeType().getMimeTypeString());
  }

  @Test
  public void setMimeType() throws Exception {
    this.document.setMimeType(MimeType.XML);
    Assert.assertEquals("text/xml", this.document.getMimeType().getMimeTypeString());
  }

  @Test
  public void save() throws Exception {
    this.document.save("streamDocumentSaveTest.txt");
    Assert.assertTrue(Files.exists(Paths.get("streamDocumentSaveTest.txt")));
    FileReader fileReader = new FileReader("streamDocumentSaveTest.txt");
    int read = fileReader.read();
    fileReader.close();
    Assert.assertEquals(65, read);
    Files.deleteIfExists(Paths.get("streamDocumentSaveTest.txt"));
  }

  @Test
  public void createDocumentFromStreamedDataFile() throws Exception {
    String file = this.getFileBy("txt");
    try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(new byte[]{0x041})) {
      DataFile dataFile = new DataFile(byteArrayInputStream, file, "text/plain");
      StreamDocument streamDocument = new StreamDocument(dataFile.getStream(),
          dataFile.getName(),
          MimeType.fromMimeTypeString(dataFile.getMediaType()));
      streamDocument.save(file);
    }
    try (FileInputStream fileInputStream = new FileInputStream(file)) {
      Assert.assertArrayEquals(new byte[]{0x041}, IOUtils.toByteArray(fileInputStream));
    }
  }

  @Test
  public void getDigest() throws Exception {
    Assert.assertEquals("VZrq0IJk1XldOQlxjN0Fq9SVcuhP5VWQ7vMaiKCP3/0=", document.getDigest(DigestAlgorithm.SHA256));
  }

  /*
    NB! If this test fails then ensure that directory testFiles/tmp/readonly is read-only!
   */
  @Test(expected = DSSException.class)
  public void saveWhenNoAccessRights() throws Exception {
    File tmp = StreamDocumentTest.readOnlyPath.toFile();
    String dataFileName = tmp.getAbsolutePath() + File.separator + "no_access.txt";
    Assert.assertTrue("Invalid directory " + StreamDocumentTest.readOnlyPath, tmp.isDirectory() && tmp.exists());
    this.document.save(dataFileName);
  }

  @Test(expected = DSSException.class)
  public void constructorThrowsException() throws Exception {
    InputStream stream = new InputStream() {

      @Override
      public int read() throws IOException {
        throw new IOException();
      }

    };
    this.document = new StreamDocument(stream, "suur_a.txt", MimeType.TEXT);
    stream.close();
    this.document.openStream();
  }

  @Test(expected = DSSException.class)
  public void testGetBytesThrowsException() throws Exception {
    new MockStreamDocument().openStream();
  }

  @Test(expected = DSSException.class)
  public void testOpenStreamThrowsException() throws Exception {
    new MockStreamDocument().openStream();
  }

  @Test(expected = DSSException.class)
  public void testGetDigestThrowsException() throws Exception {
    new MockStreamDocument().getDigest(DigestAlgorithm.SHA1);
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    try (ByteArrayInputStream stream = new ByteArrayInputStream(new byte[]{0x041})) {
      this.document = new StreamDocument(stream, "suur_a.txt", MimeType.TEXT);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

}
