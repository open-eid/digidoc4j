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

import org.apache.commons.io.IOUtils;
import org.digidoc4j.DataFile;
import org.digidoc4j.impl.StreamDocument;
import org.digidoc4j.utils.Helper;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.*;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.MimeType;

public class StreamDocumentTest {
  StreamDocument document;

  @BeforeClass
  public static void setUpDir() throws IOException {
    if (Files.isWritable(Paths.get("src/test/resources/testFiles/tmp/readonly"))) {
      // setting directory testFiles/tmp/readonly permissions to "read only"
      if (System.getProperty("os.name").startsWith("Windows")) {
        File file = new File("src/test/resources/testFiles/tmp/readonly");
        // deny write permission for all the users
        System.out.println("icacls "+file.getAbsolutePath()+" /deny Everyone:(WD,WA) /T /Q");
        Runtime.getRuntime().exec("icacls "+file.getAbsolutePath()+" /deny Everyone:(WD,WA) /T /Q");
      } else {
        Set<PosixFilePermission> perms = new HashSet<PosixFilePermission>();
        //add owners permission
        perms.add(PosixFilePermission.OWNER_READ);
        perms.add(PosixFilePermission.OWNER_EXECUTE);
        //add group permissions
        perms.add(PosixFilePermission.GROUP_READ);
        perms.add(PosixFilePermission.GROUP_EXECUTE);
        //add others permissions
        perms.add(PosixFilePermission.OTHERS_READ);
        perms.add(PosixFilePermission.OTHERS_EXECUTE);
        Files.setPosixFilePermissions(Paths.get("src/test/resources/testFiles/tmp/readonly"), perms);
      }
    }
  }

  @Before
  public void setUp() throws IOException {
    try(ByteArrayInputStream stream = new ByteArrayInputStream(new byte[]{0x041})) {
      document = new StreamDocument(stream, "suur_a.txt", MimeType.TEXT);
    }
  }

  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();

  @AfterClass
  public static void resetTemporaryRODir() throws IOException {
    if (System.getProperty("os.name").startsWith("Windows")) {
      File file = new File("src/test/resources/testFiles/tmp/readonly");
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
      Files.setPosixFilePermissions(Paths.get("src/test/resources/testFiles/tmp/readonly"), perms);
    }
  }

  @Test
  public void openStream() throws Exception {
    assertEquals(65, document.openStream().read());
  }

  @Test
  public void getName() throws Exception {
    assertEquals("suur_a.txt", document.getName());
  }

  @Test
  public void getAbsolutePath() throws Exception {
    assertTrue(document.getAbsolutePath().matches(".*digidoc4j.*.\\.tmp"));
  }

  @Test
  public void getMimeType() throws Exception {
    assertEquals("text/plain", document.getMimeType().getMimeTypeString());
  }

  @Test
  public void setMimeType() throws Exception {
    document.setMimeType(MimeType.XML);
    assertEquals("text/xml", document.getMimeType().getMimeTypeString());
  }

  @Test
  public void save() throws Exception {
    document.save("streamDocumentSaveTest.txt");
    assertTrue(Files.exists(Paths.get("streamDocumentSaveTest.txt")));

    FileReader fileReader = new FileReader("streamDocumentSaveTest.txt");
    int read = fileReader.read();
    fileReader.close();

    assertEquals(65, read);
    Files.deleteIfExists(Paths.get("streamDocumentSaveTest.txt"));
  }

  @Test
  public void createDocumentFromStreamedDataFile() throws Exception {
    String dataFileName = testFolder.newFolder().getAbsolutePath()+ File.separator + "createDocumentFromStreamedDataFile.txt";
    try(ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(new byte[]{0x041})) {
      DataFile dataFile = new DataFile(byteArrayInputStream, dataFileName, "text/plain");
      StreamDocument streamDocument = new StreamDocument(dataFile.getStream(),
          dataFile.getName(),
          MimeType.fromMimeTypeString(dataFile.getMediaType()));

      streamDocument.save(dataFileName);
    }

    try(FileInputStream fileInputStream = new FileInputStream(dataFileName)) {
      assertArrayEquals(new byte[]{0x041}, IOUtils.toByteArray(fileInputStream));
    }
    testFolder.delete();
  }

  @Test
  public void getDigest() throws Exception {
    assertEquals("VZrq0IJk1XldOQlxjN0Fq9SVcuhP5VWQ7vMaiKCP3/0=", document.getDigest(DigestAlgorithm.SHA256));
  }

  /*
    NB! If this test fails then ensure that directory testFiles/tmp/readonly is read-only!
   */
  @Test(expected = DSSException.class)
  public void saveWhenNoAccessRights() throws Exception {
    String tmpFolder = "src/test/resources/testFiles/tmp/readonly";
    File tmp = new File(tmpFolder);
    String dataFileName = tmp.getAbsolutePath() + File.separator + "no_access.txt";
    Assert.assertTrue("Invalid directory " + tmpFolder, tmp.isDirectory() && tmp.exists());
    document.save(dataFileName);
  }

  @Test(expected = DSSException.class)
  public void constructorThrowsException() throws Exception {
    InputStream stream = new MockInputStream();
    document = new StreamDocument(stream, "suur_a.txt", MimeType.TEXT);
    stream.close();

    document.openStream();
  }

  @Test(expected = DSSException.class)
  public void testGetBytesThrowsException() throws Exception {
    StreamDocument mockDocument = new MockStreamDocument();
    mockDocument.openStream();
  }

  @Test(expected = DSSException.class)
  public void testOpenStreamThrowsException() throws Exception {
    StreamDocument mockDocument = new MockStreamDocument();
    mockDocument.openStream();
  }

  @Test(expected = DSSException.class)
  public void testGetDigestThrowsException() throws Exception {
    StreamDocument mockDocument = new MockStreamDocument();
    mockDocument.getDigest(DigestAlgorithm.SHA1);
  }

  private class MockInputStream extends InputStream {
    @Override
    public int read() throws IOException {
      throw new IOException();
    }
  }

  private class MockStreamDocument extends StreamDocument {
    public MockStreamDocument() {
      super(new ByteArrayInputStream(new byte[]{0x041}), "fileName.txt", MimeType.TEXT);
    }

    @Override
    FileInputStream getTemporaryFileAsStream() throws FileNotFoundException {
      throw new FileNotFoundException("File not found (mock)");
    }
  }
}
