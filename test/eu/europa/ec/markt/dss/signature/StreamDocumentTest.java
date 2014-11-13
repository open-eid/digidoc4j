package eu.europa.ec.markt.dss.signature;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import org.apache.commons.io.IOUtils;
import org.digidoc4j.DataFile;
import org.digidoc4j.utils.Helper;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.Test;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.Assert.*;

public class StreamDocumentTest {
  StreamDocument document;

  @Before
  public void setUp() throws IOException {
    try(ByteArrayInputStream stream = new ByteArrayInputStream(new byte[]{0x041})) {
      document = new StreamDocument(stream, "suur_a.txt", MimeType.TEXT);
    }
  }

  @AfterClass
  public static void deleteTemporaryFiles() throws IOException {
    Helper.deleteFile("createDocumentFromStreamedDataFile.txt");
  }

  @Test
  public void openStream() throws Exception {
    assertEquals(65, document.openStream().read());
  }

  @Test
  public void getBytes() throws Exception {
    assertArrayEquals(new byte[]{0x041}, document.getBytes());
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
    try(ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(new byte[]{0x041})) {
      DataFile dataFile = new DataFile(byteArrayInputStream, "A.txt", "text/plain");
      StreamDocument streamDocument = new StreamDocument(dataFile.getStream(),
          dataFile.getName(),
          MimeType.fromMimeTypeString(dataFile.getMediaType()));

      streamDocument.save("createDocumentFromStreamedDataFile.txt");
    }

    try(FileInputStream fileInputStream = new FileInputStream("createDocumentFromStreamedDataFile.txt")) {
      assertArrayEquals(new byte[]{0x041}, IOUtils.toByteArray(fileInputStream));
    }

    Files.deleteIfExists(Paths.get("createDocumentFromStreamedDataFile.txt"));
  }

  @Test
  public void getDigest() throws Exception {
    assertEquals("VZrq0IJk1XldOQlxjN0Fq9SVcuhP5VWQ7vMaiKCP3/0=", document.getDigest(DigestAlgorithm.SHA256));
  }

  @Test(expected = DSSException.class)
  public void saveWhenNoAccessRights() throws Exception {
    document.save("/bin/no_access.txt");
  }

  @Test(expected = DSSException.class)
  public void constructorThrowsException() throws Exception {
    InputStream stream = new MockInputStream();
    document = new StreamDocument(stream, "suur_a.txt", MimeType.TEXT);
    stream.close();

    document.getBytes();
  }

  @Test(expected = DSSException.class)
  public void testGetBytesThrowsException() throws Exception {
    StreamDocument mockDocument = new MockStreamDocument();
    mockDocument.getBytes();
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