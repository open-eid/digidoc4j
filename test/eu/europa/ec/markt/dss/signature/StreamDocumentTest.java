package eu.europa.ec.markt.dss.signature;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import org.apache.commons.io.IOUtils;
import org.digidoc4j.api.DataFile;
import org.junit.Before;
import org.junit.Test;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class StreamDocumentTest {
  StreamDocument document;

  @Before
  public void setUp() {
    ByteArrayInputStream stream = new ByteArrayInputStream(new byte[]{0x041});
    document = new StreamDocument(stream, "suur_a.txt", MimeType.TEXT);
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
    assertEquals("text/plain", document.getMimeType().getCode());
  }

  @Test
  public void setMimeType() throws Exception {
    document.setMimeType(MimeType.XML);
    assertEquals("text/xml", document.getMimeType().getCode());
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
    DataFile dataFile = new DataFile(new ByteArrayInputStream(new byte[]{0x041}), "A.txt", "text/plain");
    StreamDocument streamDocument = new StreamDocument(dataFile.getStream(), dataFile.getFileName(),
        MimeType.fromCode(dataFile.getMediaType()));
    streamDocument.save("createDocumentFromStreamedDataFile.txt");

    assertArrayEquals(new byte[]{0x041},
        IOUtils.toByteArray(new FileInputStream("createDocumentFromStreamedDataFile.txt")));

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
    StreamDocument mockDocument = mock(StreamDocument.class);
    doThrow(new FileNotFoundException()).
        when(mockDocument).getTemporaryFileAsStream();
    when(mockDocument.getBytes()).thenCallRealMethod();
    mockDocument.getBytes();
  }

  @Test(expected = DSSException.class)
  public void testOpenStreamThrowsException() throws Exception {
    StreamDocument mockDocument = mock(StreamDocument.class);
    doThrow(new FileNotFoundException()).
        when(mockDocument).getTemporaryFileAsStream();
    when(mockDocument.openStream()).thenCallRealMethod();
    mockDocument.openStream();
  }

  @Test(expected = DSSException.class)
  public void testGetDigestThrowsException() throws Exception {
    StreamDocument mockDocument = mock(StreamDocument.class);
    doThrow(new FileNotFoundException()).
        when(mockDocument).getTemporaryFileAsStream();
    when(mockDocument.getDigest(DigestAlgorithm.SHA1)).thenCallRealMethod();
    mockDocument.getDigest(DigestAlgorithm.SHA1);
  }

  private class MockInputStream extends InputStream {
    @Override
    public int read() throws IOException {
      throw new IOException();
    }
  }
}