package org.digidoc4j.utils;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.signature.MimeType;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

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
    assertEquals("suur_a.txt", document.getAbsolutePath());
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
  }

  @Test
  public void getDigest() throws Exception {
    assertEquals("VZrq0IJk1XldOQlxjN0Fq9SVcuhP5VWQ7vMaiKCP3/0=", document.getDigest(DigestAlgorithm.SHA256));
  }

  @Test (expected = DigiDoc4JException.class)
  public void saveWhenNoAccessRights() throws Exception {
    document.save("/bin/no_access.txt");
  }

  @Test (expected = DigiDoc4JException.class)
  public void name() throws Exception {
    InputStream stream = new MockInputStream();
    document = new StreamDocument(stream, "suur_a.txt", MimeType.TEXT);
    stream.close();

    document.getBytes();
  }

  private class MockInputStream extends InputStream {
    @Override
    public int read() throws IOException {
      throw new IOException();
    }
  }
}