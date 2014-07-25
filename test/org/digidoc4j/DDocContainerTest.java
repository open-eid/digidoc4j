package org.digidoc4j;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.junit.Ignore;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.util.ArrayList;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

public class DDocContainerTest {
  public static final String TEXT_MIME_TYPE = "text/plain";

  @Test(expected = DigiDoc4JException.class)
  public void testSaveThrowsException() throws Exception {
    DDocContainer container = new DDocContainer();
    container.save("/not/existing/path/testSaveThrowsException.ddoc");
  }

  @Test(expected = DigiDoc4JException.class)
  @Ignore
  public void testAddingTwoDataFilesWithSameNameThrowsException() throws Exception {
    DDocContainer container = new DDocContainer();
    container.addDataFile("testFiles/test.txt", "");
    container.addDataFile("testFiles/test.txt", "");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddFileFromStreamToDDocThrowsException() throws DigiDocException {
    SignedDoc ddoc = mock(SignedDoc.class);
    when(ddoc.getNewDataFileId()).thenReturn("A");
    when(ddoc.getFormat()).thenReturn("SignedDoc.FORMAT_DDOC");
    doThrow(new DigiDocException(100, "testException", new Throwable("test Exception"))).
        when(ddoc).addDataFile(any(ee.sk.digidoc.DataFile.class));

    DDocContainer container = new DDocContainer(ddoc);
    container.addDataFile(new ByteArrayInputStream(new byte[]{0x42}), "testFromStream.txt", TEXT_MIME_TYPE);
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddDataFileThrowsException() throws Exception {
    SignedDoc ddoc = mock(SignedDoc.class);
    doThrow(new DigiDocException(100, "testException", new Throwable("test Exception"))).
        when(ddoc).addDataFile(any(File.class), any(String.class), any(String.class));

    DDocContainer container = new DDocContainer(ddoc);
    container.addDataFile("testFiles/test.txt", "");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testGetDataFileThrowsException() throws Exception {
    SignedDoc ddoc = spy(new SignedDoc("DIGIDOC-XML", "1.3"));

    ee.sk.digidoc.DataFile dataFile = mock(ee.sk.digidoc.DataFile.class);
    doThrow(new DigiDocException(100, "testException", new Throwable("test Exception"))).
        when(dataFile).getBody();
    ArrayList mockedDataFiles = new ArrayList();
    mockedDataFiles.add(dataFile);
    doReturn(mockedDataFiles).when(ddoc).getDataFiles();

    DDocContainer container = new DDocContainer(ddoc);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.getDataFiles();
  }
}
