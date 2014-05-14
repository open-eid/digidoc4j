package ee.sk.digidoc4j;

import ee.sk.digidoc4j.exceptions.NotYetImplementedException;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class ContainerTest {
  @Test
  public void testAddOneFileToContainer() throws Exception {
    Container bDocContainer = new Container();
    bDocContainer.addDataFile("test.txt", "text/plain");
    List<DataFile> dataFiles = bDocContainer.getDataFiles();
    assertEquals(1, dataFiles.size());
    assertEquals("test.txt", dataFiles.get(0).getFileName());
    assertEquals("text/plain", dataFiles.get(0).getMediaType());
  }

  @Test(expected = NotYetImplementedException.class)
  public void testAddDataFileFromInputStreamToContainer() throws Exception {
    Container container = new Container();
    container.addDataFile(new ByteArrayInputStream(new byte[]{0x41}), "test.txt", "text/plain");
  }

  @Test
  public void testRemovesOneFileFromContainerWhenFileExists() throws Exception {
    Container bDocContainer = new Container();
    bDocContainer.addDataFile("test.txt", "text/plain");
    bDocContainer.removeDataFile("test.txt");

    assertEquals(0, bDocContainer.getDataFiles().size());
  }
}
