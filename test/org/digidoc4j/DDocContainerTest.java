package org.digidoc4j;

import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.junit.Test;

public class DDocContainerTest {

  @Test(expected = DigiDoc4JException.class)
  public void testSaveThrowsException() throws Exception {
    DDocContainer container = new DDocContainer();
    container.save("/not/existing/path/testSaveThrowsException.ddoc");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddDataFileThrowsException() throws Exception {
    DDocContainer container = new DDocContainer();
    container.addDataFile("test.txt", "");
    container.addDataFile("test.txt", "");
  }
}
