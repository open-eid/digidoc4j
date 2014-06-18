package org.digidoc4j;

import org.digidoc4j.api.exceptions.NotYetImplementedException;
import org.junit.Test;

public class BDocContainerTest {

  @Test(expected = NotYetImplementedException.class)
  public void testSave() {
    BDocContainer bDocContainer = new BDocContainer();
    bDocContainer.save("file.bdoc");
  }
}