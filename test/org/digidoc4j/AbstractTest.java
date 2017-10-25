package org.digidoc4j;

import org.junit.After;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

public abstract class AbstractTest {

  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();

  @After
  public void tearDown() {
    System.clearProperty("digidoc4j.mode");
  }

}
