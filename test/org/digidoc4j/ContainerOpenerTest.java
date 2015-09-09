package org.digidoc4j;

import static org.junit.Assert.assertFalse;

import java.io.File;
import java.io.FileInputStream;

import org.apache.commons.io.FileUtils;
import org.junit.Test;

public class ContainerOpenerTest {

  private static final String BDOC_TEST_FILE = "testFiles/asics_for_testing.bdoc";
  private static final String DDOC_TEST_FILE = "testFiles/ddoc_for_testing.ddoc";
  Configuration configuration = new Configuration(Configuration.Mode.TEST);

  @Test
  public void openBDocContainer() throws Exception {
    Container container = ContainerOpener.open(BDOC_TEST_FILE, configuration);
    assertFalse(container.getDataFiles().isEmpty());
    assertFalse(container.getSignatures().isEmpty());
  }

  @Test
  public void openDDocContainer() throws Exception {
    Container container = ContainerOpener.open(DDOC_TEST_FILE, configuration);
    assertFalse(container.getDataFiles().isEmpty());
    assertFalse(container.getSignatures().isEmpty());
  }

  @Test
  public void openBDocContainerAsStream() throws Exception {
    FileInputStream stream = FileUtils.openInputStream(new File(BDOC_TEST_FILE));
    Container container = ContainerOpener.open(stream, configuration);
    assertFalse(container.getDataFiles().isEmpty());
    assertFalse(container.getSignatures().isEmpty());
  }

  @Test
  public void openDDocContainerAsStream() throws Exception {
    FileInputStream stream = FileUtils.openInputStream(new File(DDOC_TEST_FILE));
    Container container = ContainerOpener.open(stream, configuration);
    assertFalse(container.getDataFiles().isEmpty());
    assertFalse(container.getSignatures().isEmpty());
  }

  @Test
  public void openBDocContainerAsStream_WithBigFilesNotSupported() throws Exception {
    boolean bigFilesSupportEnabled = false;
    FileInputStream stream = FileUtils.openInputStream(new File(BDOC_TEST_FILE));
    Container container = ContainerOpener.open(stream, bigFilesSupportEnabled);
    assertFalse(container.getDataFiles().isEmpty());
    assertFalse(container.getSignatures().isEmpty());

  }
}
