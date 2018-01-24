/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;

import org.apache.commons.io.FileUtils;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.junit.Ignore;
import org.junit.Test;

public class ContainerOpenerTest extends DigiDoc4JTestHelper {

  private static final String BDOC_TEST_FILE = "src/test/resources/testFiles/valid-containers/one_signature.bdoc";
  private static final String DDOC_TEST_FILE = "src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc";
  Configuration configuration = new Configuration(Configuration.Mode.TEST);

  @Test
  public void openBDocContainer() throws Exception {
    Container container = ContainerOpener.open(BDOC_TEST_FILE, configuration);
    assertContainerOpened(container, "BDOC");
  }

  @Test
  public void openDDocContainer() throws Exception {
    Container container = ContainerOpener.open(DDOC_TEST_FILE, configuration);
    assertContainerOpened(container, "DDOC");
  }

  @Test
  public void openBDocContainerAsStream() throws Exception {
    FileInputStream stream = FileUtils.openInputStream(new File(BDOC_TEST_FILE));
    Container container = ContainerOpener.open(stream, configuration);
    assertContainerOpened(container, "BDOC");
  }

  @Test
  public void openDDocContainerAsStream() throws Exception {
    FileInputStream stream = FileUtils.openInputStream(new File(DDOC_TEST_FILE));
    Container container = ContainerOpener.open(stream, configuration);
    assertContainerOpened(container, "DDOC");
  }

  @Test
  public void openBDocContainerAsStream_WithBigFilesNotSupported() throws Exception {
    boolean bigFilesSupportEnabled = false;
    FileInputStream stream = FileUtils.openInputStream(new File(BDOC_TEST_FILE));
    Container container = ContainerOpener.open(stream, bigFilesSupportEnabled);
    assertContainerOpened(container, "BDOC");
  }

  private void assertContainerOpened(Container container, String containerType) {
    assertEquals(containerType, container.getType());
    assertFalse(container.getDataFiles().isEmpty());
    assertFalse(container.getSignatures().isEmpty());
  }

  @Test
  public void testErrorTextDDOCInvalidFileFormat(){
    try {
      Container container = ContainerBuilder.
          aContainer().
          fromExistingFile("src/test/resources/testFiles/invalid-containers/error75.ddoc").
          build();

    } catch (DigiDoc4JException e){
      assertTrue( e.getMessage().contains("Invalid input file format."));
    }
  }

  @Test
  public void testErrorText75NotChanged(){
    try {
      Container container = ContainerBuilder.
          aContainer().
          fromExistingFile("src/test/resources/testFiles/invalid-containers/23181_SignedInfo_topelt_D1_lisatud.ddoc").
          build();

    } catch (DigiDoc4JException e){
      assertTrue( e.getMessage().contains("Multiple elements: SignatureValue not allowed under: Signature"));
    }
  }

  @Test
  public void testErrorText75ChangedAndNullPointer(){
    try {
      Container container = ContainerBuilder.
          aContainer().
          fromExistingFile("src/test/resources/testFiles/invalid-containers/23133_ddoc-12.ddoc").
          build();
    } catch (DigiDoc4JException e){
      assertTrue( e.getMessage().contains("Invalid input file format."));
    }
  }

  @Test
  @Ignore("TODO: solve anomaly where results are different")
  public void testErrorText75NotChangedInvalidXmlElement(){
    try {
      Container container = ContainerBuilder.
          aContainer().
          fromExistingFile("src/test/resources/testFiles/invalid-containers/BOF.ddoc").
          build();

    } catch (DigiDoc4JException e){
      assertTrue( e.getMessage().contains("Invalid xml element"));
    }
  }
}