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

import static org.apache.commons.lang.StringUtils.containsIgnoreCase;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.digidoc4j.impl.ddoc.DDocSignature;
import org.digidoc4j.impl.bdoc.BDocContainer;
import org.digidoc4j.testutils.TestDataBuilder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class ContainerBuilderTest {

  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();

  @Test
  public void buildEmptyContainer() throws Exception {
    ContainerBuilder builder = ContainerBuilder.aContainer();
    Container container = builder.build();
    assertEquals("BDOC", container.getType());
    assertTrue(container.getDataFiles().isEmpty());
    assertTrue(container.getSignatures().isEmpty());
  }

  @Test
  public void buildDDocContainer() throws Exception {
    Container container = ContainerBuilder.
        aContainer().
        withType(ContainerBuilder.DDOC_CONTAINER_TYPE).
        build();
    assertEquals("DDOC", container.getType());
    assertTrue(container.getDataFiles().isEmpty());
    assertTrue(container.getSignatures().isEmpty());
  }

  @Test
  public void buildBDocContainer() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    configuration.setTspSource("test-value");
    Container container = ContainerBuilder.
        aContainer().
        withType(ContainerBuilder.BDOC_CONTAINER_TYPE).
        withConfiguration(configuration).
        build();
    BDocContainer bDocContainer = (BDocContainer) container;
    assertEquals("BDOC", container.getType());
    assertEquals("test-value", bDocContainer.getAsicFacade().getConfiguration().getTspSource());
  }

  @Test
  public void buildBDocContainerWithDataFiles() throws Exception {
    File testFile1 = createTestFile("testFile.txt");
    Container container = ContainerBuilder.
        aContainer().
        withDataFile(testFile1.getPath(), "text/plain").
        withDataFile(new ByteArrayInputStream(new byte[]{1, 2, 3}), "streamFile.txt", "text/plain").
        withDataFile(createTestFile("ExampleFile.txt"), "text/plain").
        build();
    assertEquals(3, container.getDataFiles().size());
    assertEquals("testFile.txt", container.getDataFiles().get(0).getName());
    assertEquals("streamFile.txt", container.getDataFiles().get(1).getName());
    assertEquals("ExampleFile.txt", container.getDataFiles().get(2).getName());
  }

  private File createTestFile(String fileName) throws IOException {
    File testFile1 = testFolder.newFile(fileName);
    FileUtils.writeStringToFile(testFile1, "Banana Pancakes");
    return testFile1;
  }

  @Test
  public void signAndValidateContainer() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile(testFolder);
    TestDataBuilder.signContainer(container);
    ValidationResult result = container.validate();
    assertFalse(result.hasErrors());
    assertFalse(result.hasWarnings());
    assertTrue(result.getContainerErrors().isEmpty());
    assertTrue(result.isValid());
    assertTrue(containsIgnoreCase(result.getReport(), "<Indication>VALID</Indication>"));
  }

  @Test
  public void signAndSaveContainerToFile() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile(testFolder);
    TestDataBuilder.signContainer(container);
    String filePath = testFolder.newFile("test-container.bdoc").getPath();
    File file = container.saveAsFile(filePath);
    assertTrue(FileUtils.sizeOf(file) > 0);
  }

  @Test
  public void signAndSaveContainerToStream() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile(testFolder);
    TestDataBuilder.signContainer(container);
    InputStream stream = container.saveAsStream();
    byte[] bytes = IOUtils.toByteArray(stream);
    assertTrue(bytes.length > 10);
  }

  @Test
  public void signAndSaveDDocContainerToStream() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    File testFile = createTestFile("testFile.txt");
    Container container = ContainerBuilder.
        aContainer().
        withConfiguration(configuration).
        withType(ContainerBuilder.DDOC_CONTAINER_TYPE).
        withDataFile(testFile, "text/plain").
        build();
    TestDataBuilder.signContainer(container, DigestAlgorithm.SHA1);
    InputStream stream = container.saveAsStream();
    byte[] bytes = IOUtils.toByteArray(stream);
    assertTrue(bytes.length > 10);
  }

  @Test
  public void addAndRemoveSignatureFromDDocContainer() throws Exception {
    File testFile = createTestFile("testFile.txt");
    Container container = ContainerBuilder.
        aContainer().
        withConfiguration(new Configuration(Configuration.Mode.TEST)).
        withType(ContainerBuilder.DDOC_CONTAINER_TYPE).
        withDataFile(testFile, "text/plain").
        build();
    DDocSignature signature1 = (DDocSignature) TestDataBuilder.signContainer(container, DigestAlgorithm.SHA1);
    DDocSignature signature2 = (DDocSignature) TestDataBuilder.signContainer(container, DigestAlgorithm.SHA1);
    assertEquals(0, ((DDocSignature) container.getSignatures().get(0)).getIndexInArray());
    assertEquals(1, ((DDocSignature) container.getSignatures().get(1)).getIndexInArray());
    assertEquals(0, signature1.getIndexInArray());
    assertEquals(1, signature2.getIndexInArray());

  }

  @Test
  public void removeSignatureFromSignedContainer() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile(testFolder);
    Signature signature = TestDataBuilder.signContainer(container);
    container.saveAsFile(testFolder.newFile("test-container.bdoc").getPath());
    container.removeSignature(signature);
    assertTrue(container.getSignatures().isEmpty());
  }
}
