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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.util.zip.ZipFile;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.exceptions.InvalidDataFileException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.impl.asic.asice.AsicEContainer;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainer;
import org.digidoc4j.impl.ddoc.DDocContainer;
import org.digidoc4j.test.CustomConfiguration;
import org.digidoc4j.test.CustomContainer;
import org.digidoc4j.test.TestAssert;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

public class ContainerBuilderTest extends AbstractTest {

  private static final String BDOC_TEST_FILE = "src/test/resources/testFiles/valid-containers/one_signature.bdoc";
  private static final String DDOC_TEST_FILE = "src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc";

  @Test
  public void buildEmptyContainer() throws Exception {
    ContainerBuilder builder = ContainerBuilder.aContainer();
    Container container = builder.build();
    Assert.assertEquals("BDOC", container.getType());
    Assert.assertTrue(container.getDataFiles().isEmpty());
    Assert.assertTrue(container.getSignatures().isEmpty());
  }

  @Test(expected = NotSupportedException.class)
  public void buildEmptyDDocContainer() throws Exception {
    ContainerBuilder.aContainer(Container.DocumentType.DDOC).build();
  }

  @Test
  public void buildBDocContainer() throws Exception {
    this.configuration = new Configuration(Configuration.Mode.TEST);
    this.configuration.setTspSource("test-value");
    Container container = ContainerBuilder.aContainer().withConfiguration(this.configuration).build();
    BDocContainer bDocContainer = (BDocContainer) container;
    Assert.assertEquals("BDOC", container.getType());
    Assert.assertEquals("test-value", bDocContainer.getConfiguration().getTspSource());
  }

  @Test
  public void buildBDocContainerWithDataFiles() throws Exception {
    File testFile1 = this.createTemporaryFileBy("testFile.txt", "TEST");
    File testFile2 = this.createTemporaryFileBy("testFile2.txt", "TEST");
    LargeDataFile largeDataFile = new LargeDataFile(new ByteArrayInputStream(new byte[]{1, 2, 3}), "largeStreamFile.txt", "text/plain");
    Container container = ContainerBuilder.aContainer().withDataFile(testFile1.getPath(), "text/plain").
        withDataFile(new ByteArrayInputStream(new byte[]{1, 2, 3}), "streamFile.txt", "text/plain").
        withDataFile(this.createTemporaryFileBy("ExampleFile.txt", "TEST"), "text/plain").
        withDataFile(new DataFile(testFile2.getPath(), "text/plain")).withDataFile(largeDataFile).build();
    Assert.assertEquals(5, container.getDataFiles().size());
    Assert.assertEquals("testFile.txt", container.getDataFiles().get(0).getName());
    Assert.assertEquals("streamFile.txt", container.getDataFiles().get(1).getName());
    Assert.assertEquals("ExampleFile.txt", container.getDataFiles().get(2).getName());
    Assert.assertEquals("testFile2.txt", container.getDataFiles().get(3).getName());
    Assert.assertEquals("largeStreamFile.txt", container.getDataFiles().get(4).getName());
  }

  @Test(expected = InvalidDataFileException.class)
  public void buildContainer_withNullFilePath_shouldThrowException() throws Exception {
    ContainerBuilder.aContainer().withDataFile((String) null, "text/plain").build();
  }

  @Test(expected = InvalidDataFileException.class)
  public void buildContainer_withStreamDocAndNullFileName_shouldThrowException() throws Exception {
    ContainerBuilder.aContainer().withDataFile(new ByteArrayInputStream(new byte[]{1, 2, 3}), null, "text/plain").
        build();
  }

  @Test(expected = InvalidDataFileException.class)
  public void buildContainer_withNullMimeType_shouldThrowException() throws Exception {
    ContainerBuilder.aContainer().withDataFile("testFile.txt", null).build();
  }

  @Test(expected = InvalidDataFileException.class)
  public void buildContainer_withInvalidMimeType_shouldThrowException() throws Exception {
    ContainerBuilder.aContainer().
        withDataFile("src/test/resources/testFiles/helper-files/test.txt", "application\\rtf").build();
  }

  @Test
  public void signAndValidateContainer() throws Exception {
    Container container = this.createNonEmptyContainer();
    TestDataBuilderUtil.signContainer(container);
    ContainerValidationResult result = container.validate();
    Assert.assertTrue(result.isValid());
    Assert.assertFalse(result.hasWarnings());
    Assert.assertTrue(result.getContainerErrors().isEmpty());
    Assert.assertTrue(result.isValid());
    Assert.assertTrue(StringUtils.containsIgnoreCase(result.getReport(), "<Indication>TOTAL_PASSED</Indication>"));
  }

  @Test
  public void saveContainerWithoutSignaturesToFile() throws Exception {
    File dataFile = TestDataBuilderUtil.createTestFile(testFolder);
    Container container = TestDataBuilderUtil.createContainerWithFile(dataFile.getPath());
    String filePath = testFolder.newFile("test-container.bdoc").getPath();
    File containerFile = container.saveAsFile(filePath);
    Assert.assertTrue(FileUtils.sizeOf(containerFile) > 0);
    ZipFile zip = new ZipFile(filePath);
    Assert.assertNotNull(zip.getEntry("mimetype"));
    Assert.assertNotNull(zip.getEntry("META-INF/manifest.xml"));
    Assert.assertNotNull(zip.getEntry(dataFile.getName()));
  }

  @Test
  public void signAndSaveContainerToFile() throws Exception {
    Container container = this.createNonEmptyContainer();
    TestDataBuilderUtil.signContainer(container);
    Assert.assertEquals(1, container.getSignatures().size());
    String filePath = testFolder.newFile("test-container.bdoc").getPath();
    File file = container.saveAsFile(filePath);
    Assert.assertTrue(FileUtils.sizeOf(file) > 0);
    ZipFile zip = new ZipFile(filePath);
    Assert.assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
  }

  @Test
  public void signAndSaveContainerToStream() throws Exception {
    Container container = this.createNonEmptyContainer();
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    try (InputStream stream = container.saveAsStream()) {
      byte[] bytes = IOUtils.toByteArray(stream);
      Assert.assertTrue(bytes.length > 10);
    }
  }

  @Test
  public void removeSignatureFromSignedContainer() throws Exception {
    Container container = TestDataBuilderUtil.createContainerWithFile(testFolder);
    Signature signature = TestDataBuilderUtil.signContainer(container);
    container.saveAsFile(this.getFileBy("bdoc"));
    container.removeSignature(signature);
    Assert.assertTrue(container.getSignatures().isEmpty());
  }

  @Test
  public void buildCustomContainerWithCustomImplementation() throws Exception {
    ContainerBuilder.setContainerImplementation("TEST-FORMAT", CustomContainer.class);
    Container container = ContainerBuilder.aContainer("TEST-FORMAT").build();
    Assert.assertEquals("TEST-FORMAT", container.getType());
  }

  @Test
  public void overrideExistingBDocContainerImplementation() throws Exception {
    ContainerBuilder.setContainerImplementation("BDOC", CustomContainer.class);
    Container container = ContainerBuilder.aContainer().build();
    Assert.assertEquals("TEST-FORMAT", container.getType());
  }

  @Ignore
  @Test
  public void useExtendedBDocContainerImplementation() throws Exception {
    ContainerBuilder.setContainerImplementation("BDOC", BDocContainer.class);
    Container container = ContainerBuilder.
        aContainer("BDOC").
        build();
    Assert.assertEquals("BDOC-EXTENDED", container.getType());
  }

  @Test
  public void clearCustomContainerImplementations_shouldUseDefaultContainerImplementation() throws Exception {
    ContainerBuilder.setContainerImplementation("BDOC", BDocContainer.class);
    ContainerBuilder.removeCustomContainerImplementations();
    Container container = ContainerBuilder.aContainer().build();
    Assert.assertEquals("BDOC", container.getType());
  }

  @Test
  public void createCustomContainerWithConfiguration() throws Exception {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    ContainerBuilder.setContainerImplementation("TEST-FORMAT", CustomContainer.class);
    Container container = ContainerBuilder.aContainer("TEST-FORMAT").
        withConfiguration(this.configuration).build();
    Assert.assertEquals("TEST-FORMAT", container.getType());
    Assert.assertSame(this.configuration, ((CustomContainer) container).getConfiguration());
  }

  @Test
  public void createCustomContainerWithCustomConfiguration() throws Exception {
    ContainerBuilder.setContainerImplementation("TEST-FORMAT", CustomContainer.class);
    CustomConfiguration configuration = new CustomConfiguration();
    Container container = ContainerBuilder.aContainer("TEST-FORMAT").
        withConfiguration(configuration).build();
    Assert.assertEquals("TEST-FORMAT", container.getType());
    Assert.assertSame(configuration, ((CustomContainer) container).getConfiguration());
  }

  @Test
  public void openDefaultContainerFromFile() throws Exception {
    Container container = ContainerBuilder.aContainer().fromExistingFile(BDOC_TEST_FILE).build();
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.BDOC);
  }

  @Test
  public void openDefaultContainerFromFileWithConfiguration() throws Exception {
    this.configuration = new Configuration(Configuration.Mode.TEST);
    this.configuration.setTspSource("test-value");
    Container container = ContainerBuilder.aContainer().withConfiguration(this.configuration).
        fromExistingFile(BDOC_TEST_FILE).build();
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.BDOC);
    Assert.assertEquals("test-value", ((BDocContainer) container).getConfiguration().getTspSource());
  }

  @Test
  public void openDDocContainerFromFile_whenUsingDefaultContainer() throws Exception {
    Container container = ContainerBuilder.aContainer().fromExistingFile(DDOC_TEST_FILE).build();
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.DDOC);
  }

  @Test
  public void openDDocContainerFromFile() throws Exception {
    Container container = ContainerBuilder.aContainer("DDOC").fromExistingFile(DDOC_TEST_FILE).build();
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.DDOC);
  }

  @Test
  public void openCustomContainerFromFile() throws Exception {
    File testFile = this.createTemporaryFileBy("testFile.txt", "TEST");
    ContainerBuilder.setContainerImplementation("TEST-FORMAT", CustomContainer.class);
    Container container = ContainerBuilder.aContainer("TEST-FORMAT").fromExistingFile(testFile.getPath()).build();
    Assert.assertEquals("TEST-FORMAT", container.getType());
    Assert.assertEquals(testFile.getPath(), ((CustomContainer) container).getOpenedFromFile());
  }

  @Test
  public void openCustomContainerFromFile_withConfiguration() throws Exception {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    File testFile = this.createTemporaryFileBy("testFile.txt", "TEST");
    ContainerBuilder.setContainerImplementation("TEST-FORMAT", CustomContainer.class);
    Container container = ContainerBuilder.aContainer("TEST-FORMAT").withConfiguration(this.configuration).
        fromExistingFile(testFile.getPath()).build();
    Assert.assertEquals("TEST-FORMAT", container.getType());
    Assert.assertEquals(testFile.getPath(), ((CustomContainer) container).getOpenedFromFile());
    Assert.assertSame(this.configuration, ((CustomContainer) container).getConfiguration());
  }

  @Test
  public void openCustomContainerFromFile_withCustomConfiguration() throws Exception {
    CustomConfiguration configuration = new CustomConfiguration(Configuration.Mode.TEST);
    File testFile = this.createTemporaryFileBy("testFile.txt", "TEST");
    ContainerBuilder.setContainerImplementation("TEST-FORMAT", CustomContainer.class);
    Container container = ContainerBuilder.aContainer("TEST-FORMAT").withConfiguration(configuration).
        fromExistingFile(testFile.getPath()).build();
    Assert.assertEquals("TEST-FORMAT", container.getType());
    Assert.assertEquals(testFile.getPath(), ((CustomContainer) container).getOpenedFromFile());
    Assert.assertSame(configuration, ((CustomContainer) container).getConfiguration());
  }

  @Test
  public void openBDocContainerFromStream() throws Exception {
    try (InputStream stream = FileUtils.openInputStream(new File(BDOC_TEST_FILE))) {
      Container container = ContainerBuilder.aContainer().fromStream(stream).build();
      TestAssert.assertContainerIsOpened(container, Container.DocumentType.ASICE);
    }
  }

  // When reading from stream there are no major difference between BDOC and ASICE
  @Test
  public void openBDocContainerFromStream_withConfiguration() throws Exception {
    this.configuration = new Configuration(Configuration.Mode.TEST);
    this.configuration.setTspSource("test-value");
    InputStream stream = FileUtils.openInputStream(new File(BDOC_TEST_FILE));
    Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICE).
        withConfiguration(this.configuration).
        fromStream(stream).build();
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.ASICE);
    Assert.assertEquals("test-value", ((AsicEContainer) container).getConfiguration().getTspSource());
  }

  @Test
  public void openDDocContainerFromStream() throws Exception {
    InputStream stream = FileUtils.openInputStream(new File(DDOC_TEST_FILE));
    Container container = ContainerBuilder.aContainer().fromStream(stream).build();
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.DDOC);
  }

  @Test
  public void openDDocContainerFromStream_withConfiguration() throws Exception {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    try (InputStream stream = FileUtils.openInputStream(new File(DDOC_TEST_FILE))) {
      Container container = ContainerBuilder.aContainer(Container.DocumentType.DDOC).withConfiguration(this.configuration).
          fromStream(stream).build();
      TestAssert.assertContainerIsOpened(container, Container.DocumentType.DDOC);
      Assert.assertSame(this.configuration, ((DDocContainer) container).getDDoc4JFacade().getConfiguration());
    }
  }

  @Test
  public void openDefaultContainerFromStream_withBDOC() throws Exception {
    InputStream stream = FileUtils.openInputStream(new File(BDOC_TEST_FILE));
    Container container = ContainerBuilder.aContainer().withConfiguration(Configuration.of(Configuration.Mode.TEST)).
        fromStream(stream).build();
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.ASICE);
  }

  @Test
  public void openDefaultContainerFromStream_withDDOC() throws Exception {
    InputStream stream = FileUtils.openInputStream(new File(DDOC_TEST_FILE));
    Container container = ContainerBuilder.aContainer().withConfiguration(Configuration.of(Configuration.Mode.TEST)).
        fromStream(stream).build();
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.DDOC);
  }

  @Test
  public void openCustomContainerFromStream() throws Exception {
    InputStream stream = FileUtils.openInputStream(this.createTemporaryFileBy("testFile.txt", "TEST"));
    ContainerBuilder.setContainerImplementation("TEST-FORMAT", CustomContainer.class);
    Container container = ContainerBuilder.aContainer("TEST-FORMAT").fromStream(stream).build();
    Assert.assertEquals("TEST-FORMAT", container.getType());
    Assert.assertSame(stream, ((CustomContainer) container).getOpenedFromStream());
  }

  @Test
  public void openCustomContainerFromStream_withConfiguration() throws Exception {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    InputStream stream = FileUtils.openInputStream(this.createTemporaryFileBy("testFile.txt", "TEST"));
    ContainerBuilder.setContainerImplementation("TEST-FORMAT", CustomContainer.class);
    Container container = ContainerBuilder.aContainer("TEST-FORMAT").withConfiguration(this.configuration).
        fromStream(stream).build();
    Assert.assertEquals("TEST-FORMAT", container.getType());
    Assert.assertSame(stream, ((CustomContainer) container).getOpenedFromStream());
    Assert.assertSame(this.configuration, ((CustomContainer) container).getConfiguration());
  }

  @Test
  public void openCustomContainerFromStream_withCustomConfiguration() throws Exception {
    this.configuration = new CustomConfiguration();
    InputStream stream = FileUtils.openInputStream(this.createTemporaryFileBy("testFile.txt", "TEST"));
    ContainerBuilder.setContainerImplementation("TEST-FORMAT", CustomContainer.class);
    Container container = ContainerBuilder.aContainer("TEST-FORMAT").withConfiguration(this.configuration).
        fromStream(stream).build();
    Assert.assertEquals("TEST-FORMAT", container.getType());
    Assert.assertSame(stream, ((CustomContainer) container).getOpenedFromStream());
    Assert.assertSame(this.configuration, ((CustomContainer) container).getConfiguration());
  }

  @Test
  public void openDDocContainerWithTempDirectory() throws Exception {
    File folder = this.testFolder.newFolder();
    Assert.assertTrue(folder.list().length == 0);
    ContainerBuilder.aContainer(Container.DocumentType.DDOC).
        fromExistingFile("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc").
        usingTempDirectory(folder.getPath()).build();
    Assert.assertTrue(folder.list().length > 0);
  }

  @Test
  public void openDDocContainerWithTempDirectoryAndConfiguration() throws Exception {
    File folder = this.testFolder.newFolder();
    Assert.assertTrue(folder.list().length == 0);
    ContainerBuilder.aContainer(Container.DocumentType.DDOC).
        fromExistingFile("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc").
        withConfiguration(Configuration.of(Configuration.Mode.TEST)).usingTempDirectory(folder.getPath()).build();
    Assert.assertTrue(folder.list().length > 0);
  }

  @Test
  public void openDDocContainerFromStreamWithTempDirectory() throws Exception {
    File folder = this.testFolder.newFolder();
    Assert.assertTrue(folder.list().length == 0);
    InputStream stream = FileUtils.openInputStream(new File(DDOC_TEST_FILE));
    ContainerBuilder.aContainer(Container.DocumentType.DDOC).fromStream(stream).
        usingTempDirectory(folder.getPath()).build();
    Assert.assertTrue(folder.list().length > 0);
  }

  @Test
  public void openDDocContainerFromStreamWithTempDirectoryAndConfiguration() throws Exception {
    File folder = this.testFolder.newFolder();
    Assert.assertTrue(folder.list().length == 0);
    InputStream stream = FileUtils.openInputStream(new File(DDOC_TEST_FILE));
    ContainerBuilder.aContainer(Container.DocumentType.DDOC).withConfiguration(Configuration.of(Configuration.Mode.TEST))
        .fromStream(stream).usingTempDirectory(folder.getPath()).build();
    Assert.assertTrue(folder.list().length > 0);
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void after() {
    ContainerBuilder.removeCustomContainerImplementations();
  }

}
