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

import static org.digidoc4j.ContainerBuilder.BDOC_CONTAINER_TYPE;
import static org.digidoc4j.ContainerBuilder.DDOC_CONTAINER_TYPE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.io.IOUtils;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.digidoc4j.testutils.RestrictedFileWritingRule;
import org.digidoc4j.testutils.RestrictedFileWritingRule.FileWritingRestrictedException;
import org.digidoc4j.testutils.TestDataBuilder;
import org.junit.Rule;
import org.junit.Test;

import eu.europa.esig.dss.MimeType;

public class FileWritingOperationsTest extends DigiDoc4JTestHelper {

  private static final String tslCacheDirectoryPath = System.getProperty("java.io.tmpdir") + File.separator + "dss-cache-tsl" + File.separator;
  private static final String TEST_BDOC_CONTAINER = "testFiles/valid-containers/one_signature.bdoc";
  private static final String TEST_DDOC_CONTAINER = "testFiles/valid-containers/ddoc_for_testing.ddoc";
  private static final String TEST_LARGE_BDOC_CONTAINER = "testFiles/valid-containers/bdoc-ts-with-large-data-file.bdoc";

  @Rule
  public RestrictedFileWritingRule rule = new RestrictedFileWritingRule(new File(tslCacheDirectoryPath).getPath());

  private static Configuration configuration = new Configuration(Configuration.Mode.TEST);

  @Test(expected = FileWritingRestrictedException.class)
  public void writingToFileIsNotAllowed() throws IOException {
    File.createTempFile("test", "test");
  }

  @Test
  public void openingExistingContainer_shouldNotStoreDataFilesOnDisk_byDefault() throws Exception {
    Container container = open(TEST_BDOC_CONTAINER, BDOC_CONTAINER_TYPE);
    TestDataBuilder.signContainer(container);
    assertSavingContainer(container);
  }

  @Test
  public void openingExistingDDocContainer_shouldNotStoreDataFilesOnDisk_byDefault() throws Exception {
    Container container = open(TEST_DDOC_CONTAINER, DDOC_CONTAINER_TYPE);
    TestDataBuilder.signContainer(container, DigestAlgorithm.SHA1);
    assertSavingContainer(container);
  }

  @Test
  public void creatingNewContainer_shouldNotStoreDataFilesOnDisk_byDefault() throws Throwable {
    Container container = createWithTestFiles(BDOC_CONTAINER_TYPE);
    TestDataBuilder.signContainer(container);
    assertSavingContainer(container);
  }

  @Test
  public void creatingNewDDocContainer_shouldNotStoreDataFilesOnDisk_byDefault() throws Throwable {
    Container container = createWithTestFiles(DDOC_CONTAINER_TYPE);
    TestDataBuilder.signContainer(container, DigestAlgorithm.SHA1);
    assertSavingContainer(container);
  }

  @Test
  public void creatingDataFiles_shouldNotStoreDataFilesOnDisk_byDefault() throws Exception {
    Container container = createContainerWithDataFiles(BDOC_CONTAINER_TYPE);
    assertEquals(3, container.getDataFiles().size());
    TestDataBuilder.signContainer(container);
    assertSavingContainer(container);
  }

  @Test
  public void creatingDataFilesForDDoc_shouldNotStoreDataFilesOnDisk_byDefault() throws Exception {
    Container container = createContainerWithDataFiles(DDOC_CONTAINER_TYPE);
    assertEquals(3, container.getDataFiles().size());
    TestDataBuilder.signContainer(container, DigestAlgorithm.SHA1);
    assertSavingContainer(container);
  }

  @Test(expected = FileWritingRestrictedException.class)
  public void creatingLargeDataFile_shouldStoreFileOnDisk() throws Throwable {
    InputStream dataFileInputStream = new ByteArrayInputStream(new byte[]{1, 2, 3});
    try {
      DataFile dataFile = new LargeDataFile(dataFileInputStream, "stream-file.txt", MimeType.TEXT.getMimeTypeString());
      assertFalse("Did not create a temporary file", true);
    } catch (Exception e) {
      throw e.getCause();
    }
  }

  @Test(expected = FileWritingRestrictedException.class)
  public void openingExistingContainer_withStoringDataFilesOnDisk() throws Exception {
    configuration.setMaxFileSizeCachedInMemoryInMB(0);
    Container container = openWithConfiguration(TEST_BDOC_CONTAINER, BDOC_CONTAINER_TYPE);
    assertEquals(1, container.getDataFiles().size());
  }

  @Test(expected = FileWritingRestrictedException.class)
  public void openingExistingContainer_withLarge2MbFile_shouldStoreDataFilesOnDisk() throws Exception {
    configuration.setMaxFileSizeCachedInMemoryInMB(1);
    Container container = openWithConfiguration(TEST_LARGE_BDOC_CONTAINER, BDOC_CONTAINER_TYPE);
    assertEquals(1, container.getDataFiles().size());
  }

  @Test
  public void openingExistingContainer_withLarge2MbFile_shouldNotStoreDataFilesOnDisk() throws Exception {
    configuration.setMaxFileSizeCachedInMemoryInMB(4);
    Container container = openWithConfiguration(TEST_LARGE_BDOC_CONTAINER, BDOC_CONTAINER_TYPE);
    assertEquals(1, container.getDataFiles().size());
  }

  private Container open(String containerPath, String type) {
    return ContainerBuilder.
        aContainer(type).
        fromExistingFile(containerPath).
        build();
  }

  private Container openWithConfiguration(String containerPath, String type) {
    return ContainerBuilder.
        aContainer(type).
        fromExistingFile(containerPath).
        withConfiguration(configuration).
        build();
  }

  private Container createWithTestFiles(String type) {
    InputStream dataFileInputStream = new ByteArrayInputStream(new byte[]{1, 2, 3});
    File pdfFile = new File("testFiles/special-char-files/dds_acrobat.pdf");
    return ContainerBuilder.
        aContainer(type).
        withDataFile(dataFileInputStream, "test-stream.txt", MimeType.TEXT.getMimeTypeString()).
        withDataFile("testFiles/helper-files/test.txt", MimeType.TEXT.getMimeTypeString()).
        withDataFile(pdfFile, MimeType.PDF.getMimeTypeString()).
        build();
  }

  private Container createContainerWithDataFiles(String type) {
    DataFile pathDataFile = new DataFile("testFiles/helper-files/test.txt", MimeType.TEXT.getMimeTypeString());
    DataFile byteDataFile = new DataFile(new byte[]{1, 2, 3}, "byte-file.txt", MimeType.TEXT.getMimeTypeString());
    InputStream dataFileInputStream = new ByteArrayInputStream(new byte[]{1, 2, 3});
    DataFile streamDataFile = new DataFile(dataFileInputStream, "stream-file.txt", MimeType.TEXT.getMimeTypeString());

    return ContainerBuilder.
        aContainer(type).
        withDataFile(pathDataFile).
        withDataFile(byteDataFile).
        withDataFile(streamDataFile).
        build();
  }

  private void assertSavingContainer(Container container) throws IOException {
    container.validate();
    InputStream inputStream = container.saveAsStream();
    assertContainerStream(inputStream);
  }

  private void assertContainerStream(InputStream inputStream) throws IOException {
    byte[] containerBytes = IOUtils.toByteArray(inputStream);
    assertTrue(containerBytes.length > 0);
  }
}
