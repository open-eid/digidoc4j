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

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import org.digidoc4j.test.RestrictedExternalResourceRule;
import org.digidoc4j.test.RestrictedExternalResourceRule.FileWritingRestrictedException;
import org.digidoc4j.test.TestAssert;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.JRE;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

@EnabledForJreRange(max = JRE.JAVA_17)
public class FileWritingOperationsTest extends AbstractTest {

  /**
   * {@link RestrictedExternalResourceRule} uses {@code SecurityManager} to achieve its goal.
   * Since Java 17, Security Manager and its related API-s are deprecated for removal.
   * Since Java 18, dynamically installing a Security Manager is disabled by default unless the end user has explicitly
   * opted to allow it.
   * https://openjdk.org/jeps/411
   * TODO (DD4J-992): Find an alternative to using Security Manager for limiting filesystem access.
   */
  @Rule
  public RestrictedExternalResourceRule rule = new RestrictedExternalResourceRule(
          new File(System.getProperty("java.io.tmpdir") + File.separator + "dss-cache-tsl" + File.separator).getPath(),
          new File(System.getProperty("java.io.tmpdir") + File.separator + "temp-tsl-keystore" + File.separator).getPath()
  );

  @Test
  public void writingToFileIsNotAllowed() {
    assertThrows(
            FileWritingRestrictedException.class,
            () -> File.createTempFile("test", "test")
    );
  }

  @Test
  public void openingExistingContainer_shouldNotStoreDataFilesOnDisk_byDefault() throws Exception {
    Container container = openContainerBy(Paths.get("src/test/resources/testFiles/valid-containers/one_signature.bdoc"));
    TestDataBuilderUtil.signContainer(container);
    TestAssert.assertSaveAsStream(container);
  }

  @Test
  public void openingExistingDDocContainer_shouldNotStoreDataFilesOnDisk_byDefault() throws Exception {
    Container container = openContainerBy(Paths.get("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc"));
    TestAssert.assertSaveAsStream(container);
  }

  @Ignore("Fail in travis")
  @Test
  public void creatingNewContainer_shouldNotStoreDataFilesOnDisk_byDefault() throws Throwable {
    Container container = createNonEmptyContainerIncludingPDFFileBy(Container.DocumentType.BDOC);
    TestDataBuilderUtil.signContainer(container);
    TestAssert.assertSaveAsStream(container);
  }

  @Ignore("Fail in travis")
  @Test
  public void creatingDataFiles_shouldNotStoreDataFilesOnDisk_byDefault() throws Exception {
    Container container = createNonEmptyContainerBy(Container.DocumentType.BDOC);
    assertEquals(3, container.getDataFiles().size());
    TestDataBuilderUtil.signContainer(container);
    TestAssert.assertSaveAsStream(container);
  }

  @Test
  public void creatingDataFilesForDDoc_shouldNotStoreDataFilesOnDisk_byDefault() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    TestAssert.assertSaveAsStream(container);
  }

  @Test(expected = FileWritingRestrictedException.class)
  public void creatingLargeDataFile_shouldStoreFileOnDisk() throws Throwable {
    InputStream dataFileInputStream = new ByteArrayInputStream(new byte[]{1, 2, 3});
    try {
      DataFile dataFile = new LargeDataFile(dataFileInputStream, "stream-file.txt", MimeTypeEnum.TEXT.getMimeTypeString());
      assertFalse("Did not create a temporary file", true);
    } catch (Exception e) {
      throw e.getCause();
    }
  }

  @Test(expected = FileWritingRestrictedException.class)
  public void openingExistingContainer_withStoringDataFilesOnDisk() throws Exception {
    configuration = Configuration.of(Configuration.Mode.TEST);
    configuration.setMaxFileSizeCachedInMemoryInMB(0);
    Container container = openContainerByConfiguration(Paths.get("src/test/resources/testFiles/valid-containers/one_signature.bdoc"));
    assertEquals(1, container.getDataFiles().size());
  }

  @Test(expected = FileWritingRestrictedException.class)
  public void openingExistingContainer_withLarge2MbFile_shouldStoreDataFilesOnDisk() throws Exception {
    configuration = Configuration.of(Configuration.Mode.TEST);
    configuration.setMaxFileSizeCachedInMemoryInMB(1);
    Container container = openContainerByConfiguration(Paths.get("src/test/resources/testFiles/valid-containers/bdoc-ts-with-large-data-file.bdoc"));
    assertEquals(1, container.getDataFiles().size());
  }

  @Test
  @Ignore //This test fails in Travis
  public void openingExistingContainer_withLarge2MbFile_shouldNotStoreDataFilesOnDisk() throws Exception {
    configuration = Configuration.of(Configuration.Mode.TEST);
    configuration.setMaxFileSizeCachedInMemoryInMB(4);
    Container container = openContainerByConfiguration(Paths.get("src/test/resources/testFiles/valid-containers/bdoc-ts-with-large-data-file.bdoc"));
    assertEquals(1, container.getDataFiles().size());
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected Container createNonEmptyContainerBy(Container.DocumentType documentType) {
    DataFile pathDataFile = new DataFile("src/test/resources/testFiles/helper-files/test.txt", MimeTypeEnum.TEXT.getMimeTypeString());
    DataFile byteDataFile = new DataFile(new byte[]{1, 2, 3}, "byte-file.txt", MimeTypeEnum.TEXT.getMimeTypeString());
    InputStream dataFileInputStream = new ByteArrayInputStream(new byte[]{1, 2, 3});
    DataFile streamDataFile = new DataFile(dataFileInputStream, "stream-file.txt", MimeTypeEnum.TEXT.getMimeTypeString());
    return ContainerBuilder.aContainer(documentType).withDataFile(pathDataFile).withDataFile(byteDataFile).
        withDataFile(streamDataFile).build();
  }

  private Container createNonEmptyContainerIncludingPDFFileBy(Container.DocumentType documentType) {
    InputStream dataFileInputStream = new ByteArrayInputStream(new byte[]{1, 2, 3});
    File pdfFile = new File("src/test/resources/testFiles/special-char-files/dds_acrobat.pdf");
    return ContainerBuilder.aContainer(documentType).
        withDataFile(dataFileInputStream, "test-stream.txt", MimeTypeEnum.TEXT.getMimeTypeString()).
        withDataFile("src/test/resources/testFiles/helper-files/test.txt", MimeTypeEnum.TEXT.getMimeTypeString()).
        withDataFile(pdfFile, MimeTypeEnum.PDF.getMimeTypeString()).build();
  }

}
