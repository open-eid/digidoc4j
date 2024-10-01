/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.asics;

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.Timestamp;
import org.digidoc4j.TimestampBuilder;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.test.util.TestZipUtil;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.function.Consumer;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.not;

public class TimestampedCompositeContainerParsingTest extends AbstractTest {

  @Test
  public void openContainer_WhenDataFileIsTextFileAndLoadFromFile_ReturnsRegularAsicsContainer() {
    Container container = openContainerFromFile(
            "src/test/resources/testFiles/valid-containers/1xTST-text-data-file.asics"
    );

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container, not(instanceOf(AsicSCompositeContainer.class)));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(1));
  }

  @Test
  public void openContainer_WhenDataFileIsTextFileAndLoadFromStream_ReturnsRegularAsicsContainer() {
    Container container = openContainerFromStream(
            "src/test/resources/testFiles/valid-containers/1xTST-text-data-file.asics"
    );

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container, not(instanceOf(AsicSCompositeContainer.class)));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(1));
  }

  @Test
  public void openContainer_WhenDataFileIsZipFileAndLoadFromFile_ReturnsRegularAsicsContainer() {
    byte[] zipBytes = TestZipUtil.writeEntriesToByteArray(
            TestZipUtil.createDeflatedEntry("name.ext", "Content.".getBytes(StandardCharsets.UTF_8)),
            TestZipUtil.createDeflatedEntry("other", "Something...".getBytes(StandardCharsets.UTF_8))
    );
    Container container = openContainerFromFile(createTimestampedAsics(builder -> builder.withDataFile(
            new ByteArrayInputStream(zipBytes),
            "archive.zip",
            MimeTypeEnum.ZIP.getMimeTypeString()
    )));

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container, not(instanceOf(AsicSCompositeContainer.class)));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(1));
  }

  @Test
  public void openContainer_WhenDataFileIsZipFileAndLoadFromStream_ReturnsRegularAsicsContainer() {
    byte[] zipBytes = TestZipUtil.writeEntriesToByteArray(
            TestZipUtil.createDeflatedEntry("name.ext", "Content.".getBytes(StandardCharsets.UTF_8)),
            TestZipUtil.createDeflatedEntry("other", "Something...".getBytes(StandardCharsets.UTF_8))
    );
    Container container = openContainerFromStream(createTimestampedAsics(builder -> builder.withDataFile(
            new ByteArrayInputStream(zipBytes),
            "archive.zip",
            MimeTypeEnum.ZIP.getMimeTypeString()
    )));

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container, not(instanceOf(AsicSCompositeContainer.class)));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(1));
  }

  @Test
  public void openContainer_WhenDataFileIsXmlFileAndLoadFromFile_ReturnsRegularAsicsContainer() {
    Container container = openContainerFromFile(createTimestampedAsics(builder -> builder.withDataFile(
            "src/test/resources/testFiles/helper-files/test.xml",
            MimeTypeEnum.XML.getMimeTypeString()
    )));

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container, not(instanceOf(AsicSCompositeContainer.class)));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(1));
  }

  @Test
  public void openContainer_WhenDataFileIsXmlFileAndLoadFromStream_ReturnsRegularAsicsContainer() {
    Container container = openContainerFromStream(createTimestampedAsics(builder -> builder.withDataFile(
            "src/test/resources/testFiles/helper-files/test.xml",
            MimeTypeEnum.XML.getMimeTypeString()
    )));

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container, not(instanceOf(AsicSCompositeContainer.class)));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(1));
  }

  @Test
  public void openContainer_WhenDataFileIsAsiceContainerAndLoadFromFile_ReturnsCompositeAsicsContainer() {
    Container container = openContainerFromFile(
            "src/test/resources/testFiles/valid-containers/1xTST-asice-datafile-with-expired-signer-and-ocsp.asics"
    );

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container, instanceOf(AsicSCompositeContainer.class));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(1));
    // TODO (DD4J-1095): verify that parameters from the inner container are correct
  }

  @Test
  public void openContainer_WhenDataFileIsAsiceContainerAndLoadFromStream_ReturnsCompositeAsicsContainer() {
    Container container = openContainerFromStream(
            "src/test/resources/testFiles/valid-containers/1xTST-asice-datafile-with-expired-signer-and-ocsp.asics"
    );

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container, instanceOf(AsicSCompositeContainer.class));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(1));
    // TODO (DD4J-1095): verify that parameters from the inner container are correct
  }

  @Test
  public void openContainer_WhenDataFileIsDegenerateAsiceContainerAndLoadFromFile_ReturnsCompositeAsicsContainer() {
    Container container = createTimestampedAsics(builder -> builder.withDataFile(
            "src/test/resources/testFiles/degenerate-containers/2-mimetypes.asice",
            MimeTypeEnum.ASICE.getMimeTypeString()
    ));
    File file = saveContainerToTemporaryFile(container);

    TechnicalException caughtException = Assert.assertThrows(
            TechnicalException.class,
            () -> ContainerOpener.open(file.getPath(), configuration)
    );

    assertThat(caughtException.getMessage(), equalTo("Failed to parse nested ASiC container"));
  }

  @Test
  public void openContainer_WhenDataFileIsDegenerateAsiceContainerAndLoadFromStream_ReturnsCompositeAsicsContainer() {
    Container container = createTimestampedAsics(builder -> builder.withDataFile(
            "src/test/resources/testFiles/degenerate-containers/2-mimetypes.asice",
            MimeTypeEnum.ASICE.getMimeTypeString()
    ));

    TechnicalException caughtException = Assert.assertThrows(
            TechnicalException.class,
            () -> ContainerOpener.open(container.saveAsStream(), configuration)
    );

    assertThat(caughtException.getMessage(), equalTo("Failed to parse nested ASiC container"));
  }

  @Test
  public void openContainer_WhenDataFileIsSignedAsicsContainerAndLoadFromFile_ReturnsCompositeAsicsContainer() {
    Container container = openContainerFromFile(createTimestampedAsics(builder -> builder.withDataFile(
            "src/test/resources/testFiles/valid-containers/asics-1-signature.asics",
            MimeTypeEnum.ASICS.getMimeTypeString()
    )));

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container, instanceOf(AsicSCompositeContainer.class));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(1));
    // TODO (DD4J-1095): verify that parameters from the inner container are correct
  }

  @Test
  public void openContainer_WhenDataFileIsSignedAsicsContainerAndLoadFromStream_ReturnsCompositeAsicsContainer() {
    Container container = openContainerFromStream(createTimestampedAsics(builder -> builder.withDataFile(
            "src/test/resources/testFiles/valid-containers/asics-1-signature.asics",
            MimeTypeEnum.ASICS.getMimeTypeString()
    )));

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container, instanceOf(AsicSCompositeContainer.class));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(1));
    // TODO (DD4J-1095): verify that parameters from the inner container are correct
  }

  @Test
  public void openContainer_WhenDataFileIsTimestampedAsicsContainerAndLoadFromFile_ReturnsCompositeAsicsContainer() {
    Container container = openContainerFromFile(createTimestampedAsics(builder -> builder.withDataFile(
            "src/test/resources/testFiles/valid-containers/1xTST-text-data-file.asics",
            MimeTypeEnum.ASICS.getMimeTypeString()
    )));

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container, instanceOf(AsicSCompositeContainer.class));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(1));
    // TODO (DD4J-1095): verify that parameters from the inner container are correct
  }

  @Test
  public void openContainer_WhenDataFileIsTimestampedAsicsContainerAndLoadFromStream_ReturnsCompositeAsicsContainer() {
    Container container = openContainerFromStream(createTimestampedAsics(builder -> builder.withDataFile(
            "src/test/resources/testFiles/valid-containers/1xTST-text-data-file.asics",
            MimeTypeEnum.ASICS.getMimeTypeString()
    )));

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container, instanceOf(AsicSCompositeContainer.class));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(1));
    // TODO (DD4J-1095): verify that parameters from the inner container are correct
  }

  @Test
  public void openContainer_WhenDataFileIsDegenerateAsicsContainerAndLoadFromFile_ReturnsCompositeAsicsContainer() {
    Container container = createTimestampedAsics(builder -> builder.withDataFile(
            "src/test/resources/testFiles/degenerate-containers/2-mimetypes.asics",
            MimeTypeEnum.ASICE.getMimeTypeString()
    ));
    File file = saveContainerToTemporaryFile(container);

    TechnicalException caughtException = Assert.assertThrows(
            TechnicalException.class,
            () -> ContainerOpener.open(file.getPath(), configuration)
    );

    assertThat(caughtException.getMessage(), equalTo("Failed to parse nested ASiC container"));
  }

  @Test
  public void openContainer_WhenDataFileIsDegenerateAsicsContainerAndLoadFromStream_ReturnsCompositeAsicsContainer() {
    Container container = createTimestampedAsics(builder -> builder.withDataFile(
            "src/test/resources/testFiles/degenerate-containers/2-mimetypes.asics",
            MimeTypeEnum.ASICE.getMimeTypeString()
    ));

    TechnicalException caughtException = Assert.assertThrows(
            TechnicalException.class,
            () -> ContainerOpener.open(container.saveAsStream(), configuration)
    );

    assertThat(caughtException.getMessage(), equalTo("Failed to parse nested ASiC container"));
  }

  @Test
  public void openContainer_WhenDataFileIsBdocContainerAndLoadFromFile_ReturnsCompositeAsicsContainer() {
    Container container = openContainerFromFile(
            "src/test/resources/testFiles/valid-containers/1xTST-valid-bdoc-data-file.asics"
    );

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container, instanceOf(AsicSCompositeContainer.class));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(1));
    // TODO (DD4J-1095): verify that parameters from the inner container are correct
  }

  @Test
  public void openContainer_WhenDataFileIsBdocContainerAndLoadFromStream_ReturnsCompositeAsicsContainer() {
    Container container = openContainerFromStream(
            "src/test/resources/testFiles/valid-containers/1xTST-valid-bdoc-data-file.asics"
    );

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container, instanceOf(AsicSCompositeContainer.class));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(1));
    // TODO (DD4J-1095): verify that parameters from the inner container are correct
  }

  @Test
  public void openContainer_WhenDataFileIsDegenerateBdocContainerAndLoadFromFile_ReturnsCompositeAsicsContainer() {
    Container container = createTimestampedAsics(builder -> builder.withDataFile(
            "src/test/resources/testFiles/degenerate-containers/2-mimetypes.bdoc",
            MimeTypeEnum.ASICE.getMimeTypeString()
    ));
    File file = saveContainerToTemporaryFile(container);

    TechnicalException caughtException = Assert.assertThrows(
            TechnicalException.class,
            () -> ContainerOpener.open(file.getPath(), configuration)
    );

    assertThat(caughtException.getMessage(), equalTo("Failed to parse nested ASiC container"));
  }

  @Test
  public void openContainer_WhenDataFileIsDegenerateBdocContainerAndLoadFromStream_ReturnsCompositeAsicsContainer() {
    Container container = createTimestampedAsics(builder -> builder.withDataFile(
            "src/test/resources/testFiles/degenerate-containers/2-mimetypes.bdoc",
            MimeTypeEnum.ASICE.getMimeTypeString()
    ));

    TechnicalException caughtException = Assert.assertThrows(
            TechnicalException.class,
            () -> ContainerOpener.open(container.saveAsStream(), configuration)
    );

    assertThat(caughtException.getMessage(), equalTo("Failed to parse nested ASiC container"));
  }

  @Test
  public void openContainer_WhenDataFileIsDdocContainerAndLoadFromFile_ReturnsCompositeAsicsContainer() {
    Container container = openContainerFromFile(
            "src/test/resources/testFiles/valid-containers/ddoc-valid.asics"
    );

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container, instanceOf(AsicSCompositeContainer.class));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(1));
    // TODO (DD4J-1095): verify that parameters from the inner container are correct
  }

  @Test
  public void openContainer_WhenDataFileIsDdocContainerAndLoadFromStream_ReturnsCompositeAsicsContainer() {
    Container container = openContainerFromStream(
            "src/test/resources/testFiles/valid-containers/ddoc-valid.asics"
    );

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container, instanceOf(AsicSCompositeContainer.class));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(1));
    // TODO (DD4J-1095): verify that parameters from the inner container are correct
  }

  @Test
  public void openContainer_WhenDataFileIsPadesContainerAndLoadFromFile_ReturnsRegularAsicsContainer() {
    Container container = openContainerFromFile(createTimestampedAsics(builder -> builder.withDataFile(
            "src/test/resources/testFiles/invalid-containers/EE_AS-P-BpLT-V-009.pdf",
            MimeTypeEnum.XML.getMimeTypeString()
    )));

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container, not(instanceOf(AsicSCompositeContainer.class)));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(1));
  }

  @Test
  public void openContainer_WhenDataFileIsPadesContainerAndLoadFromStream_ReturnsRegularAsicsContainer() {
    Container container = openContainerFromStream(createTimestampedAsics(builder -> builder.withDataFile(
            "src/test/resources/testFiles/invalid-containers/EE_AS-P-BpLT-V-009.pdf",
            MimeTypeEnum.XML.getMimeTypeString()
    )));

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container, not(instanceOf(AsicSCompositeContainer.class)));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(1));
  }

  @Test
  public void openContainer_WhenMultipleTimestampsAndDataFileIsContainerAndLoadFromFile_ReturnsCompositeAsicsContainer() {
    Container container = openContainerFromFile(
            "src/test/resources/testFiles/valid-containers/2xTST-valid-bdoc-data-file.asics"
    );

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container, instanceOf(AsicSCompositeContainer.class));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(2));
    // TODO (DD4J-1095): verify that parameters from the inner container are correct
  }

  @Test
  public void openContainer_WhenMultipleTimestampsAndDataFileIsContainerAndLoadFromStream_ReturnsCompositeAsicsContainer() {
    Container container = openContainerFromStream(
            "src/test/resources/testFiles/valid-containers/2xTST-valid-bdoc-data-file.asics"
    );

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container, instanceOf(AsicSCompositeContainer.class));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(2));
    // TODO (DD4J-1095): verify that parameters from the inner container are correct
  }

  @Test
  public void openContainer_WhenMultipleTimestampedAsicsContainersRecursivelyAndLoadFromFile_ReturnsCompositeAsicsContainerWithOneLevelOfNesting() {
    Container container = openContainerFromFile(
            "src/test/resources/testFiles/valid-containers/1xTST-recursive-asics-datafile.asics"
    );

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container, instanceOf(AsicSCompositeContainer.class));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(1));
    // TODO (DD4J-1095): verify that parameters from the inner container are correct

    ContainerValidationResult validationResult = container.validate();
    assertThat(validationResult.getTimestampReports(), hasSize(2));
  }

  @Test
  public void openContainer_WhenMultipleTimestampedAsicsContainersRecursivelyAndLoadFromStream_ReturnsCompositeAsicsContainerWithOneLevelOfNesting() {
    Container container = openContainerFromStream(
            "src/test/resources/testFiles/valid-containers/1xTST-recursive-asics-datafile.asics"
    );

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container, instanceOf(AsicSCompositeContainer.class));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(1));
    // TODO (DD4J-1095): verify that parameters from the inner container are correct

    ContainerValidationResult validationResult = container.validate();
    assertThat(validationResult.getTimestampReports(), hasSize(2));
  }

  private Container openContainerFromFile(String path) {
    return ContainerOpener.open(path, configuration);
  }

  private Container openContainerFromFile(Container container) {
    File testFile = saveContainerToTemporaryFile(container);
    try {
      return ContainerOpener.open(testFile.getPath(), configuration);
    } finally {
      testFile.delete();
    }
  }

  private Container openContainerFromStream(String path) {
    try (InputStream inputStream = Files.newInputStream(Paths.get(path))) {
      return ContainerOpener.open(inputStream, configuration);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to read input file: " + path, e);
    }
  }

  private Container openContainerFromStream(Container container) {
    try (InputStream inputStream = container.saveAsStream()) {
      return ContainerOpener.open(inputStream, configuration);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to read container stream", e);
    }
  }

  private Container createTimestampedAsics(Consumer<ContainerBuilder> containerBuilderConfigurator) {
    ContainerBuilder containerBuilder = ContainerBuilder
            .aContainer(Container.DocumentType.ASICS)
            .withConfiguration(configuration);

    containerBuilderConfigurator.accept(containerBuilder);
    Container container = containerBuilder.build();

    Timestamp timestamp = TimestampBuilder
            .aTimestamp(container)
            .invokeTimestamping();

    container.addTimestamp(timestamp);
    return container;
  }

  private File saveContainerToTemporaryFile(Container container) {
    String extension = container.getType().toLowerCase();
    File containerFile = createTemporaryFileByExtension(extension);
    container.saveAsFile(containerFile.getPath());
    return containerFile;
  }

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
  }

}
