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
import eu.europa.esig.dss.model.FileDocument;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotYetImplementedException;
import org.digidoc4j.utils.ContainerUtils;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.time.Duration;
import java.time.Instant;
import java.util.function.Consumer;

import static org.digidoc4j.test.TestAssert.assertTimeBetweenNotBeforeAndNow;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

public class CompositeContainerBuilderTest {

  private static final String CONTAINER_FILE_NAME = "container";

  @Test
  public void fromContainer_WhenContainerIsNull_ThrowsException() {
    NullPointerException caughtException = assertThrows(
            NullPointerException.class,
            () -> CompositeContainerBuilder.fromContainer(null, CONTAINER_FILE_NAME)
    );

    assertThat(caughtException.getMessage(), equalTo("Container cannot be null"));
  }

  @Test
  public void fromContainer_WhenFileNameIsNull_ThrowsException() {
    Container container = mock(Container.class);

    NullPointerException caughtException = assertThrows(
              NullPointerException.class,
              () -> CompositeContainerBuilder.fromContainer(container, null)
    );

    assertThat(caughtException.getMessage(), equalTo("Container file name cannot be null"));
    verifyNoInteractions(container);
  }

  @Test
  public void fromContainer_WhenFileNameIsEmpty_ThrowsException() {
    fromContainer_WhenFileNameIsInvalid_ThrowsException(StringUtils.EMPTY);
  }

  @Test
  public void fromContainer_WhenFileNameIsBlank_ThrowsException() {
    fromContainer_WhenFileNameIsInvalid_ThrowsException(StringUtils.SPACE);
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void fromContainer_WhenFileNameIsInvalid_ThrowsException(String fileName) {
    Container container = mock(Container.class);

    IllegalArgumentException caughtException = assertThrows(
            IllegalArgumentException.class,
            () -> CompositeContainerBuilder.fromContainer(container, fileName)
    );

    assertThat(caughtException.getMessage(), equalTo("File name cannot be empty"));
    verifyNoInteractions(container);
  }

  @Test
  public void fromContainer_WhenFileNameEndsWithFileSeparator_ThrowsException() {
    Container container = mock(Container.class);

    IllegalArgumentException caughtException = assertThrows(
            IllegalArgumentException.class,
            () -> CompositeContainerBuilder.fromContainer(container, "test" + File.separator)
    );

    assertThat(caughtException.getMessage(), equalTo("File name cannot be empty"));
    verifyNoInteractions(container);
  }

  @Test
  public void fromContainer_WhenFileNameContainsNullCharacter_ThrowsException() {
    Container container = mock(Container.class);

    IllegalArgumentException caughtException = assertThrows(
            IllegalArgumentException.class,
            () -> CompositeContainerBuilder.fromContainer(container, "test\0")
    );

    assertThat(caughtException.getMessage(), containsString("Null character present in file/path name."));
    verifyNoInteractions(container);
  }

  @Test
  public void fromContainerFile_WhenFilePathIsNull_ThrowsException() {
    NullPointerException caughtException = assertThrows(
            NullPointerException.class,
            () -> CompositeContainerBuilder.fromContainerFile(null)
    );

    assertThat(caughtException.getMessage(), equalTo("Container file path cannot be null"));
  }

  @Test
  public void fromContainerFile_WhenFilePathIsEmpty_ThrowsException() {
    fromContainerFile_WhenFilePathIsInvalid_ThrowsException(StringUtils.EMPTY);
  }

  @Test
  public void fromContainerFile_WhenFilePathIsBlank_ThrowsException() {
    fromContainerFile_WhenFilePathIsInvalid_ThrowsException(StringUtils.SPACE);
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void fromContainerFile_WhenFilePathIsInvalid_ThrowsException(String filePath) {
    IllegalArgumentException caughtException = assertThrows(
            IllegalArgumentException.class,
            () -> CompositeContainerBuilder.fromContainerFile(filePath)
    );

    assertThat(caughtException.getMessage(), equalTo("File name cannot be empty"));
  }

  @Test
  public void fromContainerFile_WhenFilePathEndsWithFileSeparator_ThrowsException() {
    IllegalArgumentException caughtException = assertThrows(
            IllegalArgumentException.class,
            () -> CompositeContainerBuilder.fromContainerFile("test" + File.separator)
    );

    assertThat(caughtException.getMessage(), equalTo("File name cannot be empty"));
  }

  @Test
  public void fromContainerFile_WhenFilePathContainsNullCharacter_ThrowsException() {
    IllegalArgumentException caughtException = assertThrows(
            IllegalArgumentException.class,
            () -> CompositeContainerBuilder.fromContainerFile("test\0")
    );

    assertThat(caughtException.getMessage(), containsString("Null character present in file/path name."));
  }

  @Test
  public void fromContainerStream_WhenContainerIsNull_ThrowsException() {
    NullPointerException caughtException = assertThrows(
            NullPointerException.class,
            () -> CompositeContainerBuilder.fromContainerStream(null, CONTAINER_FILE_NAME)
    );

    assertThat(caughtException.getMessage(), equalTo("Container input stream cannot be null"));
  }

  @Test
  public void fromContainerStream_WhenFileNameIsNull_ThrowsException() {
    InputStream inputStream = mock(InputStream.class);

    NullPointerException caughtException = assertThrows(
            NullPointerException.class,
            () -> CompositeContainerBuilder.fromContainerStream(inputStream, null)
    );

    assertThat(caughtException.getMessage(), equalTo("Container file name cannot be null"));
    verifyNoInteractions(inputStream);
  }

  @Test
  public void fromContainerStream_WhenFileNameIsEmpty_ThrowsException() {
    fromContainerStream_WhenFileNameIsInvalid_ThrowsException(StringUtils.EMPTY);
  }

  @Test
  public void fromContainerStream_WhenFileNameIsBlank_ThrowsException() {
    fromContainerStream_WhenFileNameIsInvalid_ThrowsException(StringUtils.SPACE);
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void fromContainerStream_WhenFileNameIsInvalid_ThrowsException(String fileName) {
    InputStream inputStream = mock(InputStream.class);

    IllegalArgumentException caughtException = assertThrows(
            IllegalArgumentException.class,
            () -> CompositeContainerBuilder.fromContainerStream(inputStream, fileName)
    );

    assertThat(caughtException.getMessage(), equalTo("File name cannot be empty"));
    verifyNoInteractions(inputStream);
  }

  @Test
  public void fromContainerStream_WhenFileNameEndsWithFileSeparator_ThrowsException() {
    InputStream inputStream = mock(InputStream.class);

    IllegalArgumentException caughtException = assertThrows(
            IllegalArgumentException.class,
            () -> CompositeContainerBuilder.fromContainerStream(inputStream, "test" + File.separator)
    );

    assertThat(caughtException.getMessage(), equalTo("File name cannot be empty"));
    verifyNoInteractions(inputStream);
  }

  @Test
  public void fromContainerStream_WhenFileNameContainsNullCharacter_ThrowsException() {
    InputStream inputStream = mock(InputStream.class);

    IllegalArgumentException caughtException = assertThrows(
            IllegalArgumentException.class,
            () -> CompositeContainerBuilder.fromContainerStream(inputStream, "test\0")
    );

    assertThat(caughtException.getMessage(), containsString("Null character present in file/path name."));
    verifyNoInteractions(inputStream);
  }

  @Test
  public void buildTimestamped_WhenSpecifiedFileIsNotContainer_ThrowsException() {
    CompositeContainerBuilder builder = CompositeContainerBuilder
            .fromContainerFile("src/test/resources/testFiles/helper-files/test.txt")
            .withConfiguration(Configuration.of(Configuration.Mode.TEST));
    Consumer<TimestampBuilder> timestampBuilderConfigurator = mockConsumer();

    assertThrows(
            DigiDoc4JException.class,
            () -> builder.buildTimestamped(timestampBuilderConfigurator)
    );

    verifyNoInteractions(timestampBuilderConfigurator);
  }

  @Test
  public void buildTimestamped_WhenSpecifiedStreamIsNotContainer_ThrowsException() {
    CompositeContainerBuilder builder = CompositeContainerBuilder
            .fromContainerStream(new ByteArrayInputStream(new byte[0]), CONTAINER_FILE_NAME)
            .withConfiguration(Configuration.of(Configuration.Mode.TEST));
    Consumer<TimestampBuilder> timestampBuilderConfigurator = mockConsumer();

    assertThrows(
            DigiDoc4JException.class,
            () -> builder.buildTimestamped(timestampBuilderConfigurator)
    );

    verifyNoInteractions(timestampBuilderConfigurator);
  }

  @Test
  public void buildTimestamped_WhenSpecifiedContainerIsAsice_CreatesTimestampedCompositeContainer() {
    buildTimestamped_WhenSpecifiedContainerIsAllowedType_CreatesTimestampedCompositeContainer(
            "src/test/resources/testFiles/valid-containers/valid-asice-esteid2018.asice",
            Constant.ASICE_CONTAINER_TYPE,
            MimeTypeEnum.ASICE.getMimeTypeString()
    );
  }

  @Test
  public void buildTimestamped_WhenSpecifiedFileIsAsice_CreatesTimestampedCompositeContainer() throws Exception {
    buildTimestamped_WhenSpecifiedFileIsAllowedContainerType_CreatesTimestampedCompositeContainer(
            "src/test/resources/testFiles/valid-containers/valid-asice-esteid2018.asice",
            Constant.ASICE_CONTAINER_TYPE,
            MimeTypeEnum.ASICE.getMimeTypeString()
    );
  }

  @Test
  public void buildTimestamped_WhenSpecifiedStreamIsAsice_CreatesTimestampedCompositeContainer() throws Exception {
    buildTimestamped_WhenSpecifiedStreamIsAllowedContainerType_CreatesTimestampedCompositeContainer(
            "src/test/resources/testFiles/valid-containers/valid-asice-esteid2018.asice",
            Constant.ASICE_CONTAINER_TYPE,
            MimeTypeEnum.ASICE.getMimeTypeString()
    );
  }

  @Test
  public void buildTimestamped_WhenSpecifiedContainerIsSignedAsics_CreatesTimestampedCompositeContainer() {
    buildTimestamped_WhenSpecifiedContainerIsAllowedType_CreatesTimestampedCompositeContainer(
            "src/test/resources/testFiles/valid-containers/valid-asics-esteid2018.asics",
            Constant.ASICS_CONTAINER_TYPE,
            MimeTypeEnum.ASICS.getMimeTypeString()
    );
  }

  @Test
  public void buildTimestamped_WhenSpecifiedFileIsSignedAsics_CreatesTimestampedCompositeContainer() throws Exception {
    buildTimestamped_WhenSpecifiedFileIsAllowedContainerType_CreatesTimestampedCompositeContainer(
            "src/test/resources/testFiles/valid-containers/valid-asics-esteid2018.asics",
            Constant.ASICS_CONTAINER_TYPE,
            MimeTypeEnum.ASICS.getMimeTypeString()
    );
  }

  @Test
  public void buildTimestamped_WhenSpecifiedStreamIsSignedAsics_CreatesTimestampedCompositeContainer() throws Exception {
    buildTimestamped_WhenSpecifiedStreamIsAllowedContainerType_CreatesTimestampedCompositeContainer(
            "src/test/resources/testFiles/valid-containers/valid-asics-esteid2018.asics",
            Constant.ASICS_CONTAINER_TYPE,
            MimeTypeEnum.ASICS.getMimeTypeString()
    );
  }

  @Test
  public void buildTimestamped_WhenSpecifiedContainerIsTimestampedAsics_CreatesTimestampedCompositeContainer() {
    buildTimestamped_WhenSpecifiedContainerIsAllowedType_CreatesTimestampedCompositeContainer(
            "src/test/resources/testFiles/valid-containers/1xTST-text-data-file.asics",
            Constant.ASICS_CONTAINER_TYPE,
            MimeTypeEnum.ASICS.getMimeTypeString()
    );
  }

  @Test
  public void buildTimestamped_WhenSpecifiedFileIsTimestampedAsics_CreatesTimestampedCompositeContainer() throws Exception {
    buildTimestamped_WhenSpecifiedFileIsAllowedContainerType_CreatesTimestampedCompositeContainer(
            "src/test/resources/testFiles/valid-containers/1xTST-text-data-file.asics",
            Constant.ASICS_CONTAINER_TYPE,
            MimeTypeEnum.ASICS.getMimeTypeString()
    );
  }

  @Test
  public void buildTimestamped_WhenSpecifiedStreamIsTimestampedAsics_CreatesTimestampedCompositeContainer() throws Exception {
    buildTimestamped_WhenSpecifiedStreamIsAllowedContainerType_CreatesTimestampedCompositeContainer(
            "src/test/resources/testFiles/valid-containers/1xTST-text-data-file.asics",
            Constant.ASICS_CONTAINER_TYPE,
            MimeTypeEnum.ASICS.getMimeTypeString()
    );
  }

  @Test
  public void buildTimestamped_WhenSpecifiedContainerIsBdoc_CreatesTimestampedCompositeContainer() {
    buildTimestamped_WhenSpecifiedContainerIsAllowedType_CreatesTimestampedCompositeContainer(
            "src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc",
            Constant.BDOC_CONTAINER_TYPE,
            MimeTypeEnum.ASICE.getMimeTypeString()
    );
  }

  @Test
  public void buildTimestamped_WhenSpecifiedFileIsBdoc_CreatesTimestampedCompositeContainer() throws Exception {
    buildTimestamped_WhenSpecifiedFileIsAllowedContainerType_CreatesTimestampedCompositeContainer(
            "src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc",
            Constant.BDOC_CONTAINER_TYPE,
            MimeTypeEnum.ASICE.getMimeTypeString()
    );
  }

  @Test
  public void buildTimestamped_WhenSpecifiedStreamIsBdoc_CreatesTimestampedCompositeContainer() throws Exception {
    buildTimestamped_WhenSpecifiedStreamIsAllowedContainerType_CreatesTimestampedCompositeContainer(
            "src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc",
            Constant.BDOC_CONTAINER_TYPE,
            MimeTypeEnum.ASICE.getMimeTypeString()
    );
  }

  @Test
  public void buildTimestamped_WhenSpecifiedContainerIsDdoc_CreatesTimestampedCompositeContainer() {
    buildTimestamped_WhenSpecifiedContainerIsAllowedType_CreatesTimestampedCompositeContainer(
            "src/test/resources/testFiles/valid-containers/ddoc-valid.ddoc",
            Constant.DDOC_CONTAINER_TYPE,
            ContainerUtils.DDOC_MIMETYPE_STRING
    );
  }

  @Test
  public void buildTimestamped_WhenSpecifiedFileIsDdoc_CreatesTimestampedCompositeContainer() throws Exception {
    buildTimestamped_WhenSpecifiedFileIsAllowedContainerType_CreatesTimestampedCompositeContainer(
            "src/test/resources/testFiles/valid-containers/ddoc-valid.ddoc",
            Constant.DDOC_CONTAINER_TYPE,
            ContainerUtils.DDOC_MIMETYPE_STRING
    );
  }

  @Test
  public void buildTimestamped_WhenSpecifiedStreamIsDdoc_CreatesTimestampedCompositeContainer() throws Exception {
    buildTimestamped_WhenSpecifiedStreamIsAllowedContainerType_CreatesTimestampedCompositeContainer(
            "src/test/resources/testFiles/valid-containers/ddoc-valid.ddoc",
            Constant.DDOC_CONTAINER_TYPE,
            ContainerUtils.DDOC_MIMETYPE_STRING
    );
  }

  @Test
  public void buildTimestamped_WhenSpecifiedContainerIsPades_ThrowsPadesSerializationNotImplementedException() {
    Container nestedContainer = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/valid-pades-esteid2018.pdf",
            Configuration.of(Configuration.Mode.TEST)
    );
    CompositeContainerBuilder builder = CompositeContainerBuilder.fromContainer(nestedContainer, CONTAINER_FILE_NAME);
    Consumer<TimestampBuilder> timestampBuilderConfigurator = mockConsumer();

    assertThrows(
            NotYetImplementedException.class,
            () -> builder.buildTimestamped(timestampBuilderConfigurator)
    );

    verifyNoInteractions(timestampBuilderConfigurator);
  }

  @Test
  public void buildTimestamped_WhenSpecifiedFileIsPades_ThrowsPadesNestedContainerNotSupportedException() {
    CompositeContainerBuilder builder = CompositeContainerBuilder
            .fromContainerFile("src/test/resources/testFiles/valid-containers/valid-pades-esteid2018.pdf")
            .withConfiguration(Configuration.of(Configuration.Mode.TEST));
    Consumer<TimestampBuilder> timestampBuilderConfigurator = mockConsumer();

    IllegalArgumentException caughtException = assertThrows(
            IllegalArgumentException.class,
            () -> builder.buildTimestamped(timestampBuilderConfigurator)
    );

    assertThat(caughtException.getMessage(), equalTo("Unsupported nested container type: PADES"));
    verifyNoInteractions(timestampBuilderConfigurator);
  }

  @Test
  public void buildTimestamped_WhenSpecifiedStreamIsPades_ThrowsParsingException() {
    FileDocument nestedContainerFile = new FileDocument(
            "src/test/resources/testFiles/valid-containers/valid-pades-esteid2018.pdf"
    );
    CompositeContainerBuilder builder = CompositeContainerBuilder
            .fromContainerStream(nestedContainerFile.openStream(), CONTAINER_FILE_NAME)
            .withConfiguration(Configuration.of(Configuration.Mode.TEST));
    Consumer<TimestampBuilder> timestampBuilderConfigurator = mockConsumer();

    assertThrows(
            DigiDoc4JException.class,
            () -> builder.buildTimestamped(timestampBuilderConfigurator)
    );

    verifyNoInteractions(timestampBuilderConfigurator);
  }

  @Test
  public void buildTimestamped_WhenTimestampBuilderIsConfigured_ChangesReflectInFinalTimestamp() {
    Instant notBefore = Instant.now();

    CompositeContainer compositeContainer = CompositeContainerBuilder
            .fromContainerFile("src/test/resources/testFiles/valid-containers/valid-asice.asice")
            .withConfiguration(Configuration.of(Configuration.Mode.TEST))
            .buildTimestamped(timestampBuilder -> timestampBuilder
                    .withTimestampDigestAlgorithm(DigestAlgorithm.SHA384)
                    .withTspSource("http://tsa.demo.sk.ee/tsarsa")
            );

    assertThat(compositeContainer, notNullValue());
    assertThat(compositeContainer.getNestingContainerTimestamps(), hasSize(1));
    assertTimeBetweenNotBeforeAndNow(
            compositeContainer.getNestingContainerTimestamps().get(0).getCreationTime(),
            notBefore, Duration.ofMinutes(1L)
    );
    assertThat(
            compositeContainer.getNestingContainerTimestamps().get(0).getCertificate().getSubjectName(X509Cert.SubjectName.CN),
            equalTo("DEMO SK TIMESTAMPING AUTHORITY 2023R")
    );
    assertThat(
            compositeContainer.getNestingContainerTimestamps().get(0).getDigestAlgorithm(),
            equalTo(DigestAlgorithm.SHA384)
    );
  }

  private static void buildTimestamped_WhenSpecifiedContainerIsAllowedType_CreatesTimestampedCompositeContainer(
          String nestedContainerPath,
          String nestedContainerTypeString,
          String nestedContainerMimeTypeString
  ) {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    Container nestedContainer = ContainerOpener.open(nestedContainerPath, configuration);
    Instant notBefore = Instant.now();

    CompositeContainer compositeContainer = CompositeContainerBuilder
            .fromContainer(nestedContainer, CONTAINER_FILE_NAME)
            .buildTimestamped(timestampBuilder -> {});

    assertThat(compositeContainer, notNullValue());
    assertThat(compositeContainer.getConfiguration(), sameInstance(configuration));
    assertThat(compositeContainer.getType(), equalTo(Constant.ASICS_CONTAINER_TYPE));
    assertThat(compositeContainer.getNestedContainerType(), equalTo(nestedContainerTypeString));
    assertThat(compositeContainer.getNestingContainerDataFiles(), hasSize(1));
    assertThat(compositeContainer.getNestingContainerDataFiles().get(0).getName(), equalTo(CONTAINER_FILE_NAME));
    assertThat(
            compositeContainer.getNestingContainerDataFiles().get(0).getMediaType(),
            equalTo(nestedContainerMimeTypeString)
    );
    assertThat(compositeContainer.getDataFiles(), equalTo(compositeContainer.getNestingContainerDataFiles()));
    assertThat(compositeContainer.getNestingContainerSignatures(), empty());
    assertThat(compositeContainer.getSignatures(), equalTo(compositeContainer.getNestingContainerSignatures()));
    assertThat(compositeContainer.getNestingContainerTimestamps(), hasSize(1));
    assertTimeBetweenNotBeforeAndNow(
            compositeContainer.getNestingContainerTimestamps().get(0).getCreationTime(),
            notBefore, Duration.ofMinutes(1L)
    );
    assertThat(compositeContainer.getTimestamps(), equalTo(compositeContainer.getNestingContainerTimestamps()));
    assertNestedContainerContents(compositeContainer, nestedContainer);
  }

  private static void buildTimestamped_WhenSpecifiedFileIsAllowedContainerType_CreatesTimestampedCompositeContainer(
          String nestedContainerPath,
          String nestedContainerTypeString,
          String nestedContainerMimeTypeString
  ) throws Exception {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    FileDocument nestedContainerFile = new FileDocument(nestedContainerPath);
    Instant notBefore = Instant.now();

    CompositeContainer compositeContainer = CompositeContainerBuilder
            .fromContainerFile(nestedContainerFile.getAbsolutePath())
            .withConfiguration(configuration)
            .buildTimestamped(timestampBuilder -> {});

    assertThat(compositeContainer, notNullValue());
    assertThat(compositeContainer.getConfiguration(), sameInstance(configuration));
    assertThat(compositeContainer.getType(), equalTo(Constant.ASICS_CONTAINER_TYPE));
    assertThat(compositeContainer.getNestedContainerType(), equalTo(nestedContainerTypeString));
    assertThat(compositeContainer.getNestingContainerDataFiles(), hasSize(1));
    assertThat(
            compositeContainer.getNestingContainerDataFiles().get(0).getName(),
            equalTo(nestedContainerFile.getName())
    );
    assertThat(
            compositeContainer.getNestingContainerDataFiles().get(0).getMediaType(),
            equalTo(nestedContainerMimeTypeString)
    );
    assertArrayEquals(
            IOUtils.toByteArray(nestedContainerFile.openStream()),
            compositeContainer.getNestingContainerDataFiles().get(0).getBytes()
    );
    assertThat(compositeContainer.getDataFiles(), equalTo(compositeContainer.getNestingContainerDataFiles()));
    assertThat(compositeContainer.getNestingContainerSignatures(), empty());
    assertThat(compositeContainer.getSignatures(), equalTo(compositeContainer.getNestingContainerSignatures()));
    assertThat(compositeContainer.getNestingContainerTimestamps(), hasSize(1));
    assertTimeBetweenNotBeforeAndNow(
            compositeContainer.getNestingContainerTimestamps().get(0).getCreationTime(),
            notBefore, Duration.ofMinutes(1L)
    );
    assertThat(compositeContainer.getTimestamps(), equalTo(compositeContainer.getNestingContainerTimestamps()));
    assertNestedContainerContents(compositeContainer, ContainerOpener
            .open(nestedContainerFile.getAbsolutePath(), configuration));
  }

  private static void buildTimestamped_WhenSpecifiedStreamIsAllowedContainerType_CreatesTimestampedCompositeContainer(
          String nestedContainerPath,
          String nestedContainerTypeString,
          String nestedContainerMimeTypeString
  ) throws Exception {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    FileDocument nestedContainerFile = new FileDocument(nestedContainerPath);
    Instant notBefore = Instant.now();

    CompositeContainer compositeContainer = CompositeContainerBuilder
            .fromContainerStream(nestedContainerFile.openStream(), CONTAINER_FILE_NAME)
            .withConfiguration(configuration)
            .buildTimestamped(timestampBuilder -> {});

    assertThat(compositeContainer, notNullValue());
    assertThat(compositeContainer.getConfiguration(), sameInstance(configuration));
    assertThat(compositeContainer.getType(), equalTo(Constant.ASICS_CONTAINER_TYPE));
    assertThat(compositeContainer.getNestedContainerType(), equalTo(nestedContainerTypeString));
    assertThat(compositeContainer.getNestingContainerDataFiles(), hasSize(1));
    assertThat(compositeContainer.getNestingContainerDataFiles().get(0).getName(), equalTo(CONTAINER_FILE_NAME));
    assertThat(
            compositeContainer.getNestingContainerDataFiles().get(0).getMediaType(),
            equalTo(nestedContainerMimeTypeString)
    );
    assertArrayEquals(
            IOUtils.toByteArray(nestedContainerFile.openStream()),
            compositeContainer.getNestingContainerDataFiles().get(0).getBytes()
    );
    assertThat(compositeContainer.getDataFiles(), equalTo(compositeContainer.getNestingContainerDataFiles()));
    assertThat(compositeContainer.getNestingContainerSignatures(), empty());
    assertThat(compositeContainer.getSignatures(), equalTo(compositeContainer.getNestingContainerSignatures()));
    assertThat(compositeContainer.getNestingContainerTimestamps(), hasSize(1));
    assertTimeBetweenNotBeforeAndNow(
            compositeContainer.getNestingContainerTimestamps().get(0).getCreationTime(),
            notBefore, Duration.ofMinutes(1L)
    );
    assertThat(compositeContainer.getTimestamps(), equalTo(compositeContainer.getNestingContainerTimestamps()));
    assertNestedContainerContents(compositeContainer, ContainerOpener
            .open(nestedContainerFile.openStream(), configuration));
  }

  private static void assertNestedContainerContents(CompositeContainer compositeContainer, Container nestedContainer) {
    assertThat(compositeContainer.getNestedContainerType(), equalTo(nestedContainer.getType()));
    assertThat(compositeContainer.getNestedContainerDataFiles(), hasSize(nestedContainer.getDataFiles().size()));
    for (int i = 0; i < nestedContainer.getDataFiles().size(); ++i) {
      assertThat(
              compositeContainer.getNestedContainerDataFiles().get(i).getName(),
              equalTo(nestedContainer.getDataFiles().get(i).getName())
      );
      assertThat(
              compositeContainer.getNestedContainerDataFiles().get(i).getMediaType(),
              equalTo(nestedContainer.getDataFiles().get(i).getMediaType())
      );
      Assert.assertArrayEquals(
              nestedContainer.getDataFiles().get(i).getBytes(),
              compositeContainer.getNestedContainerDataFiles().get(i).getBytes()
      );
    }
    assertThat(compositeContainer.getNestedContainerSignatures(), hasSize(nestedContainer.getSignatures().size()));
    for (int i = 0; i < nestedContainer.getSignatures().size(); ++i) {
      assertThat(
              compositeContainer.getNestedContainerSignatures().get(i).getUniqueId(),
              equalTo(nestedContainer.getSignatures().get(i).getUniqueId())
      );
    }
    assertThat(compositeContainer.getNestedContainerTimestamps(), hasSize(nestedContainer.getTimestamps().size()));
    for (int i = 0; i < nestedContainer.getTimestamps().size(); ++i) {
      assertThat(
              compositeContainer.getNestedContainerTimestamps().get(i).getUniqueId(),
              equalTo(nestedContainer.getTimestamps().get(i).getUniqueId())
      );
    }
  }

  @SuppressWarnings("unchecked")
  private static <T> Consumer<T> mockConsumer() {
    return (Consumer<T>) mock(Consumer.class);
  }

}
