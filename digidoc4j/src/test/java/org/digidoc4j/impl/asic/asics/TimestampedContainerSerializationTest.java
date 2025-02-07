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

import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import org.apache.commons.lang3.tuple.Pair;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.DataFile;
import org.digidoc4j.TimestampBuilder;
import org.digidoc4j.impl.asic.cades.TimestampAndManifestPair;
import org.digidoc4j.test.util.TestZipUtil;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.function.Function;
import java.util.function.UnaryOperator;
import java.util.zip.ZipEntry;

import static org.digidoc4j.test.matcher.IsDataFile.isDataFileWithNameAndMediaType;
import static org.digidoc4j.test.matcher.IsDssDocument.isDocumentWithNameAndMimeType;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

public class TimestampedContainerSerializationTest extends AbstractTest {

  @Test
  public void save_WhenAsicsWithSingleTimestampIsSerialized_ResultingZipContainerContainsExpectedEntries() {
    serialize_WhenAsicsWithSingleTimestampIsSerialized_ResultingZipContainerContainsExpectedEntries(container -> {
      ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

      container.save(byteArrayOutputStream);

      return TestZipUtil.readEntries(byteArrayOutputStream.toByteArray());
    });
  }

  @Test
  public void saveAsFile_WhenAsicsWithSingleTimestampIsSerialized_ResultingZipContainerContainsExpectedEntries() {
    serialize_WhenAsicsWithSingleTimestampIsSerialized_ResultingZipContainerContainsExpectedEntries(container -> {
      File file = createTemporaryFileByExtension("asics");

      container.saveAsFile(file.getPath());

      return TestZipUtil.readEntries(file);
    });
  }

  @Test
  public void saveAsStream_WhenAsicsWithSingleTimestampIsSerialized_ResultingZipContainerContainsExpectedEntries() {
    serialize_WhenAsicsWithSingleTimestampIsSerialized_ResultingZipContainerContainsExpectedEntries(container -> {
      try (InputStream inputStream = container.saveAsStream()) {
        return TestZipUtil.readEntries(inputStream);
      } catch (IOException e) {
          throw new IllegalStateException("Failed to save container as stream", e);
      }
    });
  }

  private void serialize_WhenAsicsWithSingleTimestampIsSerialized_ResultingZipContainerContainsExpectedEntries(
          Function<Container, List<Pair<ZipEntry, byte[]>>> containerToZipSerializer
  ) {
    DataFile dataFile = new DataFile(new byte[] {0, 1, 2, 3}, "name.ext", MimeTypeEnum.TEXT.getMimeTypeString());
    Container container = createTimestampedAsics(dataFile, 1);

    List<Pair<ZipEntry, byte[]>> containerEntries = containerToZipSerializer.apply(container);

    assertThat(containerEntries, hasSize(4));
    assertThat(containerEntries.get(0).getKey().getName(), equalTo(ASiCUtils.MIME_TYPE));
    assertThat(containerEntries.get(0).getKey().getMethod(), equalTo(ZipEntry.STORED));
    assertThat(containerEntries.get(0).getValue(), is(MimeTypeEnum.ASICS.getMimeTypeString().getBytes(StandardCharsets.UTF_8)));
    assertThat(containerEntries.get(1).getKey().getName(), equalTo("META-INF/manifest.xml"));
    assertThat(containerEntries.get(1).getKey().getMethod(), equalTo(ZipEntry.DEFLATED));
    assertThat(containerEntries.get(2).getKey().getName(), equalTo("name.ext"));
    assertThat(containerEntries.get(2).getKey().getMethod(), equalTo(ZipEntry.DEFLATED));
    assertThat(containerEntries.get(2).getValue(), is(new byte[] {0, 1, 2, 3}));
    assertThat(containerEntries.get(3).getKey().getName(), equalTo("META-INF/timestamp.tst"));
    assertThat(containerEntries.get(3).getKey().getMethod(), equalTo(ZipEntry.DEFLATED));
  }

  @Test
  public void save_WhenAsicsWithMultipleTimestampsIsSerialized_ResultingZipContainerContainsExpectedEntries() {
    serialize_WhenAsicsWithMultipleTimestampsIsSerialized_ResultingZipContainerContainsExpectedEntries(container -> {
      ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

      container.save(byteArrayOutputStream);

      return TestZipUtil.readEntries(byteArrayOutputStream.toByteArray());
    });
  }

  @Test
  public void saveAsFile_WhenAsicsWithMultipleTimestampsIsSerialized_ResultingZipContainerContainsExpectedEntries() {
    serialize_WhenAsicsWithMultipleTimestampsIsSerialized_ResultingZipContainerContainsExpectedEntries(container -> {
      File file = createTemporaryFileByExtension("asics");

      container.saveAsFile(file.getPath());

      return TestZipUtil.readEntries(file);
    });
  }

  @Test
  public void saveAsStream_WhenAsicsWithMultipleTimestampsIsSerialized_ResultingZipContainerContainsExpectedEntries() {
    serialize_WhenAsicsWithMultipleTimestampsIsSerialized_ResultingZipContainerContainsExpectedEntries(container -> {
      try (InputStream inputStream = container.saveAsStream()) {
        return TestZipUtil.readEntries(inputStream);
      } catch (IOException e) {
        throw new IllegalStateException("Failed to save container as stream", e);
      }
    });
  }

  private void serialize_WhenAsicsWithMultipleTimestampsIsSerialized_ResultingZipContainerContainsExpectedEntries(
          Function<Container, List<Pair<ZipEntry, byte[]>>> containerToZipSerializer
  ) {
    DataFile dataFile = new DataFile(new byte[] {(byte) 0x89, 'P', 'N', 'G'}, "img.png", MimeTypeEnum.PNG.getMimeTypeString());
    Container container = createTimestampedAsics(dataFile, 3);

    List<Pair<ZipEntry, byte[]>> containerEntries = containerToZipSerializer.apply(container);

    assertThat(containerEntries, hasSize(8));
    assertThat(containerEntries.get(0).getKey().getName(), equalTo(ASiCUtils.MIME_TYPE));
    assertThat(containerEntries.get(0).getKey().getMethod(), equalTo(ZipEntry.STORED));
    assertThat(containerEntries.get(0).getValue(), is(MimeTypeEnum.ASICS.getMimeTypeString().getBytes(StandardCharsets.UTF_8)));
    assertThat(containerEntries.get(1).getKey().getName(), equalTo("META-INF/manifest.xml"));
    assertThat(containerEntries.get(1).getKey().getMethod(), equalTo(ZipEntry.DEFLATED));
    assertThat(containerEntries.get(2).getKey().getName(), equalTo("img.png"));
    assertThat(containerEntries.get(2).getKey().getMethod(), equalTo(ZipEntry.DEFLATED));
    assertThat(containerEntries.get(2).getValue(), is(new byte[] {(byte) 0x89, 'P', 'N', 'G'}));
    assertThat(containerEntries.get(3).getKey().getName(), equalTo("META-INF/timestamp.tst"));
    assertThat(containerEntries.get(3).getKey().getMethod(), equalTo(ZipEntry.DEFLATED));
    assertThat(containerEntries.get(4).getKey().getName(), equalTo("META-INF/timestamp002.tst"));
    assertThat(containerEntries.get(4).getKey().getMethod(), equalTo(ZipEntry.DEFLATED));
    assertThat(containerEntries.get(5).getKey().getName(), equalTo("META-INF/ASiCArchiveManifest001.xml"));
    assertThat(containerEntries.get(5).getKey().getMethod(), equalTo(ZipEntry.DEFLATED));
    assertThat(containerEntries.get(6).getKey().getName(), equalTo("META-INF/timestamp003.tst"));
    assertThat(containerEntries.get(6).getKey().getMethod(), equalTo(ZipEntry.DEFLATED));
    assertThat(containerEntries.get(7).getKey().getName(), equalTo("META-INF/ASiCArchiveManifest.xml"));
    assertThat(containerEntries.get(7).getKey().getMethod(), equalTo(ZipEntry.DEFLATED));
  }

  @Test
  public void save_WhenSerializedAsicsWithTimestampsIsParsed_ResultingContainerContainsExpectedEntries() {
    serialize_WhenSerializedAsicsWithTimestampsIsParsed_ResultingContainerContainsExpectedEntries(container -> {
      ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

      container.save(byteArrayOutputStream);

      return ContainerOpener.open(new ByteArrayInputStream(byteArrayOutputStream.toByteArray()), configuration);
    });
  }

  @Test
  public void saveAsFile_WhenSerializedAsicsWithTimestampsIsParsed_ResultingContainerContainsExpectedEntries() {
    serialize_WhenSerializedAsicsWithTimestampsIsParsed_ResultingContainerContainsExpectedEntries(container -> {
      File file = createTemporaryFileByExtension("asics");

      container.saveAsFile(file.getPath());

      return ContainerOpener.open(file.getPath(), configuration);
    });
  }

  @Test
  public void saveAsStream_WhenSerializedAsicsWithTimestampsIsParsed_ResultingContainerContainsExpectedEntries() {
    serialize_WhenSerializedAsicsWithTimestampsIsParsed_ResultingContainerContainsExpectedEntries(container -> {
      try (InputStream inputStream = container.saveAsStream()) {
        return ContainerOpener.open(inputStream, configuration);
      } catch (IOException e) {
        throw new IllegalStateException("Failed to save container as stream", e);
      }
    });
  }

  private void serialize_WhenSerializedAsicsWithTimestampsIsParsed_ResultingContainerContainsExpectedEntries(
          UnaryOperator<Container> containerSerializerAndDeserializer
  ) {
    DataFile dataFile = createTextDataFile("test.txt", "This is a test file.");
    Container container = createTimestampedAsics(dataFile, 2);

    Container result = containerSerializerAndDeserializer.apply(container);

    assertThat(result.getType(), equalTo(Constant.ASICS_CONTAINER_TYPE));
    assertThat(result.getDataFiles(), contains(
            isDataFileWithNameAndMediaType("test.txt", MimeTypeEnum.TEXT)
    ));
    assertThat(result.getSignatures(), empty());
    assertThat(result.getTimestamps(), hasSize(2));
    assertThat(result.getTimestamps().get(0), instanceOf(TimestampAndManifestPair.class));
    TimestampAndManifestPair timestamp0 = (TimestampAndManifestPair) result.getTimestamps().get(0);
    assertThat(
            timestamp0.getCadesTimestamp().getTimestampDocument(),
            isDocumentWithNameAndMimeType("META-INF/timestamp.tst", MimeTypeEnum.TST)
    );
    assertThat(timestamp0.getArchiveManifest(), nullValue());
    TimestampAndManifestPair timestamp1 = (TimestampAndManifestPair) result.getTimestamps().get(1);
    assertThat(
            timestamp1.getCadesTimestamp().getTimestampDocument(),
            isDocumentWithNameAndMimeType("META-INF/timestamp002.tst", MimeTypeEnum.TST)
    );
    assertThat(timestamp1.getArchiveManifest(), notNullValue());
    assertThat(
            timestamp1.getArchiveManifest().getManifestDocument(),
            isDocumentWithNameAndMimeType("META-INF/ASiCArchiveManifest.xml", MimeTypeEnum.XML)
    );
  }

  private Container createTimestampedAsics(DataFile dataFile, int timestampCount) {
    Container container = ContainerBuilder
            .aContainer(Container.DocumentType.ASICS)
            .withConfiguration(configuration)
            .withDataFile(dataFile)
            .build();

    for (int i = 0; i < timestampCount; ++i) {
      container.addTimestamp(TimestampBuilder.aTimestamp(container).invokeTimestamping());
    }
    return container;
  }

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
  }

}
