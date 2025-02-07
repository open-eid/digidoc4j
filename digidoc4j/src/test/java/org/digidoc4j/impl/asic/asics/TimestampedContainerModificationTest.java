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
import org.digidoc4j.DataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.Timestamp;
import org.digidoc4j.TimestampBuilder;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.RemovingDataFileException;
import org.digidoc4j.exceptions.RemovingTimestampException;
import org.digidoc4j.impl.asic.cades.TimestampAndManifestPair;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;

import static org.digidoc4j.test.matcher.IsDssDocument.isDocumentWithName;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertThrows;

public class TimestampedContainerModificationTest extends AbstractTest {

  @Test
  public void addDataFile_WhenDataFileIsAddedToTimestampedContainer_ThrowsException() {
    Container container = createTimestampedAsics(1);
    DataFile dataFile = createTextDataFile("another.txt", "Test.");

    DigiDoc4JException caughtException = assertThrows(
            DigiDoc4JException.class,
            () -> container.addDataFile(dataFile)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Datafiles cannot be added to an already timestamped container")
    );
  }

  @Test
  public void addDataFile_WhenDataFileAsFileIsAddedToTimestampedContainer_ThrowsException() {
    Container container = createTimestampedAsics(1);
    File dataFile = new File("src/test/resources/testFiles/helper-files/test.txt");

    DigiDoc4JException caughtException = assertThrows(
            DigiDoc4JException.class,
            () -> container.addDataFile(dataFile, MimeTypeEnum.TEXT.getMimeTypeString())
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Datafiles cannot be added to an already timestamped container")
    );
  }

  @Test
  public void addDataFile_WhenDataFileAsPathIsAddedToTimestampedContainer_ThrowsException() {
    Container container = createTimestampedAsics(1);
    String dataFilePath = "src/test/resources/testFiles/helper-files/test.txt";

    DigiDoc4JException caughtException = assertThrows(
            DigiDoc4JException.class,
            () -> container.addDataFile(dataFilePath, MimeTypeEnum.TEXT.getMimeTypeString())
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Datafiles cannot be added to an already timestamped container")
    );
  }

  @Test
  public void addDataFile_WhenDataFileAsStreamIsAddedToTimestampedContainer_ThrowsException() {
    Container container = createTimestampedAsics(1);
    ByteArrayInputStream dataFileStream = new ByteArrayInputStream("This is a test file.".getBytes(StandardCharsets.UTF_8));

    DigiDoc4JException caughtException = assertThrows(
            DigiDoc4JException.class,
            () -> container.addDataFile(dataFileStream, "test.txt", MimeTypeEnum.TEXT.getMimeTypeString())
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Datafiles cannot be added to an already timestamped container")
    );
  }

  @Test
  public void removeDataFile_WhenDataFileIsRemovedFromTimestampedContainer_ThrowsException() {
    Container container = createTimestampedAsics(1);
    DataFile dataFile = container.getDataFiles().get(0);

    RemovingDataFileException caughtException = assertThrows(
            RemovingDataFileException.class,
            () -> container.removeDataFile(dataFile)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Datafiles cannot be removed from an already timestamped container")
    );
  }

  @Test
  public void addSignature_WhenSignatureIsAddedToTimestampedContainer_ThrowsException() {
    Container container = createTimestampedAsics(1);
    Signature signature = createSignatureBy(Container.DocumentType.ASICE, pkcs12Esteid2018SignatureToken);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> container.addSignature(signature)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Not supported: Not for ASiC-S container")
    );
  }

  @Test
  public void removeTimestamp_WhenRemovingTimestampThatIsCoveredByAnotherTimestamp_ThrowsException() {
    Container container = createTimestampedAsics(2);
    Timestamp initialTimestamp = container.getTimestamps().get(0);

    RemovingTimestampException caughtException = assertThrows(
            RemovingTimestampException.class,
            () -> container.removeTimestamp(initialTimestamp)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Timestamp cannot be removed; it is covered by other timestamp(s)")
    );
  }

  @Test
  public void removeTimestamp_WhenTimestampWithManifestBecomesLastTimestamp_ManifestIsRenamedToUnindexedName() {
    Container container = createTimestampedAsics(3);
    TimestampAndManifestPair firstTimestampWithManifest = (TimestampAndManifestPair) container.getTimestamps().get(1);
    assertThat(firstTimestampWithManifest.getCadesTimestamp(), notNullValue());
    assertThat(firstTimestampWithManifest.getArchiveManifest().getManifestDocument(), isDocumentWithName("META-INF/ASiCArchiveManifest001.xml"));
    Timestamp lastTimestamp = container.getTimestamps().get(2);

    container.removeTimestamp(lastTimestamp);

    assertThat(container.getTimestamps(), hasSize(2));
    assertThat(container.getTimestamps().get(1), sameInstance(firstTimestampWithManifest));
    assertThat(firstTimestampWithManifest.getCadesTimestamp(), notNullValue());
    assertThat(firstTimestampWithManifest.getArchiveManifest().getManifestDocument(), isDocumentWithName("META-INF/ASiCArchiveManifest.xml"));
  }

  @Test
  public void removeTimestamp_WhenTimestampedAreRemovedFromLastToFirst_AllTimestampsAreRemovedSuccessfully() {
    Container container = createTimestampedAsics(3);
    assertThat(container.getTimestamps(), hasSize(3));

    container.removeTimestamp(container.getTimestamps().get(2));
    assertThat(container.getTimestamps(), hasSize(2));

    container.removeTimestamp(container.getTimestamps().get(1));
    assertThat(container.getTimestamps(), hasSize(1));

    container.removeTimestamp(container.getTimestamps().get(0));
    assertThat(container.getTimestamps(), empty());
  }

  private Container createTimestampedAsics(int timestampCount) {
    Container container = ContainerBuilder
            .aContainer(Container.DocumentType.ASICS)
            .withConfiguration(configuration)
            .withDataFile(createTextDataFile("test.txt", "This is a test file."))
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
