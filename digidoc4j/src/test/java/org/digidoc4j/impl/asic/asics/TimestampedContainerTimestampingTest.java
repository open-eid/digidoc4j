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
import eu.europa.esig.dss.spi.DSSUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.Timestamp;
import org.digidoc4j.TimestampBuilder;
import org.digidoc4j.exceptions.IllegalTimestampException;
import org.digidoc4j.impl.asic.cades.AsicArchiveManifest;
import org.digidoc4j.test.MatchAllCertificateStoreSelector;
import org.junit.Test;

import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;

public class TimestampedContainerTimestampingTest extends AbstractTest {

  @Test
  public void addTimestamp_WhenContainerWithInMemoryDataFileIsTimestampedOnce_TimestampProperlyAdded() {
    Container container = createAsicsContainerWithInMemoryDataFile();
    Timestamp timestamp = TimestampBuilder.aTimestamp(container)
            .invokeTimestamping();

    container.addTimestamp(timestamp);

    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getDataFiles().get(0).getName(), equalTo("test.txt"));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(1));
    assertThat(container.getTimestamps().get(0), instanceOf(AsicSContainerTimestamp.class));
    AsicSContainerTimestamp asicsTimestamp = (AsicSContainerTimestamp) container.getTimestamps().get(0);
    assertThat(asicsTimestamp.getArchiveManifest(), nullValue());
  }

  @Test
  public void addTimestamp_WhenContainerWithDataFileFromFileIsTimestampedOnce_TimestampProperlyAdded() {
    Container container = createAsicsContainerWithDataFileFromFile();
    Timestamp timestamp = TimestampBuilder.aTimestamp(container)
            .invokeTimestamping();

    container.addTimestamp(timestamp);

    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getDataFiles().get(0).getName(), equalTo("test.txt"));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(1));
    assertThat(container.getTimestamps().get(0), instanceOf(AsicSContainerTimestamp.class));
    AsicSContainerTimestamp asicsTimestamp = (AsicSContainerTimestamp) container.getTimestamps().get(0);
    assertThat(asicsTimestamp.getArchiveManifest(), nullValue());
  }

  @Test
  public void addTimestamp_WhenContainerWithInMemoryDataFileIsTimestampedTwice_DataFileIsCorrectlyReferencedInManifest() {
    Container container = createAsicsContainerWithInMemoryDataFile();
    container.addTimestamp(TimestampBuilder.aTimestamp(container).invokeTimestamping());
    Timestamp timestamp = TimestampBuilder.aTimestamp(container)
            .invokeTimestamping();

    container.addTimestamp(timestamp);

    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getDataFiles().get(0).getName(), equalTo("test.txt"));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(2));
    assertThat(container.getTimestamps().get(1), instanceOf(AsicSContainerTimestamp.class));
    AsicSContainerTimestamp asicsTimestamp = (AsicSContainerTimestamp) container.getTimestamps().get(1);
    assertThat(asicsTimestamp.getArchiveManifest(), notNullValue(AsicArchiveManifest.class));
    assertThat(asicsTimestamp.getArchiveManifest().getReferencedDataObjects(), hasSize(2));
    List<AsicArchiveManifest.DataReference> references = asicsTimestamp.getArchiveManifest().getReferencedDataObjects();
    assertThat(references.get(0).getName(), equalTo("META-INF/timestamp.tst"));
    assertThat(references.get(0).getMimeType(), equalTo(MimeTypeEnum.TST.getMimeTypeString()));
    assertThat(references.get(1).getName(), equalTo("test.txt"));
    assertThat(references.get(1).getMimeType(), equalTo(MimeTypeEnum.TEXT.getMimeTypeString()));
  }

  @Test
  public void addTimestamp_WhenContainerWithDataFileFromFileIsTimestampedTwice_DataFileIsCorrectlyReferencedInManifest() {
    Container container = createAsicsContainerWithDataFileFromFile();
    container.addTimestamp(TimestampBuilder.aTimestamp(container).invokeTimestamping());
    Timestamp timestamp = TimestampBuilder.aTimestamp(container)
            .invokeTimestamping();

    container.addTimestamp(timestamp);

    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getDataFiles().get(0).getName(), equalTo("test.txt"));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(2));
    assertThat(container.getTimestamps().get(1), instanceOf(AsicSContainerTimestamp.class));
    AsicSContainerTimestamp asicsTimestamp = (AsicSContainerTimestamp) container.getTimestamps().get(1);
    assertThat(asicsTimestamp.getArchiveManifest(), notNullValue(AsicArchiveManifest.class));
    assertThat(asicsTimestamp.getArchiveManifest().getReferencedDataObjects(), hasSize(2));
    List<AsicArchiveManifest.DataReference> references = asicsTimestamp.getArchiveManifest().getReferencedDataObjects();
    assertThat(references.get(0).getName(), equalTo("META-INF/timestamp.tst"));
    assertThat(references.get(0).getMimeType(), equalTo(MimeTypeEnum.TST.getMimeTypeString()));
    assertThat(references.get(1).getName(), equalTo("test.txt"));
    assertThat(references.get(1).getMimeType(), equalTo(MimeTypeEnum.TEXT.getMimeTypeString()));
  }

  @Test
  public void addTimestamp_WhenSecondTimestampIsAdded_PreviousTimestampTokenIsAugmented() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/1xTST-text-data-file.asics",
            configuration
    );
    assertThat(container.getTimestamps(), hasSize(1));
    assertThat(
            container.getTimestamps().get(0).getCreationTime(),
            equalTo(Date.from(Instant.parse("2024-05-28T12:24:09Z")))
    );
    assertThat(
            container.getTimestamps().get(0).getCertificate().getSubjectName(),
            equalTo("C=EE, O=SK ID Solutions AS, OID.2.5.4.97=NTREE-10747013, CN=DEMO SK TIMESTAMPING AUTHORITY 2023E")
    );
    Collection<X509CertificateHolder> initialTimestampCertificates = container.getTimestamps().get(0)
            .getTimeStampToken().getCertificates().getMatches(new MatchAllCertificateStoreSelector());
    assertThat(initialTimestampCertificates, hasSize(1));

    Timestamp timestamp2 = TimestampBuilder.aTimestamp(container).invokeTimestamping();
    container.addTimestamp(timestamp2);

    assertThat(container.getTimestamps(), hasSize(2));
    assertThat(
            container.getTimestamps().get(0).getCreationTime(),
            equalTo(Date.from(Instant.parse("2024-05-28T12:24:09Z")))
    );
    assertThat(
            container.getTimestamps().get(0).getCertificate().getSubjectName(),
            equalTo("C=EE, O=SK ID Solutions AS, OID.2.5.4.97=NTREE-10747013, CN=DEMO SK TIMESTAMPING AUTHORITY 2023E")
    );
    Collection<X509CertificateHolder> augmentedTimestampCertificates = container.getTimestamps().get(0)
            .getTimeStampToken().getCertificates().getMatches(new MatchAllCertificateStoreSelector());
    assertThat(augmentedTimestampCertificates, hasSize(3));
    assertThat(container.getTimestamps().get(1), sameInstance(timestamp2));
  }

  @Test
  public void addTimestamp_WhenThirdTimestampIsAdded_ManifestOfPreviousTimestampIsRenamed() throws Exception {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/2xTST-text-data-file.asics",
            configuration
    );
    assertThat(container.getTimestamps(), hasSize(2));
    AsicSContainerTimestamp timestamp1 = (AsicSContainerTimestamp) container.getTimestamps().get(0);
    assertThat(timestamp1.getCadesTimestamp().getTimestampDocument().getName(), equalTo("META-INF/timestamp.tst"));
    assertThat(timestamp1.getArchiveManifest(), nullValue());
    AsicSContainerTimestamp timestamp2 = (AsicSContainerTimestamp) container.getTimestamps().get(1);
    assertThat(timestamp2.getCadesTimestamp().getTimestampDocument().getName(), equalTo("META-INF/timestamp002.tst"));
    assertThat(timestamp2.getArchiveManifest(), notNullValue(AsicArchiveManifest.class));
    AsicArchiveManifest timestamp2Manifest = timestamp2.getArchiveManifest();
    assertThat(timestamp2Manifest.getManifestDocument().getName(), equalTo("META-INF/ASiCArchiveManifest.xml"));

    Timestamp timestamp3 = TimestampBuilder.aTimestamp(container).invokeTimestamping();
    container.addTimestamp(timestamp3);

    assertThat(container.getTimestamps(), hasSize(3));
    assertThat(container.getTimestamps().get(0), sameInstance(timestamp1));
    assertThat(timestamp1.getCadesTimestamp().getTimestampDocument().getName(), equalTo("META-INF/timestamp.tst"));
    assertThat(timestamp1.getArchiveManifest(), nullValue());
    AsicSContainerTimestamp newTimestamp2 = (AsicSContainerTimestamp) container.getTimestamps().get(1);
    assertThat(newTimestamp2.getCadesTimestamp().getTimestampDocument().getName(), equalTo("META-INF/timestamp002.tst"));
    assertThat(newTimestamp2.getArchiveManifest(), sameInstance(timestamp2Manifest));
    AsicArchiveManifest newTimestamp2Manifest = timestamp2.getArchiveManifest();
    assertThat(newTimestamp2Manifest.getManifestDocument().getName(), equalTo("META-INF/ASiCArchiveManifest001.xml"));
    assertArrayEquals(
            DSSUtils.toByteArray(timestamp2Manifest.getManifestDocument()),
            DSSUtils.toByteArray(newTimestamp2Manifest.getManifestDocument())
    );
    assertThat(container.getTimestamps().get(2), sameInstance(timestamp3));
  }

  @Test
  public void addTimestamp_WhenSecondTimestampIsAddedButContainerContentDoesNotMatchWithTimestamp_ThrowsException() {
    Container container = createAsicsContainerWithInMemoryDataFile();
    Timestamp timestamp1 = TimestampBuilder.aTimestamp(container).invokeTimestamping();
    Timestamp timestamp2 = TimestampBuilder.aTimestamp(container).invokeTimestamping();
    container.addTimestamp(timestamp1);

    IllegalTimestampException caughtException = assertThrows(
            IllegalTimestampException.class,
            () -> container.addTimestamp(timestamp2)
    );

    assertThat(caughtException.getMessage(),
            equalTo("Cannot add timestamp not covering the entire contents of a container"));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(1));
    assertThat(container.getTimestamps().get(0), sameInstance(timestamp1));
  }

  @Test
  public void addTimestamp_WhenThirdTimestampIsAddedButContainerContentDoesNotMatchWithTimestamp_ThrowsException() {
    Container container = createAsicsContainerWithInMemoryDataFile();
    Timestamp timestamp1 = TimestampBuilder.aTimestamp(container).invokeTimestamping();
    container.addTimestamp(timestamp1);
    Timestamp timestamp2 = TimestampBuilder.aTimestamp(container).invokeTimestamping();
    Timestamp timestamp3 = TimestampBuilder.aTimestamp(container).invokeTimestamping();
    container.addTimestamp(timestamp2);

    IllegalTimestampException caughtException = assertThrows(
            IllegalTimestampException.class,
            () -> container.addTimestamp(timestamp3)
    );

    assertThat(caughtException.getMessage(),
            equalTo("Cannot add timestamp not covering the entire contents of a container"));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getSignatures(), empty());
    assertThat(container.getTimestamps(), hasSize(2));
  }

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
  }

  private Container createAsicsContainerWithInMemoryDataFile() {
    return ContainerBuilder
            .aContainer(Container.DocumentType.ASICS)
            .withConfiguration(configuration)
            .withDataFile(createTextDataFile("test.txt", "This is a test file."))
            .build();
  }

  private Container createAsicsContainerWithDataFileFromFile() {
    return ContainerBuilder
            .aContainer(Container.DocumentType.ASICS)
            .withConfiguration(configuration)
            .withDataFile("src/test/resources/testFiles/helper-files/test.txt", MimeTypeEnum.TEXT.getMimeTypeString())
            .build();
  }

}
