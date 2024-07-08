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
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.impl.asic.cades.AsicArchiveManifest;
import org.junit.Test;

import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

public class TimestampedContainerParsingTest extends AbstractTest {

  @Test
  public void openContainer_WhenAsicsWithOnlyDataFile_AsicsWithOneDataFileAndNoTimestampsNorSignaturesIsOpened() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/container_without_signatures.asics",
            configuration
    );

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getDataFiles().get(0).getName(), equalTo("test.txt"));
    assertThat(container.getDataFiles().get(0).getMediaType(), equalTo(MimeTypeEnum.TEXT.getMimeTypeString()));
    assertThat(container.getTimestamps(), empty());
    assertThat(container.getSignatures(), empty());
  }

  @Test
  public void openContainer_WhenAsicsWithOneTimestamp_AsicsWithOneDataFileAndOneTimestampIsOpened() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/testtimestamp.asics",
            configuration
    );

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getDataFiles().get(0).getName(), equalTo("test.txt"));
    assertThat(container.getDataFiles().get(0).getMediaType(), equalTo(MimeTypeEnum.TEXT.getMimeTypeString()));
    assertThat(container.getTimestamps(), hasSize(1));
    assertThat(container.getTimestamps().get(0), instanceOf(AsicSContainerTimestamp.class));
    assertThat(container.getTimestamps().get(0).getCreationTime(), equalTo(Date.from(Instant.parse("2017-11-24T08:20:33Z"))));
    AsicSContainerTimestamp asicsTimestamp = (AsicSContainerTimestamp) container.getTimestamps().get(0);
    assertThat(asicsTimestamp.getCadesTimestamp().getTimestampDocument().getName(), equalTo("META-INF/timestamp.tst"));
    assertThat(asicsTimestamp.getCadesTimestamp().getTimestampDocument().getMimeType(), equalTo(MimeTypeEnum.TST));
    assertThat(asicsTimestamp.getArchiveManifest(), nullValue());
    assertThat(container.getSignatures(), empty());
  }

  @Test
  public void openContainer_WhenAsicsWith3Timestamps_AsicsWithOneDataFileAnd3TimestampsInExpectedOrderIsOpened() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/3xTST-text-data-file.asics",
            configuration
    );

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getDataFiles().get(0).getName(), equalTo("test.txt"));
    assertThat(container.getDataFiles().get(0).getMediaType(), equalTo(MimeTypeEnum.TEXT.getMimeTypeString()));
    assertThat(container.getTimestamps(), hasSize(3));
    assertThat(container.getTimestamps().get(0), instanceOf(AsicSContainerTimestamp.class));
    assertThat(container.getTimestamps().get(0).getCreationTime(), equalTo(Date.from(Instant.parse("2024-07-05T08:42:57Z"))));
    AsicSContainerTimestamp asicsTimestamp1 = (AsicSContainerTimestamp) container.getTimestamps().get(0);
    assertThat(asicsTimestamp1.getCadesTimestamp().getTimestampDocument().getName(), equalTo("META-INF/timestamp.tst"));
    assertThat(asicsTimestamp1.getCadesTimestamp().getTimestampDocument().getMimeType(), equalTo(MimeTypeEnum.TST));
    assertThat(asicsTimestamp1.getArchiveManifest(), nullValue());
    assertThat(container.getTimestamps().get(1), instanceOf(AsicSContainerTimestamp.class));
    assertThat(container.getTimestamps().get(1).getCreationTime(), equalTo(Date.from(Instant.parse("2024-07-05T08:44:04Z"))));
    AsicSContainerTimestamp asicsTimestamp2 = (AsicSContainerTimestamp) container.getTimestamps().get(1);
    assertThat(asicsTimestamp2.getCadesTimestamp().getTimestampDocument().getName(), equalTo("META-INF/timestamp002.tst"));
    assertThat(asicsTimestamp2.getCadesTimestamp().getTimestampDocument().getMimeType(), equalTo(MimeTypeEnum.TST));
    assertThat(asicsTimestamp2.getArchiveManifest(), notNullValue(AsicArchiveManifest.class));
    assertThat(asicsTimestamp2.getArchiveManifest().getReferencedTimestamp().getName(), equalTo("META-INF/timestamp002.tst"));
    assertThat(asicsTimestamp2.getArchiveManifest().getManifestDocument().getName(), equalTo("META-INF/ASiCArchiveManifest001.xml"));
    assertThat(asicsTimestamp2.getArchiveManifest().getManifestDocument().getMimeType(), equalTo(MimeTypeEnum.XML));
    assertThat(asicsTimestamp2.getArchiveManifest().getNonNullEntryNames(), equalTo(new HashSet<>(Arrays.asList(
            "test.txt", "META-INF/timestamp.tst"
    ))));
    assertThat(container.getTimestamps().get(2), instanceOf(AsicSContainerTimestamp.class));
    assertThat(container.getTimestamps().get(2).getCreationTime(), equalTo(Date.from(Instant.parse("2024-07-05T08:45:10Z"))));
    AsicSContainerTimestamp asicsTimestamp3 = (AsicSContainerTimestamp) container.getTimestamps().get(2);
    assertThat(asicsTimestamp3.getCadesTimestamp().getTimestampDocument().getName(), equalTo("META-INF/timestamp003.tst"));
    assertThat(asicsTimestamp3.getCadesTimestamp().getTimestampDocument().getMimeType(), equalTo(MimeTypeEnum.TST));
    assertThat(asicsTimestamp3.getArchiveManifest(), notNullValue(AsicArchiveManifest.class));
    assertThat(asicsTimestamp3.getArchiveManifest().getReferencedTimestamp().getName(), equalTo("META-INF/timestamp003.tst"));
    assertThat(asicsTimestamp3.getArchiveManifest().getManifestDocument().getName(), equalTo("META-INF/ASiCArchiveManifest.xml"));
    assertThat(asicsTimestamp3.getArchiveManifest().getManifestDocument().getMimeType(), equalTo(MimeTypeEnum.XML));
    assertThat(asicsTimestamp3.getArchiveManifest().getNonNullEntryNames(), equalTo(new HashSet<>(Arrays.asList(
            "test.txt", "META-INF/timestamp.tst", "META-INF/timestamp002.tst", "META-INF/ASiCArchiveManifest001.xml"
    ))));
    assertThat(container.getSignatures(), empty());
  }

  @Test
  public void openContainer_WhenAsicsWithOneTimestampWithoutManifest_DataFileMimeTypeIsInferred() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/1xTST-image-no-manifest.asics",
            configuration
    );

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getDataFiles().get(0).getName(), equalTo("smile.png"));
    assertThat(container.getDataFiles().get(0).getMediaType(), equalTo(MimeTypeEnum.PNG.getMimeTypeString()));
    assertThat(container.getTimestamps(), hasSize(1));
    assertThat(container.getTimestamps().get(0), instanceOf(AsicSContainerTimestamp.class));
    AsicSContainerTimestamp asicsTimestamp = (AsicSContainerTimestamp) container.getTimestamps().get(0);
    assertThat(asicsTimestamp.getArchiveManifest(), nullValue());
    assertThat(container.getSignatures(), empty());
  }

  @Test
  public void openContainer_WhenAsicsWithOneTimestampAndManifestOverridesDataFileMimeType_DataFileMimeTypeAsSpecifiedInManifest() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/1xTST-image-but-pdf-in-manifest.asics",
            configuration
    );

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getDataFiles().get(0).getName(), equalTo("smile.png"));
    assertThat(container.getDataFiles().get(0).getMediaType(), equalTo(MimeTypeEnum.PDF.getMimeTypeString()));
    assertThat(container.getTimestamps(), hasSize(1));
    assertThat(container.getTimestamps().get(0), instanceOf(AsicSContainerTimestamp.class));
    AsicSContainerTimestamp asicsTimestamp = (AsicSContainerTimestamp) container.getTimestamps().get(0);
    assertThat(asicsTimestamp.getArchiveManifest(), nullValue());
    assertThat(container.getSignatures(), empty());
  }

  @Test
  public void openContainer_WhenAsicsWith3TimestampsAndDifferentMimeTypesInDifferentManifests_MimeTypesOfLastManifestAreApplied() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/3xTST-different-mimetypes-in-different-manifests.asics",
            configuration
    );

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getDataFiles().get(0).getName(), equalTo("smile.png"));
    assertThat(container.getDataFiles().get(0).getMediaType(), equalTo("custom-mimetype"));
    assertThat(container.getTimestamps(), hasSize(3));
    assertThat(container.getTimestamps().get(0), instanceOf(AsicSContainerTimestamp.class));
    AsicSContainerTimestamp asicsTimestamp1 = (AsicSContainerTimestamp) container.getTimestamps().get(0);
    assertThat(asicsTimestamp1.getCadesTimestamp().getTimestampDocument().getName(), equalTo("META-INF/timestamp.tst"));
    assertThat(asicsTimestamp1.getCadesTimestamp().getTimestampDocument().getMimeType(), equalTo(MimeTypeEnum.SVG));
    assertThat(asicsTimestamp1.getArchiveManifest(), nullValue());
    assertThat(container.getTimestamps().get(1), instanceOf(AsicSContainerTimestamp.class));
    AsicSContainerTimestamp asicsTimestamp2 = (AsicSContainerTimestamp) container.getTimestamps().get(1);
    assertThat(asicsTimestamp2.getCadesTimestamp().getTimestampDocument().getName(), equalTo("META-INF/timestamp002.tst"));
    assertThat(asicsTimestamp2.getCadesTimestamp().getTimestampDocument().getMimeType(), equalTo(MimeTypeEnum.XML));
    assertThat(asicsTimestamp2.getArchiveManifest(), notNullValue(AsicArchiveManifest.class));
    assertThat(asicsTimestamp2.getArchiveManifest().getReferencedTimestamp().getName(), equalTo("META-INF/timestamp002.tst"));
    assertThat(asicsTimestamp2.getArchiveManifest().getManifestDocument().getName(), equalTo("META-INF/ASiCArchiveManifest001.xml"));
    assertThat(asicsTimestamp2.getArchiveManifest().getManifestDocument().getMimeType(), equalTo(MimeTypeEnum.PKCS7));
    assertThat(asicsTimestamp2.getArchiveManifest().getReferencedTimestamp().getMimeType(), equalTo(MimeTypeEnum.HTML.getMimeTypeString()));
    assertThat(asicsTimestamp2.getArchiveManifest().getReferencedDataObjects(), hasSize(2));
    assertThat(asicsTimestamp2.getArchiveManifest().getReferencedDataObjects().get(0).getName(), equalTo("META-INF/timestamp.tst"));
    assertThat(asicsTimestamp2.getArchiveManifest().getReferencedDataObjects().get(0).getMimeType(), equalTo(MimeTypeEnum.JSON.getMimeTypeString()));
    assertThat(asicsTimestamp2.getArchiveManifest().getReferencedDataObjects().get(1).getName(), equalTo("smile.png"));
    assertThat(asicsTimestamp2.getArchiveManifest().getReferencedDataObjects().get(1).getMimeType(), equalTo(MimeTypeEnum.JPEG.getMimeTypeString()));
    assertThat(container.getTimestamps().get(2), instanceOf(AsicSContainerTimestamp.class));
    AsicSContainerTimestamp asicsTimestamp3 = (AsicSContainerTimestamp) container.getTimestamps().get(2);
    assertThat(asicsTimestamp3.getCadesTimestamp().getTimestampDocument().getName(), equalTo("META-INF/timestamp003.tst"));
    assertThat(asicsTimestamp3.getCadesTimestamp().getTimestampDocument().getMimeType(), equalTo(MimeTypeEnum.ODP));
    assertThat(asicsTimestamp3.getArchiveManifest(), notNullValue(AsicArchiveManifest.class));
    assertThat(asicsTimestamp3.getArchiveManifest().getReferencedTimestamp().getName(), equalTo("META-INF/timestamp003.tst"));
    assertThat(asicsTimestamp3.getArchiveManifest().getManifestDocument().getName(), equalTo("META-INF/ASiCArchiveManifest.xml"));
    assertThat(asicsTimestamp3.getArchiveManifest().getManifestDocument().getMimeType(), equalTo(MimeTypeEnum.XML));
    assertThat(asicsTimestamp3.getArchiveManifest().getReferencedTimestamp().getMimeType(), equalTo(MimeTypeEnum.ODP.getMimeTypeString()));
    assertThat(asicsTimestamp3.getArchiveManifest().getReferencedDataObjects(), hasSize(4));
    assertThat(asicsTimestamp3.getArchiveManifest().getReferencedDataObjects().get(0).getName(), equalTo("META-INF/timestamp.tst"));
    assertThat(asicsTimestamp3.getArchiveManifest().getReferencedDataObjects().get(0).getMimeType(), equalTo(MimeTypeEnum.SVG.getMimeTypeString()));
    assertThat(asicsTimestamp3.getArchiveManifest().getReferencedDataObjects().get(1).getName(), equalTo("META-INF/timestamp002.tst"));
    assertThat(asicsTimestamp3.getArchiveManifest().getReferencedDataObjects().get(1).getMimeType(), equalTo(MimeTypeEnum.XML.getMimeTypeString()));
    assertThat(asicsTimestamp3.getArchiveManifest().getReferencedDataObjects().get(2).getName(), equalTo("META-INF/ASiCArchiveManifest001.xml"));
    assertThat(asicsTimestamp3.getArchiveManifest().getReferencedDataObjects().get(2).getMimeType(), equalTo(MimeTypeEnum.PKCS7.getMimeTypeString()));
    assertThat(asicsTimestamp3.getArchiveManifest().getReferencedDataObjects().get(3).getName(), equalTo("smile.png"));
    assertThat(asicsTimestamp3.getArchiveManifest().getReferencedDataObjects().get(3).getMimeType(), equalTo("custom-mimetype"));
    assertThat(container.getSignatures(), empty());
  }

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
  }

}
