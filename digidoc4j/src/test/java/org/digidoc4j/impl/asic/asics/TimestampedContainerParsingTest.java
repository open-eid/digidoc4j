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
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.exceptions.IllegalContainerContentException;
import org.digidoc4j.impl.asic.cades.AsicArchiveManifest;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;

import static org.digidoc4j.test.matcher.CommonMatchers.equalToIsoDate;
import static org.digidoc4j.test.matcher.IsAsicArchiveManifestDataReference.isDataReferenceWithNameAndMimeType;
import static org.digidoc4j.test.matcher.IsAsicArchiveManifestDataReference.isDataReferenceWithNameAndMimeTypeAndDigestAlgorithm;
import static org.digidoc4j.test.matcher.IsAsicArchiveManifestDataReference.isDataReferenceWithUriAndName;
import static org.digidoc4j.test.matcher.IsAsicArchiveManifestReference.isReferenceWithMimeType;
import static org.digidoc4j.test.matcher.IsAsicArchiveManifestReference.isReferenceWithName;
import static org.digidoc4j.test.matcher.IsDataFile.isDataFileWithMediaType;
import static org.digidoc4j.test.matcher.IsDataFile.isDataFileWithName;
import static org.digidoc4j.test.matcher.IsDssDocument.isDocumentWithMimeType;
import static org.digidoc4j.test.matcher.IsDssDocument.isDocumentWithName;
import static org.digidoc4j.test.util.TestZipUtil.createDeflatedEntry;
import static org.digidoc4j.test.util.TestZipUtil.createStoredEntry;
import static org.digidoc4j.test.util.TestZipUtil.writeEntriesToByteArray;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThrows;

public class TimestampedContainerParsingTest extends AbstractTest {

  @Test
  public void openContainer_WhenAsicsWithOnlyDataFile_AsicsWithOneDataFileAndNoTimestampsNorSignaturesIsOpened() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/container_without_signatures.asics",
            configuration
    );

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getDataFiles().get(0), isDataFileWithName("test.txt"));
    assertThat(container.getDataFiles().get(0), isDataFileWithMediaType(MimeTypeEnum.TEXT));
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
    assertThat(container.getDataFiles().get(0), isDataFileWithName("test.txt"));
    assertThat(container.getDataFiles().get(0), isDataFileWithMediaType(MimeTypeEnum.TEXT));
    assertThat(container.getTimestamps(), hasSize(1));
    assertThat(container.getTimestamps().get(0), instanceOf(AsicSContainerTimestamp.class));
    assertThat(container.getTimestamps().get(0).getCreationTime(), equalToIsoDate("2017-11-24T08:20:33Z"));
    assertThat(container.getTimestamps().get(0).getDigestAlgorithm(), equalTo(DigestAlgorithm.SHA256));
    AsicSContainerTimestamp asicsTimestamp = (AsicSContainerTimestamp) container.getTimestamps().get(0);
    assertThat(asicsTimestamp.getCadesTimestamp().getTimestampDocument(), isDocumentWithName("META-INF/timestamp.tst"));
    assertThat(asicsTimestamp.getCadesTimestamp().getTimestampDocument(), isDocumentWithMimeType(MimeTypeEnum.TST));
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
    assertThat(container.getDataFiles().get(0), isDataFileWithName("test.txt"));
    assertThat(container.getDataFiles().get(0), isDataFileWithMediaType(MimeTypeEnum.TEXT));
    assertThat(container.getTimestamps(), hasSize(3));
    assertThat(container.getTimestamps().get(0), instanceOf(AsicSContainerTimestamp.class));
    assertThat(container.getTimestamps().get(0).getCreationTime(), equalToIsoDate("2024-07-05T08:42:57Z"));
    assertThat(container.getTimestamps().get(0).getDigestAlgorithm(), equalTo(DigestAlgorithm.SHA256));
    AsicSContainerTimestamp asicsTimestamp1 = (AsicSContainerTimestamp) container.getTimestamps().get(0);
    assertThat(asicsTimestamp1.getCadesTimestamp().getTimestampDocument(), isDocumentWithName("META-INF/timestamp.tst"));
    assertThat(asicsTimestamp1.getCadesTimestamp().getTimestampDocument(), isDocumentWithMimeType(MimeTypeEnum.TST));
    assertThat(asicsTimestamp1.getArchiveManifest(), nullValue());
    assertThat(container.getTimestamps().get(1), instanceOf(AsicSContainerTimestamp.class));
    assertThat(container.getTimestamps().get(1).getCreationTime(), equalToIsoDate("2024-07-05T08:44:04Z"));
    assertThat(container.getTimestamps().get(1).getDigestAlgorithm(), equalTo(DigestAlgorithm.SHA384));
    AsicSContainerTimestamp asicsTimestamp2 = (AsicSContainerTimestamp) container.getTimestamps().get(1);
    assertThat(asicsTimestamp2.getCadesTimestamp().getTimestampDocument(), isDocumentWithName("META-INF/timestamp002.tst"));
    assertThat(asicsTimestamp2.getCadesTimestamp().getTimestampDocument(), isDocumentWithMimeType(MimeTypeEnum.TST));
    assertThat(asicsTimestamp2.getArchiveManifest(), notNullValue(AsicArchiveManifest.class));
    assertThat(asicsTimestamp2.getArchiveManifest().getManifestDocument(), isDocumentWithName("META-INF/ASiCArchiveManifest001.xml"));
    assertThat(asicsTimestamp2.getArchiveManifest().getManifestDocument(), isDocumentWithMimeType(MimeTypeEnum.XML));
    assertThat(asicsTimestamp2.getArchiveManifest().getReferencedTimestamp(), isReferenceWithName("META-INF/timestamp002.tst"));
    assertThat(asicsTimestamp2.getArchiveManifest().getReferencedTimestamp(), isReferenceWithMimeType(MimeTypeEnum.TST));
    assertThat(asicsTimestamp2.getArchiveManifest().getReferencedDataObjects(), contains(
            isDataReferenceWithNameAndMimeTypeAndDigestAlgorithm("META-INF/timestamp.tst", MimeTypeEnum.TST, DigestAlgorithm.SHA384),
            isDataReferenceWithNameAndMimeTypeAndDigestAlgorithm("test.txt", MimeTypeEnum.TEXT, DigestAlgorithm.SHA384)
    ));
    assertThat(asicsTimestamp2.getArchiveManifest().getNonNullEntryNames(), equalTo(new HashSet<>(Arrays.asList(
            "test.txt", "META-INF/timestamp.tst"
    ))));
    assertThat(container.getTimestamps().get(2), instanceOf(AsicSContainerTimestamp.class));
    assertThat(container.getTimestamps().get(2).getCreationTime(), equalToIsoDate("2024-07-05T08:45:10Z"));
    assertThat(container.getTimestamps().get(2).getDigestAlgorithm(), equalTo(DigestAlgorithm.SHA512));
    AsicSContainerTimestamp asicsTimestamp3 = (AsicSContainerTimestamp) container.getTimestamps().get(2);
    assertThat(asicsTimestamp3.getCadesTimestamp().getTimestampDocument(), isDocumentWithName("META-INF/timestamp003.tst"));
    assertThat(asicsTimestamp3.getCadesTimestamp().getTimestampDocument(), isDocumentWithMimeType(MimeTypeEnum.TST));
    assertThat(asicsTimestamp3.getArchiveManifest(), notNullValue(AsicArchiveManifest.class));
    assertThat(asicsTimestamp3.getArchiveManifest().getManifestDocument(), isDocumentWithName("META-INF/ASiCArchiveManifest.xml"));
    assertThat(asicsTimestamp3.getArchiveManifest().getManifestDocument(), isDocumentWithMimeType(MimeTypeEnum.XML));
    assertThat(asicsTimestamp3.getArchiveManifest().getReferencedTimestamp(), isReferenceWithName("META-INF/timestamp003.tst"));
    assertThat(asicsTimestamp3.getArchiveManifest().getReferencedTimestamp(), isReferenceWithMimeType(MimeTypeEnum.TST));
    assertThat(asicsTimestamp3.getArchiveManifest().getReferencedDataObjects(), contains(
            isDataReferenceWithNameAndMimeTypeAndDigestAlgorithm("META-INF/timestamp.tst", MimeTypeEnum.TST, DigestAlgorithm.SHA512),
            isDataReferenceWithNameAndMimeTypeAndDigestAlgorithm("META-INF/timestamp002.tst", MimeTypeEnum.TST, DigestAlgorithm.SHA512),
            isDataReferenceWithNameAndMimeTypeAndDigestAlgorithm("META-INF/ASiCArchiveManifest001.xml", MimeTypeEnum.XML, DigestAlgorithm.SHA512),
            isDataReferenceWithNameAndMimeTypeAndDigestAlgorithm("test.txt", MimeTypeEnum.TEXT, DigestAlgorithm.SHA512)
    ));
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
    assertThat(container.getDataFiles().get(0), isDataFileWithName("smile.png"));
    assertThat(container.getDataFiles().get(0), isDataFileWithMediaType(MimeTypeEnum.PNG));
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
    assertThat(container.getDataFiles().get(0), isDataFileWithName("smile.png"));
    assertThat(container.getDataFiles().get(0), isDataFileWithMediaType(MimeTypeEnum.PDF));
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
    assertThat(container.getDataFiles().get(0), isDataFileWithName("smile.png"));
    assertThat(container.getDataFiles().get(0), isDataFileWithMediaType("custom-mimetype"));
    assertThat(container.getTimestamps(), hasSize(3));
    assertThat(container.getTimestamps().get(0), instanceOf(AsicSContainerTimestamp.class));
    AsicSContainerTimestamp asicsTimestamp1 = (AsicSContainerTimestamp) container.getTimestamps().get(0);
    assertThat(asicsTimestamp1.getCadesTimestamp().getTimestampDocument(), isDocumentWithName("META-INF/timestamp.tst"));
    assertThat(asicsTimestamp1.getCadesTimestamp().getTimestampDocument(), isDocumentWithMimeType(MimeTypeEnum.SVG));
    assertThat(asicsTimestamp1.getArchiveManifest(), nullValue());
    assertThat(container.getTimestamps().get(1), instanceOf(AsicSContainerTimestamp.class));
    AsicSContainerTimestamp asicsTimestamp2 = (AsicSContainerTimestamp) container.getTimestamps().get(1);
    assertThat(asicsTimestamp2.getCadesTimestamp().getTimestampDocument(), isDocumentWithName("META-INF/timestamp002.tst"));
    assertThat(asicsTimestamp2.getCadesTimestamp().getTimestampDocument(), isDocumentWithMimeType(MimeTypeEnum.XML));
    assertThat(asicsTimestamp2.getArchiveManifest(), notNullValue(AsicArchiveManifest.class));
    assertThat(asicsTimestamp2.getArchiveManifest().getManifestDocument(), isDocumentWithName("META-INF/ASiCArchiveManifest001.xml"));
    assertThat(asicsTimestamp2.getArchiveManifest().getManifestDocument(), isDocumentWithMimeType(MimeTypeEnum.PKCS7));
    assertThat(asicsTimestamp2.getArchiveManifest().getReferencedTimestamp(), isReferenceWithName("META-INF/timestamp002.tst"));
    assertThat(asicsTimestamp2.getArchiveManifest().getReferencedTimestamp(), isReferenceWithMimeType(MimeTypeEnum.HTML));
    assertThat(asicsTimestamp2.getArchiveManifest().getReferencedDataObjects(), contains(
            isDataReferenceWithNameAndMimeType("META-INF/timestamp.tst", MimeTypeEnum.JSON),
            isDataReferenceWithNameAndMimeType("smile.png", MimeTypeEnum.JPEG)
    ));
    assertThat(container.getTimestamps().get(2), instanceOf(AsicSContainerTimestamp.class));
    AsicSContainerTimestamp asicsTimestamp3 = (AsicSContainerTimestamp) container.getTimestamps().get(2);
    assertThat(asicsTimestamp3.getCadesTimestamp().getTimestampDocument(), isDocumentWithName("META-INF/timestamp003.tst"));
    assertThat(asicsTimestamp3.getCadesTimestamp().getTimestampDocument(), isDocumentWithMimeType(MimeTypeEnum.ODP));
    assertThat(asicsTimestamp3.getArchiveManifest(), notNullValue(AsicArchiveManifest.class));
    assertThat(asicsTimestamp3.getArchiveManifest().getManifestDocument(), isDocumentWithName("META-INF/ASiCArchiveManifest.xml"));
    assertThat(asicsTimestamp3.getArchiveManifest().getManifestDocument(), isDocumentWithMimeType(MimeTypeEnum.XML));
    assertThat(asicsTimestamp3.getArchiveManifest().getReferencedTimestamp(), isReferenceWithName("META-INF/timestamp003.tst"));
    assertThat(asicsTimestamp3.getArchiveManifest().getReferencedTimestamp(), isReferenceWithMimeType(MimeTypeEnum.ODP));
    assertThat(asicsTimestamp3.getArchiveManifest().getReferencedDataObjects(), contains(
            isDataReferenceWithNameAndMimeType("META-INF/timestamp.tst", MimeTypeEnum.SVG),
            isDataReferenceWithNameAndMimeType("META-INF/timestamp002.tst", MimeTypeEnum.XML),
            isDataReferenceWithNameAndMimeType("META-INF/ASiCArchiveManifest001.xml", MimeTypeEnum.PKCS7),
            isDataReferenceWithNameAndMimeType("smile.png", "custom-mimetype")
    ));
    assertThat(container.getSignatures(), empty());
  }

  @Test
  public void openContainer_WhenTimestampedAsicsContainsNoDataFiles_ThrowsIllegalContainerContentException() {
    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> ContainerOpener.open(
                    "src/test/resources/testFiles/invalid-containers/1xTST-no-data-file.asics",
                    configuration)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Timestamped ASiC-S container must contain exactly one datafile")
    );
  }

  @Test
  public void openContainer_WhenTimestampedAsicsContainsTwoDataFiles_ThrowsIllegalContainerContentException() {
    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> ContainerOpener.open(
                    "src/test/resources/testFiles/invalid-containers/timestamptoken-two-data-files.asics",
                    configuration)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Timestamped ASiC-S container must contain exactly one datafile")
    );
  }

  @Test
  public void openContainer_WhenTimestampedAsicsContainsUnrecognizedXadesSignature_ThrowsIllegalContainerContentException() {
    byte[] containerBytes = writeEntriesToByteArray(
            createStoredEntry(ASiCUtils.MIME_TYPE, MimeTypeEnum.ASICS.getMimeTypeString().getBytes(StandardCharsets.UTF_8)),
            createDeflatedEntry(ASiCUtils.META_INF_FOLDER + "timestamp.tst", "unused".getBytes(StandardCharsets.UTF_8)),
            createDeflatedEntry(ASiCUtils.META_INF_FOLDER + "SIGNATURES.XML", "unused".getBytes(StandardCharsets.UTF_8)),
            createDeflatedEntry("datafile", "unused".getBytes(StandardCharsets.UTF_8))
    );

    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> ContainerOpener.open(new ByteArrayInputStream(containerBytes), configuration)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo(String.format(
                    "Timestamped ASiC-S container cannot contain signature entry: %sSIGNATURES.XML",
                    ASiCUtils.META_INF_FOLDER
            ))
    );
  }

  @Test
  public void openContainer_WhenTimestampedAsicsContainsCadesSignature_ThrowsIllegalContainerContentException() {
    openContainer_WhenTimestampedAsicsContainsCadesSignature_ThrowsIllegalContainerContentException("signature.p7s");
  }

  @Test
  public void openContainer_WhenTimestampedAsicsContainsCadesSignatureUpperCase_ThrowsIllegalContainerContentException() {
    openContainer_WhenTimestampedAsicsContainsCadesSignature_ThrowsIllegalContainerContentException("SIGNATURE.P7S");
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void openContainer_WhenTimestampedAsicsContainsCadesSignature_ThrowsIllegalContainerContentException(String entryName) {
    byte[] containerBytes = writeEntriesToByteArray(
            createStoredEntry(ASiCUtils.MIME_TYPE, MimeTypeEnum.ASICS.getMimeTypeString().getBytes(StandardCharsets.UTF_8)),
            createDeflatedEntry(ASiCUtils.META_INF_FOLDER + "timestamp.tst", "unused".getBytes(StandardCharsets.UTF_8)),
            createDeflatedEntry(ASiCUtils.META_INF_FOLDER + entryName, "unused".getBytes(StandardCharsets.UTF_8)),
            createDeflatedEntry("datafile", "unused".getBytes(StandardCharsets.UTF_8))
    );

    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> ContainerOpener.open(new ByteArrayInputStream(containerBytes), configuration)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Unsupported CAdES signature entry: " + ASiCUtils.META_INF_FOLDER + entryName)
    );
  }

  @Test
  public void openContainer_WhenTimestampedAsicsContainsEvidenceRecordErs_ThrowsIllegalContainerContentException() {
    openContainer_WhenTimestampedAsicsContainsEvidenceRecord_ThrowsIllegalContainerContentException("evidencerecord.ers");
  }

  @Test
  public void openContainer_WhenTimestampedAsicsContainsEvidenceRecordErsUpperCase_ThrowsIllegalContainerContentException() {
    openContainer_WhenTimestampedAsicsContainsEvidenceRecord_ThrowsIllegalContainerContentException("EVIDENCERECORD.ERS");
  }

  @Test
  public void openContainer_WhenTimestampedAsicsContainsEvidenceRecordXml_ThrowsIllegalContainerContentException() {
    openContainer_WhenTimestampedAsicsContainsEvidenceRecord_ThrowsIllegalContainerContentException("evidencerecord.xml");
  }

  @Test
  public void openContainer_WhenTimestampedAsicsContainsEvidenceRecordXmlUpperCase_ThrowsIllegalContainerContentException() {
    openContainer_WhenTimestampedAsicsContainsEvidenceRecord_ThrowsIllegalContainerContentException("EVIDENCERECORD.XML");
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void openContainer_WhenTimestampedAsicsContainsEvidenceRecord_ThrowsIllegalContainerContentException(String entryName) {
    byte[] containerBytes = writeEntriesToByteArray(
            createStoredEntry(ASiCUtils.MIME_TYPE, MimeTypeEnum.ASICS.getMimeTypeString().getBytes(StandardCharsets.UTF_8)),
            createDeflatedEntry(ASiCUtils.META_INF_FOLDER + "timestamp.tst", "unused".getBytes(StandardCharsets.UTF_8)),
            createDeflatedEntry(ASiCUtils.META_INF_FOLDER + entryName, "unused".getBytes(StandardCharsets.UTF_8)),
            createDeflatedEntry("datafile", "unused".getBytes(StandardCharsets.UTF_8))
    );

    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> ContainerOpener.open(new ByteArrayInputStream(containerBytes), configuration)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Unsupported evidence record entry: " + ASiCUtils.META_INF_FOLDER + entryName)
    );
  }

  @Test
  public void openContainer_WhenAsicsWithSpecialCharactersInDataFileNamePercentEncodedInTimestampManifest_AsicsWithExpectedContentsIsOpened() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/2xTST-datafile-with-special-characters-percentencoded-in-archive-manifest.asics",
            configuration
    );

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getDataFiles().get(0), isDataFileWithName("1234567890 !#$%&'()+,-.;=@[]^_`{}~ õäöü.txt"));
    assertThat(container.getDataFiles().get(0), isDataFileWithMediaType(MimeTypeEnum.TEXT));
    assertThat(container.getTimestamps(), hasSize(2));
    assertThat(container.getTimestamps().get(0), instanceOf(AsicSContainerTimestamp.class));
    AsicSContainerTimestamp asicsTimestamp1 = (AsicSContainerTimestamp) container.getTimestamps().get(0);
    assertThat(asicsTimestamp1.getCadesTimestamp().getTimestampDocument(), isDocumentWithName("META-INF/timestamp.tst"));
    assertThat(asicsTimestamp1.getCadesTimestamp().getTimestampDocument(), isDocumentWithMimeType(MimeTypeEnum.TST));
    assertThat(asicsTimestamp1.getArchiveManifest(), nullValue());
    assertThat(container.getTimestamps().get(1), instanceOf(AsicSContainerTimestamp.class));
    AsicSContainerTimestamp asicsTimestamp2 = (AsicSContainerTimestamp) container.getTimestamps().get(1);
    assertThat(asicsTimestamp2.getCadesTimestamp().getTimestampDocument(), isDocumentWithName("META-INF/timestamp002.tst"));
    assertThat(asicsTimestamp2.getCadesTimestamp().getTimestampDocument(), isDocumentWithMimeType(MimeTypeEnum.TST));
    assertThat(asicsTimestamp2.getArchiveManifest(), notNullValue(AsicArchiveManifest.class));
    assertThat(asicsTimestamp2.getArchiveManifest().getManifestDocument(), isDocumentWithName("META-INF/ASiCArchiveManifest.xml"));
    assertThat(asicsTimestamp2.getArchiveManifest().getManifestDocument(), isDocumentWithMimeType(MimeTypeEnum.XML));
    assertThat(asicsTimestamp2.getArchiveManifest().getReferencedTimestamp(), isReferenceWithName("META-INF/timestamp002.tst"));
    assertThat(asicsTimestamp2.getArchiveManifest().getReferencedTimestamp(), isReferenceWithMimeType(MimeTypeEnum.TST));
    assertThat(asicsTimestamp2.getArchiveManifest().getReferencedDataObjects(), contains(
            isDataReferenceWithUriAndName("META-INF/timestamp.tst", "META-INF/timestamp.tst"),
            isDataReferenceWithUriAndName(
                    "1234567890%20%21%23%24%25%26%27%28%29%2B%2C-.%3B%3D%40%5B%5D%5E_%60%7B%7D%7E%20%C3%B5%C3%A4%C3%B6%C3%BC.txt",
                    "1234567890 !#$%&'()+,-.;=@[]^_`{}~ õäöü.txt"
            )
    ));
    assertThat(asicsTimestamp2.getArchiveManifest().getNonNullEntryNames(), equalTo(new HashSet<>(Arrays.asList(
            "1234567890 !#$%&'()+,-.;=@[]^_`{}~ õäöü.txt", "META-INF/timestamp.tst"
    ))));
    assertThat(container.getSignatures(), empty());
  }

  @Test
  public void openContainer_WhenAsicsWithSpecialCharactersInDataFileNameUnencodedInTimestampManifest_AsicsWithExpectedContentsIsOpened() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/2xTST-datafile-with-special-characters-unencoded-in-archive-manifest.asics",
            configuration
    );

    assertThat(container, instanceOf(AsicSContainer.class));
    assertThat(container.getDataFiles(), hasSize(1));
    assertThat(container.getDataFiles().get(0), isDataFileWithName("1234567890 !#$&'()+,-.;=@[]^_`{}~ õäöü.txt"));
    assertThat(container.getDataFiles().get(0), isDataFileWithMediaType(MimeTypeEnum.TEXT));
    assertThat(container.getTimestamps(), hasSize(2));
    assertThat(container.getTimestamps().get(0), instanceOf(AsicSContainerTimestamp.class));
    AsicSContainerTimestamp asicsTimestamp1 = (AsicSContainerTimestamp) container.getTimestamps().get(0);
    assertThat(asicsTimestamp1.getCadesTimestamp().getTimestampDocument(), isDocumentWithName("META-INF/timestamp.tst"));
    assertThat(asicsTimestamp1.getCadesTimestamp().getTimestampDocument(), isDocumentWithMimeType(MimeTypeEnum.TST));
    assertThat(asicsTimestamp1.getArchiveManifest(), nullValue());
    assertThat(container.getTimestamps().get(1), instanceOf(AsicSContainerTimestamp.class));
    AsicSContainerTimestamp asicsTimestamp2 = (AsicSContainerTimestamp) container.getTimestamps().get(1);
    assertThat(asicsTimestamp2.getCadesTimestamp().getTimestampDocument(), isDocumentWithName("META-INF/timestamp002.tst"));
    assertThat(asicsTimestamp2.getCadesTimestamp().getTimestampDocument(), isDocumentWithMimeType(MimeTypeEnum.TST));
    assertThat(asicsTimestamp2.getArchiveManifest(), notNullValue(AsicArchiveManifest.class));
    assertThat(asicsTimestamp2.getArchiveManifest().getManifestDocument(), isDocumentWithName("META-INF/ASiCArchiveManifest.xml"));
    assertThat(asicsTimestamp2.getArchiveManifest().getManifestDocument(), isDocumentWithMimeType(MimeTypeEnum.XML));
    assertThat(asicsTimestamp2.getArchiveManifest().getReferencedTimestamp(), isReferenceWithName("META-INF/timestamp002.tst"));
    assertThat(asicsTimestamp2.getArchiveManifest().getReferencedTimestamp(), isReferenceWithMimeType(MimeTypeEnum.TST));
    assertThat(asicsTimestamp2.getArchiveManifest().getReferencedDataObjects(), contains(
            isDataReferenceWithUriAndName("META-INF/timestamp.tst", "META-INF/timestamp.tst"),
            isDataReferenceWithUriAndName(
                    "1234567890 !#$&'()+,-.;=@[]^_`{}~ õäöü.txt",
                    "1234567890 !#$&'()+,-.;=@[]^_`{}~ õäöü.txt"
            )
    ));
    assertThat(asicsTimestamp2.getArchiveManifest().getNonNullEntryNames(), equalTo(new HashSet<>(Arrays.asList(
            "1234567890 !#$&'()+,-.;=@[]^_`{}~ õäöü.txt", "META-INF/timestamp.tst"
    ))));
    assertThat(container.getSignatures(), empty());
  }

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
  }

}
