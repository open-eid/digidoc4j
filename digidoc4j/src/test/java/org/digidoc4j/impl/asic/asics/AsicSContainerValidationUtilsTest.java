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
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.DataFile;
import org.digidoc4j.exceptions.IllegalContainerContentException;
import org.digidoc4j.impl.asic.AsicEntry;
import org.digidoc4j.impl.asic.AsicParseResult;
import org.digidoc4j.impl.asic.cades.ContainerTimestampWrapper;
import org.digidoc4j.impl.asic.xades.XadesSignatureWrapper;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.zip.ZipEntry;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

public class AsicSContainerValidationUtilsTest {

  private static final String INVALID_MIMETYPE_MESSAGE = "Invalid mimetype for ASiC-S container";

  @Test
  public void validateContainerParseResult_WhenMimeTypeIsMissing_ThrowsException() {
    AsicParseResult parseResult = createParseResultWithMimeType((String) null);

    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> AsicSContainerValidationUtils.validateContainerParseResult(parseResult)
    );

    assertThat(caughtException.getMessage(), equalTo(INVALID_MIMETYPE_MESSAGE));
  }

  @Test
  public void validateContainerParseResult_WhenMimeTypeIsEmpty_ThrowsException() {
    AsicParseResult parseResult = createParseResultWithMimeType(StringUtils.EMPTY);

    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> AsicSContainerValidationUtils.validateContainerParseResult(parseResult)
    );

    assertThat(caughtException.getMessage(), equalTo(INVALID_MIMETYPE_MESSAGE));
  }

  @Test
  public void validateContainerParseResult_WhenMimeTypeIsNonAsic_ThrowsException() {
    AsicParseResult parseResult = createParseResultWithMimeType(MimeTypeEnum.TEXT);

    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> AsicSContainerValidationUtils.validateContainerParseResult(parseResult)
    );

    assertThat(caughtException.getMessage(), equalTo(INVALID_MIMETYPE_MESSAGE));
  }

  @Test
  public void validateContainerParseResult_WhenMimeTypeIsAsice_ThrowsException() {
    AsicParseResult parseResult = createParseResultWithMimeType(MimeTypeEnum.ASICE);

    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> AsicSContainerValidationUtils.validateContainerParseResult(parseResult)
    );

    assertThat(caughtException.getMessage(), equalTo(INVALID_MIMETYPE_MESSAGE));
  }

  @Test
  public void validateAsicsContainerParseResult_WhenContainsBothSignaturesAndTimestamps_ThrowsException() {
    AsicParseResult parseResult = createAsicsParseResult();
    XadesSignatureWrapper signature = mock(XadesSignatureWrapper.class);
    parseResult.setSignatures(Collections.singletonList(signature));
    ContainerTimestampWrapper timestamp = mock(ContainerTimestampWrapper.class);
    parseResult.setTimestamps(Collections.singletonList(timestamp));

    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> AsicSContainerValidationUtils.validateContainerParseResult(parseResult)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("ASiC-S container cannot contain signatures and timestamp tokens simultaneously")
    );
    verifyNoInteractions(signature, timestamp);
  }

  @Test
  public void validateAsicsContainerParseResult_WhenUnsignedContainerHasCadesSignatureEntry_ThrowsException() {
    validateAsicsContainerParseResult_WhenUnsignedContainerHasUnsupportedCadesSignatureEntry_ThrowsException("signature.p7s");
  }

  @Test
  public void validateAsicsContainerParseResult_WhenUnsignedContainerHasCadesSignaturesEntry_ThrowsException() {
    validateAsicsContainerParseResult_WhenUnsignedContainerHasUnsupportedCadesSignatureEntry_ThrowsException("signatures.p7s");
  }

  @Test
  public void validateAsicsContainerParseResult_WhenUnsignedContainerHasCadesSignature0Entry_ThrowsException() {
    validateAsicsContainerParseResult_WhenUnsignedContainerHasUnsupportedCadesSignatureEntry_ThrowsException("signature0.p7s");
  }
  @Test
  public void validateAsicsContainerParseResult_WhenUnsignedContainerHasCadesSignatureUpperCaseEntry_ThrowsException() {
    validateAsicsContainerParseResult_WhenUnsignedContainerHasUnsupportedCadesSignatureEntry_ThrowsException("SIGNATURE.P7S");
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private static void validateAsicsContainerParseResult_WhenUnsignedContainerHasUnsupportedCadesSignatureEntry_ThrowsException(String entryName) {
    AsicParseResult parseResult = createAsicsParseResult();
    parseResult.setAsicEntries(Collections.singletonList(createAsicEntry(ASiCUtils.META_INF_FOLDER + entryName)));

    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> AsicSContainerValidationUtils.validateContainerParseResult(parseResult)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Unsupported CAdES signature entry: " + ASiCUtils.META_INF_FOLDER + entryName)
    );
  }

  @Test
  public void validateAsicsContainerParseResult_WhenUnsignedContainerHasEvidenceRecordErsEntry_ThrowsException() {
    validateAsicsContainerParseResult_WhenUnsignedContainerHasUnsupportedEvidenceRecordEntry_ThrowsException("evidencerecord.ers");
  }

  @Test
  public void validateAsicsContainerParseResult_WhenUnsignedContainerHasEvidenceRecordErsUpperCaseEntry_ThrowsException() {
    validateAsicsContainerParseResult_WhenUnsignedContainerHasUnsupportedEvidenceRecordEntry_ThrowsException("EVIDENCERECORD.ERS");
  }

  @Test
  public void validateAsicsContainerParseResult_WhenUnsignedContainerHasEvidenceRecordXmlEntry_ThrowsException() {
    validateAsicsContainerParseResult_WhenUnsignedContainerHasUnsupportedEvidenceRecordEntry_ThrowsException("evidencerecord.xml");
  }

  @Test
  public void validateAsicsContainerParseResult_WhenUnsignedContainerHasEvidenceRecordXmlUpperCaseEntry_ThrowsException() {
    validateAsicsContainerParseResult_WhenUnsignedContainerHasUnsupportedEvidenceRecordEntry_ThrowsException("EVIDENCERECORD.XML");
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private static void validateAsicsContainerParseResult_WhenUnsignedContainerHasUnsupportedEvidenceRecordEntry_ThrowsException(String entryName) {
    AsicParseResult parseResult = createAsicsParseResult();
    parseResult.setAsicEntries(Collections.singletonList(createAsicEntry(ASiCUtils.META_INF_FOLDER + entryName)));

    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> AsicSContainerValidationUtils.validateContainerParseResult(parseResult)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Unsupported evidence record entry: " + ASiCUtils.META_INF_FOLDER + entryName)
    );
  }

  @Test
  public void validateAsicsContainerParseResult_WhenUnsignedContainerHasNoDataFiles_Succeeds() {
    validateAsicsContainerParseResult_WhenUnsignedContainerHasNoMoreThanOneDataFile_Succeeds(0);
  }

  @Test
  public void validateAsicsContainerParseResult_WhenUnsignedContainerHasOneDataFile_Succeeds() {
    validateAsicsContainerParseResult_WhenUnsignedContainerHasNoMoreThanOneDataFile_Succeeds(1);
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private static void validateAsicsContainerParseResult_WhenUnsignedContainerHasNoMoreThanOneDataFile_Succeeds(int dataFileCount) {
    AsicParseResult parseResult = createAsicsParseResult();
    parseResult.setDataFiles(createDataFiles(dataFileCount));

    AsicSContainerValidationUtils.validateContainerParseResult(parseResult);
  }

  @Test
  public void validateAsicsContainerParseResult_WhenUnsignedContainerHasMoreThanOneDataFile_ThrowsException() {
    AsicParseResult parseResult = createAsicsParseResult();
    parseResult.setDataFiles(createDataFiles(2));

    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> AsicSContainerValidationUtils.validateContainerParseResult(parseResult)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("ASiC-S container cannot contain more than one datafile")
    );
  }

  @Test
  public void validateAsicsContainerParseResult_WhenSignedContainerHasOneDataFile_Succeeds() {
    AsicParseResult parseResult = createAsicsParseResult();
    XadesSignatureWrapper signature = mock(XadesSignatureWrapper.class);
    parseResult.setSignatures(Collections.singletonList(signature));
    parseResult.setDataFiles(createDataFiles(1));

    AsicSContainerValidationUtils.validateContainerParseResult(parseResult);
    verifyNoInteractions(signature);
  }

  @Test
  public void validateAsicsContainerParseResult_WhenSignedContainerHasNoDataFiles_ThrowsException() {
    validateAsicsContainerParseResult_WhenSignedContainerDoesNotHaveOneDataFile_ThrowsException(0);
  }

  @Test
  public void validateAsicsContainerParseResult_WhenSignedContainerHasMoreThanOneDataFile_ThrowsException() {
    validateAsicsContainerParseResult_WhenSignedContainerDoesNotHaveOneDataFile_ThrowsException(2);
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private static void validateAsicsContainerParseResult_WhenSignedContainerDoesNotHaveOneDataFile_ThrowsException(int dataFileCount) {
    AsicParseResult parseResult = createAsicsParseResult();
    XadesSignatureWrapper signature = mock(XadesSignatureWrapper.class);
    parseResult.setSignatures(Collections.singletonList(signature));
    parseResult.setDataFiles(createDataFiles(dataFileCount));

    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> AsicSContainerValidationUtils.validateContainerParseResult(parseResult)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Signed ASiC-S container must contain exactly one datafile")
    );
    verifyNoInteractions(signature);
  }

  @Test
  public void validateAsicsContainerParseResult_WhenSignedContainerHasTimestampEntry_ThrowsException() {
    validateAsicsContainerParseResult_WhenSignedContainerHasTimestampTokenEntry_ThrowsException("timestamp.tst");
  }

  @Test
  public void validateAsicsContainerParseResult_WhenSignedContainerHasTimestamp0Entry_ThrowsException() {
    validateAsicsContainerParseResult_WhenSignedContainerHasTimestampTokenEntry_ThrowsException("timestamp0.tst");
  }
  @Test
  public void validateAsicsContainerParseResult_WhenSignedContainerHasTimestampUpperCaseEntry_ThrowsException() {
    validateAsicsContainerParseResult_WhenSignedContainerHasTimestampTokenEntry_ThrowsException("TIMESTAMP.TST");
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private static void validateAsicsContainerParseResult_WhenSignedContainerHasTimestampTokenEntry_ThrowsException(String entryName) {
    AsicParseResult parseResult = createAsicsParseResult();
    XadesSignatureWrapper signature = mock(XadesSignatureWrapper.class);
    parseResult.setSignatures(Collections.singletonList(signature));
    parseResult.setDataFiles(createDataFiles(1));
    parseResult.setAsicEntries(Collections.singletonList(createAsicEntry(ASiCUtils.META_INF_FOLDER + entryName)));

    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> AsicSContainerValidationUtils.validateContainerParseResult(parseResult)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Signed ASiC-S container cannot contain timestamp token entry: " + ASiCUtils.META_INF_FOLDER + entryName)
    );
    verifyNoInteractions(signature);
  }

  @Test
  public void validateAsicsContainerParseResult_WhenSignedContainerHasCadesSignatureEntry_ThrowsException() {
    validateAsicsContainerParseResult_WhenSignedContainerHasUnsupportedCadesSignatureEntry_ThrowsException("signature.p7s");
  }

  @Test
  public void validateAsicsContainerParseResult_WhenSignedContainerHasCadesSignaturesEntry_ThrowsException() {
    validateAsicsContainerParseResult_WhenSignedContainerHasUnsupportedCadesSignatureEntry_ThrowsException("signatures.p7s");
  }

  @Test
  public void validateAsicsContainerParseResult_WhenSignedContainerHasCadesSignature0Entry_ThrowsException() {
    validateAsicsContainerParseResult_WhenSignedContainerHasUnsupportedCadesSignatureEntry_ThrowsException("signature0.p7s");
  }
  @Test
  public void validateAsicsContainerParseResult_WhenSignedContainerHasCadesSignatureUpperCaseEntry_ThrowsException() {
    validateAsicsContainerParseResult_WhenSignedContainerHasUnsupportedCadesSignatureEntry_ThrowsException("SIGNATURE.P7S");
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private static void validateAsicsContainerParseResult_WhenSignedContainerHasUnsupportedCadesSignatureEntry_ThrowsException(String entryName) {
    AsicParseResult parseResult = createAsicsParseResult();
    XadesSignatureWrapper signature = mock(XadesSignatureWrapper.class);
    parseResult.setSignatures(Collections.singletonList(signature));
    parseResult.setDataFiles(createDataFiles(1));
    parseResult.setAsicEntries(Collections.singletonList(createAsicEntry(ASiCUtils.META_INF_FOLDER + entryName)));

    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> AsicSContainerValidationUtils.validateContainerParseResult(parseResult)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Unsupported CAdES signature entry: " + ASiCUtils.META_INF_FOLDER + entryName)
    );
    verifyNoInteractions(signature);
  }

  @Test
  public void validateAsicsContainerParseResult_WhenSignedContainerHasEvidenceRecordErsEntry_ThrowsException() {
    validateAsicsContainerParseResult_WhenSignedContainerHasUnsupportedEvidenceRecordEntry_ThrowsException("evidencerecord.ers");
  }

  @Test
  public void validateAsicsContainerParseResult_WhenSignedContainerHasEvidenceRecordErsUpperCaseEntry_ThrowsException() {
    validateAsicsContainerParseResult_WhenSignedContainerHasUnsupportedEvidenceRecordEntry_ThrowsException("EVIDENCERECORD.ERS");
  }

  @Test
  public void validateAsicsContainerParseResult_WhenSignedContainerHasEvidenceRecordXmlEntry_ThrowsException() {
    validateAsicsContainerParseResult_WhenSignedContainerHasUnsupportedEvidenceRecordEntry_ThrowsException("evidencerecord.xml");
  }

  @Test
  public void validateAsicsContainerParseResult_WhenSignedContainerHasEvidenceRecordXmlUpperCaseEntry_ThrowsException() {
    validateAsicsContainerParseResult_WhenSignedContainerHasUnsupportedEvidenceRecordEntry_ThrowsException("EVIDENCERECORD.XML");
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private static void validateAsicsContainerParseResult_WhenSignedContainerHasUnsupportedEvidenceRecordEntry_ThrowsException(String entryName) {
    AsicParseResult parseResult = createAsicsParseResult();
    XadesSignatureWrapper signature = mock(XadesSignatureWrapper.class);
    parseResult.setSignatures(Collections.singletonList(signature));
    parseResult.setDataFiles(createDataFiles(1));
    parseResult.setAsicEntries(Collections.singletonList(createAsicEntry(ASiCUtils.META_INF_FOLDER + entryName)));

    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> AsicSContainerValidationUtils.validateContainerParseResult(parseResult)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Unsupported evidence record entry: " + ASiCUtils.META_INF_FOLDER + entryName)
    );
    verifyNoInteractions(signature);
  }

  @Test
  public void validateAsicsContainerParseResult_WhenTimestampContainerHasOneDataFile_Succeeds() {
    AsicParseResult parseResult = createAsicsParseResult();
    ContainerTimestampWrapper timestamp = mock(ContainerTimestampWrapper.class);
    parseResult.setTimestamps(Collections.singletonList(timestamp));
    parseResult.setDataFiles(createDataFiles(1));

    AsicSContainerValidationUtils.validateContainerParseResult(parseResult);
  }

  @Test
  public void validateAsicsContainerParseResult_WhenTimestampedContainerHasNoDataFiles_ThrowsException() {
    validateAsicsContainerParseResult_WhenTimestampedContainerDoesNotHaveOneDataFile_ThrowsException(0);
  }

  @Test
  public void validateAsicsContainerParseResult_WhenTimestampedContainerHasMoreThanOneDataFile_ThrowsException() {
    validateAsicsContainerParseResult_WhenTimestampedContainerDoesNotHaveOneDataFile_ThrowsException(2);
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private static void validateAsicsContainerParseResult_WhenTimestampedContainerDoesNotHaveOneDataFile_ThrowsException(int dataFileCount) {
    AsicParseResult parseResult = createAsicsParseResult();
    ContainerTimestampWrapper timestamp = mock(ContainerTimestampWrapper.class);
    parseResult.setTimestamps(Collections.singletonList(timestamp));
    parseResult.setDataFiles(createDataFiles(dataFileCount));

    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> AsicSContainerValidationUtils.validateContainerParseResult(parseResult)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Timestamped ASiC-S container must contain exactly one datafile")
    );
    verifyNoInteractions(timestamp);
  }

  @Test
  public void validateAsicsContainerParseResult_WhenTimestampedContainerHasXadesSignaturesEntry_ThrowsException() {
    validateAsicsContainerParseResult_WhenTimestampedContainerHasXadesSignaturesEntry_ThrowsException("signatures.xml");
  }

  @Test
  public void validateAsicsContainerParseResult_WhenTimestampedContainerHasXadesSignatures0Entry_ThrowsException() {
    validateAsicsContainerParseResult_WhenTimestampedContainerHasXadesSignaturesEntry_ThrowsException("signatures0.xml");
  }
  @Test
  public void validateAsicsContainerParseResult_WhenTimestampedContainerHasXadesSignaturesUpperCaseEntry_ThrowsException() {
    validateAsicsContainerParseResult_WhenTimestampedContainerHasXadesSignaturesEntry_ThrowsException("SIGNATURES.XML");
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private static void validateAsicsContainerParseResult_WhenTimestampedContainerHasXadesSignaturesEntry_ThrowsException(String entryName) {
    AsicParseResult parseResult = createAsicsParseResult();
    ContainerTimestampWrapper timestamp = mock(ContainerTimestampWrapper.class);
    parseResult.setTimestamps(Collections.singletonList(timestamp));
    parseResult.setDataFiles(createDataFiles(1));
    parseResult.setAsicEntries(Collections.singletonList(createAsicEntry(ASiCUtils.META_INF_FOLDER + entryName)));

    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> AsicSContainerValidationUtils.validateContainerParseResult(parseResult)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Timestamped ASiC-S container cannot contain signature entry: " + ASiCUtils.META_INF_FOLDER + entryName)
    );
    verifyNoInteractions(timestamp);
  }

  @Test
  public void validateAsicsContainerParseResult_WhenTimestampedContainerHasCadesSignatureEntry_ThrowsException() {
    validateAsicsContainerParseResult_WhenTimestampedContainerHasUnsupportedCadesSignatureEntry_ThrowsException("signature.p7s");
  }

  @Test
  public void validateAsicsContainerParseResult_WhenTimestampedContainerHasCadesSignaturesEntry_ThrowsException() {
    validateAsicsContainerParseResult_WhenTimestampedContainerHasUnsupportedCadesSignatureEntry_ThrowsException("signatures.p7s");
  }

  @Test
  public void validateAsicsContainerParseResult_WhenTimestampedContainerHasCadesSignature0Entry_ThrowsException() {
    validateAsicsContainerParseResult_WhenTimestampedContainerHasUnsupportedCadesSignatureEntry_ThrowsException("signature0.p7s");
  }
  @Test
  public void validateAsicsContainerParseResult_WhenTimestampedContainerHasCadesSignatureUpperCaseEntry_ThrowsException() {
    validateAsicsContainerParseResult_WhenTimestampedContainerHasUnsupportedCadesSignatureEntry_ThrowsException("SIGNATURE.P7S");
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private static void validateAsicsContainerParseResult_WhenTimestampedContainerHasUnsupportedCadesSignatureEntry_ThrowsException(String entryName) {
    AsicParseResult parseResult = createAsicsParseResult();
    ContainerTimestampWrapper timestamp = mock(ContainerTimestampWrapper.class);
    parseResult.setTimestamps(Collections.singletonList(timestamp));
    parseResult.setDataFiles(createDataFiles(1));
    parseResult.setAsicEntries(Collections.singletonList(createAsicEntry(ASiCUtils.META_INF_FOLDER + entryName)));

    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> AsicSContainerValidationUtils.validateContainerParseResult(parseResult)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Unsupported CAdES signature entry: " + ASiCUtils.META_INF_FOLDER + entryName)
    );
    verifyNoInteractions(timestamp);
  }

  @Test
  public void validateAsicsContainerParseResult_WhenTimestampedContainerHasEvidenceRecordErsEntry_ThrowsException() {
    validateAsicsContainerParseResult_WhenTimestampedContainerHasUnsupportedEvidenceRecordEntry_ThrowsException("evidencerecord.ers");
  }

  @Test
  public void validateAsicsContainerParseResult_WhenTimestampedContainerHasEvidenceRecordErsUpperCaseEntry_ThrowsException() {
    validateAsicsContainerParseResult_WhenTimestampedContainerHasUnsupportedEvidenceRecordEntry_ThrowsException("EVIDENCERECORD.ERS");
  }

  @Test
  public void validateAsicsContainerParseResult_WhenTimestampedContainerHasEvidenceRecordXmlEntry_ThrowsException() {
    validateAsicsContainerParseResult_WhenTimestampedContainerHasUnsupportedEvidenceRecordEntry_ThrowsException("evidencerecord.xml");
  }

  @Test
  public void validateAsicsContainerParseResult_WhenTimestampedContainerHasEvidenceRecordXmlUpperCaseEntry_ThrowsException() {
    validateAsicsContainerParseResult_WhenTimestampedContainerHasUnsupportedEvidenceRecordEntry_ThrowsException("EVIDENCERECORD.XML");
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private static void validateAsicsContainerParseResult_WhenTimestampedContainerHasUnsupportedEvidenceRecordEntry_ThrowsException(String entryName) {
    AsicParseResult parseResult = createAsicsParseResult();
    ContainerTimestampWrapper timestamp = mock(ContainerTimestampWrapper.class);
    parseResult.setTimestamps(Collections.singletonList(timestamp));
    parseResult.setDataFiles(createDataFiles(1));
    parseResult.setAsicEntries(Collections.singletonList(createAsicEntry(ASiCUtils.META_INF_FOLDER + entryName)));

    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            () -> AsicSContainerValidationUtils.validateContainerParseResult(parseResult)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Unsupported evidence record entry: " + ASiCUtils.META_INF_FOLDER + entryName)
    );
    verifyNoInteractions(timestamp);
  }

  private static AsicParseResult createParseResultWithMimeType(String mimeType) {
    AsicParseResult parseResult = new AsicParseResult();
    parseResult.setMimeType(mimeType);
    return parseResult;
  }

  private static AsicParseResult createParseResultWithMimeType(MimeType mimeType) {
    return createParseResultWithMimeType(mimeType.getMimeTypeString());
  }

  private static AsicParseResult createAsicsParseResult() {
      return createParseResultWithMimeType(MimeTypeEnum.ASICS);
  }

  private static AsicEntry createAsicEntry(String name) {
    return new AsicEntry(new ZipEntry(name));
  }

  private static List<DataFile> createDataFiles(int count) {
    return IntStream.range(0, count)
            .mapToObj(i -> new DataFile(
                    String.format("Content of file number %d", i).getBytes(StandardCharsets.UTF_8),
                    String.format("file%d.txt", i),
                    MimeTypeEnum.TEXT.getMimeTypeString()
            ))
            .collect(Collectors.toList());
  }

}
