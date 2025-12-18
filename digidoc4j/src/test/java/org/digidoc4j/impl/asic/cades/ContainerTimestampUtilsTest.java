/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.cades;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.apache.commons.lang3.ArrayUtils.EMPTY_BYTE_ARRAY;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

public class ContainerTimestampUtilsTest {

  @Test
  public void findLastTimestamp_WhenTimestampListIsEmpty_ReturnsNull() {
    TimestampAndManifestPair result = ContainerTimestampUtils.findLastTimestamp(Collections.emptyList());

    assertThat(result, nullValue());
  }

  @Test
  public void findLastTimestamp_WhenListContainsOneTimestampWithoutManifest_ReturnsTheTimestamp() {
    TimestampAndManifestPair timestamp = createTimestampMock("timestamp-name", Instant.now(), null);
    List<TimestampAndManifestPair> timestamps = Collections.singletonList(timestamp);

    TimestampAndManifestPair result = ContainerTimestampUtils.findLastTimestamp(timestamps);

    assertThat(result, sameInstance(timestamp));
  }

  @Test
  public void findLastTimestamp_WhenListContainsTwoTimestampsCoveringEachOther_ReturnsNull() {
    TimestampAndManifestPair timestamp1 = createTimestampMock(
            "timestamp-1-name",
            Instant.now(),
            createAsicArchiveManifestMock("timestamp-1-manifest-name", new HashSet<>(Arrays.asList(
                    "timestamp-2-name", "timestamp-2-manifest-name"
            )))
    );
    TimestampAndManifestPair timestamp2 = createTimestampMock(
            "timestamp-2-name",
            Instant.now(),
            createAsicArchiveManifestMock("timestamp-2-manifest-name", new HashSet<>(Arrays.asList(
                    "timestamp-1-name", "timestamp-1-manifest-name"
            )))
    );
    List<TimestampAndManifestPair> timestamps = Arrays.asList(timestamp1, timestamp2);

    TimestampAndManifestPair result = ContainerTimestampUtils.findLastTimestamp(timestamps);

    assertThat(result, nullValue());
  }

  @Test
  public void findLastTimestamp_WhenLastTimestampInListIsNotCoveredByAnyTimestamp_ReturnsThatTimestamp() {
    TimestampAndManifestPair timestamp1 = createTimestampMock(
            "timestamp-1-name",
            Instant.now(),
            null
    );
    TimestampAndManifestPair timestamp2 = createTimestampMock(
            "timestamp-2-name",
            Instant.now(),
            createAsicArchiveManifestMock("timestamp-2-manifest-name", Collections.singleton(
                    "timestamp-1-name"
            ))
    );
    List<TimestampAndManifestPair> timestamps = Arrays.asList(timestamp1, timestamp2);

    TimestampAndManifestPair result = ContainerTimestampUtils.findLastTimestamp(timestamps);

    assertThat(result, sameInstance(timestamp2));
  }

  @Test
  public void findLastTimestamp_WhenMultipleTimestampsAreNotCoveredByOtherTimestamps_ReturnsTheOneWithLatestCreationTime() {
    TimestampAndManifestPair timestamp1 = createTimestampMock(
            "timestamp-1-name",
            Instant.parse("2024-05-13T11:28:41.5Z"),
            null
    );
    TimestampAndManifestPair timestamp2 = createTimestampMock(
            "timestamp-2-name",
            Instant.parse("2024-05-14T17:34:28.9Z"),
            null
    );
    TimestampAndManifestPair timestamp3 = createTimestampMock(
            "timestamp-3-name",
            Instant.parse("2024-05-12T07:12:15.3Z"),
            null
    );
    List<TimestampAndManifestPair> timestamps = Arrays.asList(timestamp1, timestamp2, timestamp3);

    TimestampAndManifestPair result = ContainerTimestampUtils.findLastTimestamp(timestamps);

    assertThat(result, sameInstance(timestamp2));
  }

  @Test
  public void isTimestampCoveredByTimestamp_WhenTimestampWithoutManifestIsNotCoveredInTimestampList_ReturnsFalse() {
    TimestampAndManifestPair timestamp = createTimestampMock(
            new InMemoryDocument(EMPTY_BYTE_ARRAY, "timestamp-name"),
            null
    );
    List<TimestampAndManifestPair> timestamps = Collections.singletonList(
            createTimestampMock(createAsicArchiveManifestMock(Collections.singleton("another-name")))
    );

    boolean result = ContainerTimestampUtils.isTimestampCoveredByTimestamp(timestamp, timestamps);

    assertThat(result, equalTo(false));
    verify(timestamp).getCadesTimestamp();
    verify(timestamp).getArchiveManifest();
    verifyNoMoreInteractions(timestamp);
  }

  @Test
  public void isTimestampCoveredByTimestamp_WhenTimestampNorItsManifestIsNotCoveredInTimestampList_ReturnsFalse() {
    TimestampAndManifestPair timestamp = createTimestampMock(
            new InMemoryDocument(EMPTY_BYTE_ARRAY, "timestamp-name"),
            new InMemoryDocument(EMPTY_BYTE_ARRAY, "timestamp-manifest-name")
    );
    List<TimestampAndManifestPair> timestamps = Collections.singletonList(
            createTimestampMock(createAsicArchiveManifestMock(Collections.singleton("another-name")))
    );

    boolean result = ContainerTimestampUtils.isTimestampCoveredByTimestamp(timestamp, timestamps);

    assertThat(result, equalTo(false));
    verify(timestamp).getCadesTimestamp();
    verify(timestamp).getArchiveManifest();
    verifyNoMoreInteractions(timestamp);
  }

  @Test
  public void isTimestampCoveredByTimestamp_WhenTimestampWithoutManifestIsCoveredInTimestampList_ReturnsTrue() {
    TimestampAndManifestPair timestamp = createTimestampMock(
            new InMemoryDocument(EMPTY_BYTE_ARRAY, "timestamp-name"),
            null
    );
    List<TimestampAndManifestPair> timestamps = Collections.singletonList(
            createTimestampMock(createAsicArchiveManifestMock(Collections.singleton("timestamp-name")))
    );

    boolean result = ContainerTimestampUtils.isTimestampCoveredByTimestamp(timestamp, timestamps);

    assertThat(result, equalTo(true));
    verify(timestamp).getCadesTimestamp();
    verifyNoMoreInteractions(timestamp);
  }

  @Test
  public void isTimestampCoveredByTimestamp_WhenTimestampManifestIsCoveredInTimestampList_ReturnsTrue() {
    TimestampAndManifestPair timestamp = createTimestampMock(
            new InMemoryDocument(EMPTY_BYTE_ARRAY, "timestamp-name"),
            new InMemoryDocument(EMPTY_BYTE_ARRAY, "timestamp-manifest-name")
    );
    List<TimestampAndManifestPair> timestamps = Collections.singletonList(
            createTimestampMock(createAsicArchiveManifestMock(Collections.singleton("timestamp-manifest-name")))
    );

    boolean result = ContainerTimestampUtils.isTimestampCoveredByTimestamp(timestamp, timestamps);

    assertThat(result, equalTo(true));
    verify(timestamp).getCadesTimestamp();
    verify(timestamp).getArchiveManifest();
    verifyNoMoreInteractions(timestamp);
  }

  @Test
  public void isEntryCoveredByTimestamp_WhenListIsEmpty_ReturnsFalse() {
    boolean result = ContainerTimestampUtils.isEntryCoveredByTimestamp("entry-name", Collections.emptyList());

    assertThat(result, equalTo(false));
  }

  @Test
  public void isEntryCoveredByTimestamp_WhenListContainsTimestampWithoutManifest_ReturnsFalse() {
    TimestampAndManifestPair timestamp = createTimestampMock(null);
    List<TimestampAndManifestPair> timestamps = Collections.singletonList(timestamp);

    boolean result = ContainerTimestampUtils.isEntryCoveredByTimestamp("entry-name", timestamps);

    assertThat(result, equalTo(false));
    verify(timestamp).getArchiveManifest();
    verifyNoMoreInteractions(timestamp);
  }

  @Test
  public void isEntryCoveredByTimestamp_WhenNoManifestContainsEntryName_ReturnsFalse() {
    AsicArchiveManifest manifest = createAsicArchiveManifestMock(Collections.singleton("another-name"));
    TimestampAndManifestPair timestamp = createTimestampMock(manifest);
    List<TimestampAndManifestPair> timestamps = Collections.singletonList(timestamp);

    boolean result = ContainerTimestampUtils.isEntryCoveredByTimestamp("entry-name", timestamps);

    assertThat(result, equalTo(false));
    verify(timestamp).getArchiveManifest();
    verify(manifest).getNonNullEntryNames();
    verifyNoMoreInteractions(timestamp, manifest);
  }

  @Test
  public void isEntryCoveredByTimestamp_WhenOneManifestContainsEntryName_ReturnsTrue() {
    AsicArchiveManifest manifest1 = createAsicArchiveManifestMock(Collections.singleton("another-name"));
    TimestampAndManifestPair timestamp1 = createTimestampMock(manifest1);
    AsicArchiveManifest manifest2 = createAsicArchiveManifestMock(Collections.singleton("entry-name"));
    TimestampAndManifestPair timestamp2 = createTimestampMock(manifest2);
    List<TimestampAndManifestPair> timestamps = Arrays.asList(timestamp1, timestamp2);

    boolean result = ContainerTimestampUtils.isEntryCoveredByTimestamp("entry-name", timestamps);

    assertThat(result, equalTo(true));
    verify(timestamp1).getArchiveManifest();
    verify(manifest1).getNonNullEntryNames();
    verify(timestamp2).getArchiveManifest();
    verify(manifest2).getNonNullEntryNames();
    verifyNoMoreInteractions(timestamp1, manifest1, timestamp2, manifest2);
  }

  @Test
  public void getTimestampAndManifestNames_WhenListContainsTimestampsAndManifests_ReturnsAllNames() {
    List<TimestampAndManifestPair> timestamps = Arrays.asList(
            createTimestampMock(
                    new InMemoryDocument(EMPTY_BYTE_ARRAY, "timestamp-1-name"),
                    null
            ),
            createTimestampMock(
                    new InMemoryDocument(EMPTY_BYTE_ARRAY, "timestamp-2-name"),
                    new InMemoryDocument(EMPTY_BYTE_ARRAY, "timestamp-2-manifest-name")
            )
    );

    Set<String> result = ContainerTimestampUtils.getTimestampAndManifestNames(timestamps);

    assertThat(result, hasSize(3));
    assertThat(result, containsInAnyOrder("timestamp-1-name", "timestamp-2-name", "timestamp-2-manifest-name"));
    for (TimestampAndManifestPair timestamp : timestamps) {
      verify(timestamp).getCadesTimestamp();
      verify(timestamp).getArchiveManifest();
      verifyNoMoreInteractions(timestamp);
    }
  }

  @Test
  public void getTimestampAndManifestNames_WhenListContainsTimestampWithNullName_ReturnsEmptySet() {
    TimestampAndManifestPair timestamp = createTimestampMock(
            new InMemoryDocument(EMPTY_BYTE_ARRAY),
            null
    );

    Set<String> result = ContainerTimestampUtils.getTimestampAndManifestNames(Collections.singletonList(timestamp));

    assertThat(result, empty());
    verify(timestamp).getCadesTimestamp();
    verify(timestamp).getArchiveManifest();
    verifyNoMoreInteractions(timestamp);
  }

  @Test
  public void isTimestampFileName_WhenInputIsNull_ReturnsFalse() {
    boolean result = ContainerTimestampUtils.isTimestampFileName(null);

    assertThat(result, equalTo(false));
  }

  @Test
  public void isTimestampFileName_WhenInputIsBlank_ReturnsFalse() {
    boolean result = ContainerTimestampUtils.isTimestampFileName(StringUtils.SPACE);

    assertThat(result, equalTo(false));
  }

  @Test
  public void isTimestampFileName_WhenInputDoesNotBeginWithMetaInf_ReturnsFalse() {
    boolean result = ContainerTimestampUtils.isTimestampFileName("timestamp.tst");

    assertThat(result, equalTo(false));
  }

  @Test
  public void isTimestampFileName_WhenInputDoesNotEndWithTst_ReturnsFalse() {
    boolean result = ContainerTimestampUtils.isTimestampFileName("META-INF/timestamp");

    assertThat(result, equalTo(false));
  }

  @Test
  public void isTimestampFileName_WhenInputContainsSpace_ReturnsFalse() {
    boolean result = ContainerTimestampUtils.isTimestampFileName("META-INF/time stamp.tst");

    assertThat(result, equalTo(false));
  }

  @Test
  public void isTimestampFileName_WhenInputIsStandardTstName_ReturnsTrue() {
    boolean result = ContainerTimestampUtils.isTimestampFileName("META-INF/timestamp.tst");

    assertThat(result, equalTo(true));
  }

  @Test
  public void isTimestampFileName_WhenInputIsValidTstName_ReturnsTrue() {
    boolean result = ContainerTimestampUtils.isTimestampFileName("META-INF/random.tst");

    assertThat(result, equalTo(true));
  }

  @Test
  public void isTimestampFileName_WhenInputIsTstNameWithNumber_ReturnsTrue() {
    boolean result = ContainerTimestampUtils.isTimestampFileName("META-INF/timestamp001.tst");

    assertThat(result, equalTo(true));
  }

  @Test
  public void isArchiveManifestFileName_WhenInputIsNull_ReturnsFalse() {
    boolean result = ContainerTimestampUtils.isArchiveManifestFileName(null);

    assertThat(result, equalTo(false));
  }

  @Test
  public void isArchiveManifestFileName_WhenInputIsBlank_ReturnsFalse() {
    boolean result = ContainerTimestampUtils.isArchiveManifestFileName(StringUtils.SPACE);

    assertThat(result, equalTo(false));
  }

  @Test
  public void isArchiveManifestFileName_WhenInputDoesNotBeginWithMetaInf_ReturnsFalse() {
    boolean result = ContainerTimestampUtils.isArchiveManifestFileName("ASiCArchiveManifest.xml");

    assertThat(result, equalTo(false));
  }

  @Test
  public void isArchiveManifestFileName_WhenInputDoesNotEndWithXml_ReturnsFalse() {
    boolean result = ContainerTimestampUtils.isArchiveManifestFileName("META-INF/ASiCArchiveManifest");

    assertThat(result, equalTo(false));
  }

  @Test
  public void isArchiveManifestFileName_WhenInputIsNotAsicArchiveManifest_ReturnsFalse() {
    boolean result = ContainerTimestampUtils.isArchiveManifestFileName("META-INF/ASiCManifest.xml");

    assertThat(result, equalTo(false));
  }

  @Test
  public void isArchiveManifestFileName_WhenInputIsStandardAsicArchiveManifestName_ReturnsTrue() {
    boolean result = ContainerTimestampUtils.isArchiveManifestFileName("META-INF/ASiCArchiveManifest.xml");

    assertThat(result, equalTo(true));
  }

  @Test
  public void isArchiveManifestFileName_WhenInputIsAsicArchiveManifestNameWithNumber_ReturnsTrue() {
    boolean result = ContainerTimestampUtils.isArchiveManifestFileName("META-INF/ASiCArchiveManifest001.xml");

    assertThat(result, equalTo(true));
  }

  private static TimestampAndManifestPair createTimestampMock(String fileName, Instant creationTime, AsicArchiveManifest asicArchiveManifest) {
    TimestampAndManifestPair timestamp = createTimestampMock(asicArchiveManifest);
    CadesTimestamp cadesTimestamp = mock(CadesTimestamp.class);
    doReturn(cadesTimestamp).when(timestamp).getCadesTimestamp();
    doReturn(new InMemoryDocument(EMPTY_BYTE_ARRAY, fileName)).when(cadesTimestamp).getTimestampDocument();
    doReturn(Date.from(creationTime)).when(cadesTimestamp).getCreationTime();
    return timestamp;
  }

  private static TimestampAndManifestPair createTimestampMock(DSSDocument timestampDocument, DSSDocument manifestDocument) {
    TimestampAndManifestPair timestamp = mock(TimestampAndManifestPair.class);
    if (timestampDocument != null) {
      CadesTimestamp cadesTimestamp = new CadesTimestamp(timestampDocument);
      doReturn(cadesTimestamp).when(timestamp).getCadesTimestamp();
    } else {
      doReturn(null).when(timestamp).getCadesTimestamp();
    }
    if (manifestDocument != null) {
        AsicArchiveManifest asicArchiveManifest = new AsicArchiveManifest(manifestDocument);
        doReturn(asicArchiveManifest).when(timestamp).getArchiveManifest();
    } else {
        doReturn(null).when(timestamp).getArchiveManifest();
    }
    return timestamp;
  }

  private static TimestampAndManifestPair createTimestampMock(AsicArchiveManifest asicArchiveManifest) {
    TimestampAndManifestPair timestamp = mock(TimestampAndManifestPair.class);
    doReturn(asicArchiveManifest).when(timestamp).getArchiveManifest();
    return timestamp;
  }

  private static AsicArchiveManifest createAsicArchiveManifestMock(String fileName, Set<String> entryNames) {
    AsicArchiveManifest manifest = createAsicArchiveManifestMock(entryNames);
    doReturn(new InMemoryDocument(EMPTY_BYTE_ARRAY, fileName)).when(manifest).getManifestDocument();
    return manifest;
  }

  private static AsicArchiveManifest createAsicArchiveManifestMock(Set<String> entryNames) {
    AsicArchiveManifest manifest = mock(AsicArchiveManifest.class);
    doReturn(entryNames).when(manifest).getNonNullEntryNames();
    return manifest;
  }

}
