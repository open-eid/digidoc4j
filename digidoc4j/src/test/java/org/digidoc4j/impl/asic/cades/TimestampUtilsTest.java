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
import org.junit.Test;

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

public class TimestampUtilsTest {

  @Test
  public void findLastTimestamp_WhenTimestampListIsEmpty_ReturnsNull() {
    AsicContainerTimestamp result = TimestampUtils.findLastTimestamp(Collections.emptyList());

    assertThat(result, nullValue());
  }

  @Test
  public void findLastTimestamp_WhenListContainsOneTimestampWithoutManifest_ReturnsTheTimestamp() {
    AsicContainerTimestamp timestamp = createTimestampMock("timestamp-name", Instant.now(), null);
    List<AsicContainerTimestamp> timestamps = Collections.singletonList(timestamp);

    AsicContainerTimestamp result = TimestampUtils.findLastTimestamp(timestamps);

    assertThat(result, sameInstance(timestamp));
  }

  @Test
  public void findLastTimestamp_WhenListContainsTwoTimestampsCoveringEachOther_ReturnsNull() {
    AsicContainerTimestamp timestamp1 = createTimestampMock(
            "timestamp-1-name",
            Instant.now(),
            createAsicArchiveManifestMock("timestamp-1-manifest-name", new HashSet<>(Arrays.asList(
                    "timestamp-2-name", "timestamp-2-manifest-name"
            )))
    );
    AsicContainerTimestamp timestamp2 = createTimestampMock(
            "timestamp-2-name",
            Instant.now(),
            createAsicArchiveManifestMock("timestamp-2-manifest-name", new HashSet<>(Arrays.asList(
                    "timestamp-1-name", "timestamp-1-manifest-name"
            )))
    );
    List<AsicContainerTimestamp> timestamps = Arrays.asList(timestamp1, timestamp2);

    AsicContainerTimestamp result = TimestampUtils.findLastTimestamp(timestamps);

    assertThat(result, nullValue());
  }

  @Test
  public void findLastTimestamp_WhenLastTimestampInListIsNotCoveredByAnyTimestamp_ReturnsThatTimestamp() {
    AsicContainerTimestamp timestamp1 = createTimestampMock(
            "timestamp-1-name",
            Instant.now(),
            null
    );
    AsicContainerTimestamp timestamp2 = createTimestampMock(
            "timestamp-2-name",
            Instant.now(),
            createAsicArchiveManifestMock("timestamp-2-manifest-name", Collections.singleton(
                    "timestamp-1-name"
            ))
    );
    List<AsicContainerTimestamp> timestamps = Arrays.asList(timestamp1, timestamp2);

    AsicContainerTimestamp result = TimestampUtils.findLastTimestamp(timestamps);

    assertThat(result, sameInstance(timestamp2));
  }

  @Test
  public void findLastTimestamp_WhenMultipleTimestampsAreNotCoveredByOtherTimestamps_ReturnsTheOneWithLatestCreationTime() {
    AsicContainerTimestamp timestamp1 = createTimestampMock(
            "timestamp-1-name",
            Instant.parse("2024-05-13T11:28:41.5Z"),
            null
    );
    AsicContainerTimestamp timestamp2 = createTimestampMock(
            "timestamp-2-name",
            Instant.parse("2024-05-14T17:34:28.9Z"),
            null
    );
    AsicContainerTimestamp timestamp3 = createTimestampMock(
            "timestamp-3-name",
            Instant.parse("2024-05-12T07:12:15.3Z"),
            null
    );
    List<AsicContainerTimestamp> timestamps = Arrays.asList(timestamp1, timestamp2, timestamp3);

    AsicContainerTimestamp result = TimestampUtils.findLastTimestamp(timestamps);

    assertThat(result, sameInstance(timestamp2));
  }

  @Test
  public void isTimestampCoveredByTimestamp_WhenTimestampWithoutManifestIsNotCoveredInTimestampList_ReturnsFalse() {
    AsicContainerTimestamp timestamp = createTimestampMock(
            new InMemoryDocument(EMPTY_BYTE_ARRAY, "timestamp-name"),
            null
    );
    List<AsicContainerTimestamp> timestamps = Collections.singletonList(
            createTimestampMock(createAsicArchiveManifestMock(Collections.singleton("another-name")))
    );

    boolean result = TimestampUtils.isTimestampCoveredByTimestamp(timestamp, timestamps);

    assertThat(result, equalTo(false));
    verify(timestamp).getTimestampDocument();
    verify(timestamp).getTimestampManifest();
    verifyNoMoreInteractions(timestamp);
  }

  @Test
  public void isTimestampCoveredByTimestamp_WhenTimestampNorItsManifestIsNotCoveredInTimestampList_ReturnsFalse() {
    AsicContainerTimestamp timestamp = createTimestampMock(
            new InMemoryDocument(EMPTY_BYTE_ARRAY, "timestamp-name"),
            new InMemoryDocument(EMPTY_BYTE_ARRAY, "timestamp-manifest-name")
    );
    List<AsicContainerTimestamp> timestamps = Collections.singletonList(
            createTimestampMock(createAsicArchiveManifestMock(Collections.singleton("another-name")))
    );

    boolean result = TimestampUtils.isTimestampCoveredByTimestamp(timestamp, timestamps);

    assertThat(result, equalTo(false));
    verify(timestamp).getTimestampDocument();
    verify(timestamp).getTimestampManifest();
    verifyNoMoreInteractions(timestamp);
  }

  @Test
  public void isTimestampCoveredByTimestamp_WhenTimestampWithoutManifestIsCoveredInTimestampList_ReturnsTrue() {
    AsicContainerTimestamp timestamp = createTimestampMock(
            new InMemoryDocument(EMPTY_BYTE_ARRAY, "timestamp-name"),
            null
    );
    List<AsicContainerTimestamp> timestamps = Collections.singletonList(
            createTimestampMock(createAsicArchiveManifestMock(Collections.singleton("timestamp-name")))
    );

    boolean result = TimestampUtils.isTimestampCoveredByTimestamp(timestamp, timestamps);

    assertThat(result, equalTo(true));
    verify(timestamp).getTimestampDocument();
    verifyNoMoreInteractions(timestamp);
  }

  @Test
  public void isTimestampCoveredByTimestamp_WhenTimestampManifestIsCoveredInTimestampList_ReturnsTrue() {
    AsicContainerTimestamp timestamp = createTimestampMock(
            new InMemoryDocument(EMPTY_BYTE_ARRAY, "timestamp-name"),
            new InMemoryDocument(EMPTY_BYTE_ARRAY, "timestamp-manifest-name")
    );
    List<AsicContainerTimestamp> timestamps = Collections.singletonList(
            createTimestampMock(createAsicArchiveManifestMock(Collections.singleton("timestamp-manifest-name")))
    );

    boolean result = TimestampUtils.isTimestampCoveredByTimestamp(timestamp, timestamps);

    assertThat(result, equalTo(true));
    verify(timestamp).getTimestampDocument();
    verify(timestamp).getTimestampManifest();
    verifyNoMoreInteractions(timestamp);
  }

  @Test
  public void isEntryCoveredByTimestamp_WhenListIsEmpty_ReturnsFalse() {
    boolean result = TimestampUtils.isEntryCoveredByTimestamp("entry-name", Collections.emptyList());

    assertThat(result, equalTo(false));
  }

  @Test
  public void isEntryCoveredByTimestamp_WhenListContainsTimestampWithoutManifest_ReturnsFalse() {
    AsicContainerTimestamp timestamp = createTimestampMock(null);
    List<AsicContainerTimestamp> timestamps = Collections.singletonList(timestamp);

    boolean result = TimestampUtils.isEntryCoveredByTimestamp("entry-name", timestamps);

    assertThat(result, equalTo(false));
    verify(timestamp).getTimestampManifest();
    verifyNoMoreInteractions(timestamp);
  }

  @Test
  public void isEntryCoveredByTimestamp_WhenNoManifestContainsEntryName_ReturnsFalse() {
    AsicArchiveManifest manifest = createAsicArchiveManifestMock(Collections.singleton("another-name"));
    AsicContainerTimestamp timestamp = createTimestampMock(manifest);
    List<AsicContainerTimestamp> timestamps = Collections.singletonList(timestamp);

    boolean result = TimestampUtils.isEntryCoveredByTimestamp("entry-name", timestamps);

    assertThat(result, equalTo(false));
    verify(timestamp).getTimestampManifest();
    verify(manifest).getNonNullEntryNames();
    verifyNoMoreInteractions(timestamp, manifest);
  }

  @Test
  public void isEntryCoveredByTimestamp_WhenOneManifestContainsEntryName_ReturnsTrue() {
    AsicArchiveManifest manifest1 = createAsicArchiveManifestMock(Collections.singleton("another-name"));
    AsicContainerTimestamp timestamp1 = createTimestampMock(manifest1);
    AsicArchiveManifest manifest2 = createAsicArchiveManifestMock(Collections.singleton("entry-name"));
    AsicContainerTimestamp timestamp2 = createTimestampMock(manifest2);
    List<AsicContainerTimestamp> timestamps = Arrays.asList(timestamp1, timestamp2);

    boolean result = TimestampUtils.isEntryCoveredByTimestamp("entry-name", timestamps);

    assertThat(result, equalTo(true));
    verify(timestamp1).getTimestampManifest();
    verify(manifest1).getNonNullEntryNames();
    verify(timestamp2).getTimestampManifest();
    verify(manifest2).getNonNullEntryNames();
    verifyNoMoreInteractions(timestamp1, manifest1, timestamp2, manifest2);
  }

  @Test
  public void getTimestampAndManifestNames_WhenListContainsTimestampsAndManifests_ReturnsAllNames() {
    List<AsicContainerTimestamp> timestamps = Arrays.asList(
            createTimestampMock(
                    new InMemoryDocument(EMPTY_BYTE_ARRAY, "timestamp-1-name"),
                    null
            ),
            createTimestampMock(
                    new InMemoryDocument(EMPTY_BYTE_ARRAY, "timestamp-2-name"),
                    new InMemoryDocument(EMPTY_BYTE_ARRAY, "timestamp-2-manifest-name")
            )
    );

    Set<String> result = TimestampUtils.getTimestampAndManifestNames(timestamps);

    assertThat(result, hasSize(3));
    assertThat(result, containsInAnyOrder("timestamp-1-name", "timestamp-2-name", "timestamp-2-manifest-name"));
    for (AsicContainerTimestamp timestamp : timestamps) {
      verify(timestamp).getTimestampDocument();
      verify(timestamp).getTimestampManifest();
      verifyNoMoreInteractions(timestamp);
    }
  }

  @Test
  public void getTimestampAndManifestNames_WhenListContainsTimestampWithNullName_ReturnsEmptySet() {
    AsicContainerTimestamp timestamp = createTimestampMock(
            new InMemoryDocument(EMPTY_BYTE_ARRAY),
            null
    );

    Set<String> result = TimestampUtils.getTimestampAndManifestNames(Collections.singletonList(timestamp));

    assertThat(result, empty());
    verify(timestamp).getTimestampDocument();
    verify(timestamp).getTimestampManifest();
    verifyNoMoreInteractions(timestamp);
  }

  private static AsicContainerTimestamp createTimestampMock(String fileName, Instant creationTime, AsicArchiveManifest asicArchiveManifest) {
    AsicContainerTimestamp timestamp = createTimestampMock(asicArchiveManifest);
    doReturn(new InMemoryDocument(EMPTY_BYTE_ARRAY, fileName)).when(timestamp).getTimestampDocument();
    doReturn(Date.from(creationTime)).when(timestamp).getCreationTime();
    return timestamp;
  }

  private static AsicContainerTimestamp createTimestampMock(DSSDocument timestampDocument, DSSDocument manifestDocument) {
    AsicContainerTimestamp timestamp = mock(AsicContainerTimestamp.class);
    doReturn(timestampDocument).when(timestamp).getTimestampDocument();
    if (manifestDocument != null) {
        AsicArchiveManifest asicArchiveManifest = new AsicArchiveManifest(manifestDocument);
        doReturn(asicArchiveManifest).when(timestamp).getTimestampManifest();
    } else {
        doReturn(null).when(timestamp).getTimestampManifest();
    }
    return timestamp;
  }

  private static AsicContainerTimestamp createTimestampMock(AsicArchiveManifest asicArchiveManifest) {
    AsicContainerTimestamp timestamp = mock(AsicContainerTimestamp.class);
    doReturn(asicArchiveManifest).when(timestamp).getTimestampManifest();
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
