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

import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.exceptions.DuplicateTimestampException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.exceptions.TimestampNotFoundException;
import org.junit.Before;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Function;

import static org.apache.commons.lang3.ArrayUtils.EMPTY_BYTE_ARRAY;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

public class ContainerTimestampProcessorTest {

  private ContainerTimestampProcessor timestampProcessor;

  @Before
  public void setUpProcessor() {
    timestampProcessor = new ContainerTimestampProcessor();
  }

  @Test
  public void addTimestamp_WhenTimestampTokenFileNameIsEmpty_ExceptionIsThrown() {
    CadesTimestamp cadesTimestamp = createTimestampWithName(StringUtils.EMPTY);

    TechnicalException caughtException = assertThrows(
            TechnicalException.class,
            () -> timestampProcessor.addTimestamp(cadesTimestamp)
    );

    assertThat(caughtException.getMessage(), equalTo("Timestamp token filename missing"));
    assertThat(timestampProcessor.getTimestampsInInitialOrder(), empty());
  }

  @Test
  public void addTimestamp_WhenTimestampHasDuplicateName_ExceptionIsThrown() {
    CadesTimestamp cadesTimestamp1 = createTimestampWithName("same-name");
    timestampProcessor.addTimestamp(cadesTimestamp1);
    CadesTimestamp cadesTimestamp2 = createTimestampWithName("same-name");

    DuplicateTimestampException caughtException = assertThrows(
            DuplicateTimestampException.class,
            () -> timestampProcessor.addTimestamp(cadesTimestamp2)
    );

    assertThat(caughtException.getMessage(), equalTo("Container contains duplicate timestamp token: same-name"));
    List<ContainerTimestampWrapper> list = timestampProcessor.getTimestampsInInitialOrder();
    assertThat(list, hasSize(1));
    assertThat(list.get(0).getCadesTimestamp(), sameInstance(cadesTimestamp1));
  }

  @Test
  public void addTimestamp_WhenMultipleTimestampsAreAdded_AllTimestampsPresentInProcessorInOrder() {
    CadesTimestamp cadesTimestamp1 = createTimestampWithName("name-1");
    CadesTimestamp cadesTimestamp2 = createTimestampWithName("name-2");
    CadesTimestamp cadesTimestamp3 = createTimestampWithName("name-3");

    timestampProcessor.addTimestamp(cadesTimestamp1);
    timestampProcessor.addTimestamp(cadesTimestamp2);
    timestampProcessor.addTimestamp(cadesTimestamp3);

    List<ContainerTimestampWrapper> result = timestampProcessor.getTimestampsInInitialOrder();
    assertThat(result, hasSize(3));
    assertThat(result.get(0).getCadesTimestamp(), sameInstance(cadesTimestamp1));
    assertThat(result.get(0).getArchiveManifest(), nullValue());
    assertThat(result.get(1).getCadesTimestamp(), sameInstance(cadesTimestamp2));
    assertThat(result.get(1).getArchiveManifest(), nullValue());
    assertThat(result.get(2).getCadesTimestamp(), sameInstance(cadesTimestamp3));
    assertThat(result.get(2).getArchiveManifest(), nullValue());
  }

  @Test
  public void addManifest_WhenManifestFileNameIsEmpty_ExceptionIsThrown() {
    AsicArchiveManifest archiveManifest = createManifestWithName(StringUtils.EMPTY);
    Function<String, CadesTimestamp> timestampResolver = createTimestampResolverMock();

    TechnicalException caughtException = assertThrows(
            TechnicalException.class,
            () -> timestampProcessor.addManifest(archiveManifest, timestampResolver)
    );

    assertThat(caughtException.getMessage(), equalTo("Timestamp manifest filename missing"));
    assertThat(timestampProcessor.getTimestampsInInitialOrder(), empty());
    verifyNoInteractions(timestampResolver);
  }

  @Test
  public void addManifest_WhenManifestHasDuplicateName_ExceptionIsThrown() {
    CadesTimestamp cadesTimestamp = createTimestampWithName("timestamp-name");
    timestampProcessor.addTimestamp(cadesTimestamp);
    AsicArchiveManifest archiveManifest1 = createManifestMockWithTimestampReferenceName(
            "same-name", "timestamp-name");
    timestampProcessor.addManifest(archiveManifest1, null);
    AsicArchiveManifest archiveManifest2 = createManifestMockWithTimestampReferenceName(
            "same-name", "timestamp-name");
    Function<String, CadesTimestamp> timestampResolver = createTimestampResolverMock();

    DuplicateTimestampException caughtException = assertThrows(
            DuplicateTimestampException.class,
            () -> timestampProcessor.addManifest(archiveManifest2, timestampResolver)
    );

    assertThat(caughtException.getMessage(), equalTo("Container contains duplicate timestamp manifest: same-name"));
    List<ContainerTimestampWrapper> list = timestampProcessor.getTimestampsInInitialOrder();
    assertThat(list, hasSize(1));
    assertThat(list.get(0).getCadesTimestamp(), sameInstance(cadesTimestamp));
  }

  @Test
  public void addManifest_WhenManifestTimestampReferenceIsMissing_ThrowsException() {
    AsicArchiveManifest archiveManifest = createManifestMockWithTimestampReferenceName(
            "manifest-name", null);
    Function<String, CadesTimestamp> timestampResolver = createTimestampResolverMock();

    TechnicalException caughtException = assertThrows(
            TechnicalException.class,
            () -> timestampProcessor.addManifest(archiveManifest, timestampResolver)
    );

    assertThat(caughtException.getMessage(), equalTo("No timestamp reference found in manifest: manifest-name"));
    assertThat(timestampProcessor.getTimestampsInInitialOrder(), empty());
    verify(archiveManifest, times(2)).getManifestDocument();
    verify(archiveManifest).getReferencedTimestamp();
    verifyNoMoreInteractions(archiveManifest);
  }

  @Test
  public void addManifest_WhenTimestampIsPresentInProcessor_ManifestIsAssociatedWithTimestamp() {
    CadesTimestamp cadesTimestamp = createTimestampWithName("timestamp-name");
    timestampProcessor.addTimestamp(cadesTimestamp);
    AsicArchiveManifest archiveManifest = createManifestMockWithTimestampReferenceName(
            "manifest-name", "timestamp-name");
    Function<String, CadesTimestamp> timestampResolver = createTimestampResolverMock();

    timestampProcessor.addManifest(archiveManifest, timestampResolver);

    List<ContainerTimestampWrapper> result = timestampProcessor.getTimestampsInInitialOrder();
    assertThat(result, hasSize(1));
    assertThat(result.get(0).getCadesTimestamp(), sameInstance(cadesTimestamp));
    assertThat(result.get(0).getArchiveManifest(), sameInstance(archiveManifest));
    verify(archiveManifest).getManifestDocument();
    verify(archiveManifest).getReferencedTimestamp();
    verifyNoMoreInteractions(archiveManifest);
    verifyNoInteractions(timestampResolver);
  }

  @Test
  public void addManifest_WhenTimestampIsNotPresentInProcessor_TimestampIsQueriedAndManifestIsAssociatedWithIt() {
    CadesTimestamp cadesTimestamp = createTimestampWithName("timestamp-name");
    AsicArchiveManifest archiveManifest = createManifestMockWithTimestampReferenceName(
            "manifest-name", "timestamp-name");
    Function<String, CadesTimestamp> timestampResolver = createTimestampResolverMock(cadesTimestamp);

    timestampProcessor.addManifest(archiveManifest, timestampResolver);

    List<ContainerTimestampWrapper> result = timestampProcessor.getTimestampsInInitialOrder();
    assertThat(result, hasSize(1));
    assertThat(result.get(0).getCadesTimestamp(), sameInstance(cadesTimestamp));
    assertThat(result.get(0).getArchiveManifest(), sameInstance(archiveManifest));
    verify(archiveManifest).getManifestDocument();
    verify(archiveManifest).getReferencedTimestamp();
    verify(timestampResolver).apply("timestamp-name");
    verifyNoMoreInteractions(archiveManifest, timestampResolver);
  }

  @Test
  public void addManifest_WhenTimestampIsNotPresentAndIsNotReturnedByResolver_ThrowsException() {
    AsicArchiveManifest archiveManifest = createManifestMockWithTimestampReferenceName(
            "manifest-name", "timestamp-name");
    Function<String, CadesTimestamp> timestampResolver = createTimestampResolverMock(null);

    TimestampNotFoundException caughtException = assertThrows(
            TimestampNotFoundException.class,
            () -> timestampProcessor.addManifest(archiveManifest, timestampResolver)
    );

    assertThat(caughtException.getMessage(), equalTo("Referenced timestamp token not found: timestamp-name"));
    assertThat(timestampProcessor.getTimestampsInInitialOrder(), empty());
    verify(archiveManifest).getManifestDocument();
    verify(archiveManifest).getReferencedTimestamp();
    verify(timestampResolver).apply("timestamp-name");
    verifyNoMoreInteractions(archiveManifest, timestampResolver);
  }

  @Test
  public void addManifest_WhenTimestampIsAlreadyAssociatedWithManifest_ThrowsException() {
    CadesTimestamp cadesTimestamp = createTimestampWithName("timestamp-name");
    timestampProcessor.addTimestamp(cadesTimestamp);
    AsicArchiveManifest archiveManifest1 = createManifestMockWithTimestampReferenceName(
            "manifest-1-name", "timestamp-name");
    timestampProcessor.addManifest(archiveManifest1, null);
    AsicArchiveManifest archiveManifest2 = createManifestMockWithTimestampReferenceName(
            "manifest-2-name", "timestamp-name");
    Function<String, CadesTimestamp> timestampResolver = createTimestampResolverMock();

    DuplicateTimestampException caughtException = assertThrows(
            DuplicateTimestampException.class,
            () -> timestampProcessor.addManifest(archiveManifest2, timestampResolver)
    );

    assertThat(caughtException.getMessage(), equalTo("Timestamp token cannot be referenced by multiple ASiCArchiveManifest files"));
    List<ContainerTimestampWrapper> result = timestampProcessor.getTimestampsInInitialOrder();
    assertThat(result, hasSize(1));
    assertThat(result.get(0).getCadesTimestamp(), sameInstance(cadesTimestamp));
    assertThat(result.get(0).getArchiveManifest(), sameInstance(archiveManifest1));
    verify(archiveManifest1).getManifestDocument();
    verify(archiveManifest1).getReferencedTimestamp();
    verify(archiveManifest2).getManifestDocument();
    verify(archiveManifest2).getReferencedTimestamp();
    verifyNoMoreInteractions(archiveManifest1, archiveManifest2);
    verifyNoInteractions(timestampResolver);
  }

  @Test
  public void addManifest_WhenTimestampReferenceHasNoMimeType_TimestampMimeTypeIsUnchanged() {
    DSSDocument timestampDocument = mock(DSSDocument.class);
    doReturn("timestamp-name").when(timestampDocument).getName();
    CadesTimestamp cadesTimestamp = new CadesTimestamp(timestampDocument);
    timestampProcessor.addTimestamp(cadesTimestamp);
    AsicArchiveManifest.Reference timestampReference = createReference(
            "timestamp-name", null);
    AsicArchiveManifest archiveManifest = createManifestMockWithTimestampReference(
            "manifest-name", timestampReference);

    timestampProcessor.addManifest(archiveManifest, null);

    verify(timestampDocument).getName();
    verify(archiveManifest).getManifestDocument();
    verify(archiveManifest).getReferencedTimestamp();
    verify(timestampReference).getName();
    verify(timestampReference).getMimeType();
    verifyNoMoreInteractions(timestampDocument, archiveManifest, timestampReference);
  }

  @Test
  public void addManifest_WhenTimestampReferenceHasBlankMimeType_TimestampMimeTypeIsUnchanged() {
    DSSDocument timestampDocument = mock(DSSDocument.class);
    doReturn("timestamp-name").when(timestampDocument).getName();
    CadesTimestamp cadesTimestamp = new CadesTimestamp(timestampDocument);
    timestampProcessor.addTimestamp(cadesTimestamp);
    AsicArchiveManifest.Reference timestampReference = createReference(
            "timestamp-name", StringUtils.SPACE);
    AsicArchiveManifest archiveManifest = createManifestMockWithTimestampReference(
            "manifest-name", timestampReference);

    timestampProcessor.addManifest(archiveManifest, null);

    verify(timestampDocument).getName();
    verify(archiveManifest).getManifestDocument();
    verify(archiveManifest).getReferencedTimestamp();
    verify(timestampReference).getName();
    verify(timestampReference).getMimeType();
    verifyNoMoreInteractions(timestampDocument, archiveManifest, timestampReference);
  }

  @Test
  public void addManifest_WhenTimestampReferenceHasNonBlankMimeType_TimestampMimeTypeIsUpdated() {
    DSSDocument timestampDocument = mock(DSSDocument.class);
    doReturn("timestamp-name").when(timestampDocument).getName();
    CadesTimestamp cadesTimestamp = new CadesTimestamp(timestampDocument);
    timestampProcessor.addTimestamp(cadesTimestamp);
    AsicArchiveManifest.Reference timestampReference = createReference(
            "timestamp-name", "custom-mimetype");
    AsicArchiveManifest archiveManifest = createManifestMockWithTimestampReference(
            "manifest-name", timestampReference);

    timestampProcessor.addManifest(archiveManifest, null);

    verify(timestampDocument).getName();
    verify(archiveManifest).getManifestDocument();
    verify(archiveManifest).getReferencedTimestamp();
    verify(timestampReference).getName();
    verify(timestampReference, times(2)).getMimeType();
    ArgumentCaptor<MimeType> mimeTypeCaptor = ArgumentCaptor.forClass(MimeType.class);
    verify(timestampDocument).setMimeType(mimeTypeCaptor.capture());
    verifyNoMoreInteractions(timestampDocument, archiveManifest, timestampReference);
    assertThat(mimeTypeCaptor.getValue(), notNullValue(MimeType.class));
    assertThat(mimeTypeCaptor.getValue().getMimeTypeString(), equalTo("custom-mimetype"));
  }

  @Test
  public void resolveReferenceMimeTypes_WhenNoTimestampsArePresent_NoInteractionsAndReturnsFalse() {
    BiConsumer<String, MimeType> referenceMimeTypeListener = createReferenceMimeTypeListenerMock();

    boolean result = timestampProcessor.resolveReferenceMimeTypes(referenceMimeTypeListener);

    assertThat(result, equalTo(false));
    assertThat(timestampProcessor.getTimestampsInInitialOrder(), empty());
    verifyNoInteractions(referenceMimeTypeListener);
  }

  @Test
  public void resolveReferenceMimeTypes_WhenTimestampWithoutManifestIsPresent_NoInteractionsAndReturnsFalse() {
    DSSDocument timestampDocument = mock(DSSDocument.class);
    doReturn("timestamp-name").when(timestampDocument).getName();
    timestampProcessor.addTimestamp(new CadesTimestamp(timestampDocument));
    BiConsumer<String, MimeType> referenceMimeTypeListener = createReferenceMimeTypeListenerMock();

    boolean result = timestampProcessor.resolveReferenceMimeTypes(referenceMimeTypeListener);

    assertThat(result, equalTo(false));
    assertThat(timestampProcessor.getTimestampsInInitialOrder(), hasSize(1));
    verify(timestampDocument, atLeastOnce()).getName();
    verifyNoMoreInteractions(timestampDocument);
    verifyNoInteractions(referenceMimeTypeListener);
  }

  @Test
  public void resolveReferenceMimeTypes_WhenReferencedObjectNotInProcessor_CallbackIsCalledAndReturnsTrue() {
    DSSDocument timestampDocument = mock(DSSDocument.class);
    doReturn("timestamp-name").when(timestampDocument).getName();
    timestampProcessor.addTimestamp(new CadesTimestamp(timestampDocument));
    DSSDocument manifestDocument = spy(AsicManifestTestUtils.createAsicManifestXmlDocument(
            AsicManifestTestUtils.createAsicSigReferenceXmlElement(null, "timestamp-name"),
            AsicManifestTestUtils.createAsicDataObjectReferenceXmlElement("ref-mimetype", "ref-name"),
            AsicManifestTestUtils.createAsicDataObjectReferenceXmlElement(null, "mimetypeless-ref-name")
    ));
    timestampProcessor.addManifest(new AsicArchiveManifest(manifestDocument), null);
    BiConsumer<String, MimeType> referenceMimeTypeListener = createReferenceMimeTypeListenerMock();

    boolean result = timestampProcessor.resolveReferenceMimeTypes(referenceMimeTypeListener);

    assertThat(result, equalTo(true));
    assertThat(timestampProcessor.getTimestampsInInitialOrder(), hasSize(1));
    verify(timestampDocument, atLeastOnce()).getName();
    verify(manifestDocument, atLeastOnce()).getName();
    verify(manifestDocument).openStream();
    ArgumentCaptor<MimeType> mimeTypeCaptor = ArgumentCaptor.forClass(MimeType.class);
    verify(referenceMimeTypeListener).accept(eq("ref-name"), mimeTypeCaptor.capture());
    verifyNoMoreInteractions(timestampDocument, manifestDocument, referenceMimeTypeListener);
    assertThat(mimeTypeCaptor.getValue().getMimeTypeString(), equalTo("ref-mimetype"));
  }

  @Test
  public void resolveReferenceMimeTypes_WhenReferencedObjectsInProcessor_MimeTypesUpdatedAndReturnsTrue() {
    DSSDocument timestampDocument1 = mock(DSSDocument.class);
    doReturn("timestamp-1-name").when(timestampDocument1).getName();
    timestampProcessor.addTimestamp(new CadesTimestamp(timestampDocument1));
    DSSDocument manifestDocument1 = spy(new InMemoryDocument(AsicManifestTestUtils.createAsicManifestXmlString(
            AsicManifestTestUtils.createAsicSigReferenceXmlElement(null, "timestamp-1-name")
    ).getBytes(StandardCharsets.UTF_8), "manifest-1-name"));
    timestampProcessor.addManifest(new AsicArchiveManifest(manifestDocument1), null);
    DSSDocument timestampDocument2 = mock(DSSDocument.class);
    doReturn("timestamp-2-name").when(timestampDocument2).getName();
    timestampProcessor.addTimestamp(new CadesTimestamp(timestampDocument2));
    DSSDocument manifestDocument2 = spy(new InMemoryDocument(AsicManifestTestUtils.createAsicManifestXmlString(
            AsicManifestTestUtils.createAsicSigReferenceXmlElement(null, "timestamp-2-name"),
            AsicManifestTestUtils.createAsicDataObjectReferenceXmlElement("tst-mimetype", "timestamp-1-name"),
            AsicManifestTestUtils.createAsicDataObjectReferenceXmlElement("mf-mimetype", "manifest-1-name")
    ).getBytes(StandardCharsets.UTF_8), "manifest-2-name"));
    timestampProcessor.addManifest(new AsicArchiveManifest(manifestDocument2), null);
    BiConsumer<String, MimeType> referenceMimeTypeListener = createReferenceMimeTypeListenerMock();

    boolean result = timestampProcessor.resolveReferenceMimeTypes(referenceMimeTypeListener);

    assertThat(result, equalTo(true));
    assertThat(timestampProcessor.getTimestampsInInitialOrder(), hasSize(2));
    verify(timestampDocument1, atLeastOnce()).getName();
    verify(manifestDocument1, atLeastOnce()).getName();
    verify(manifestDocument1).openStream();
    verify(timestampDocument2, atLeastOnce()).getName();
    verify(manifestDocument2, atLeastOnce()).getName();
    verify(manifestDocument2).openStream();
    ArgumentCaptor<MimeType> tstMimeTypeCaptor = ArgumentCaptor.forClass(MimeType.class);
    verify(timestampDocument1).setMimeType(tstMimeTypeCaptor.capture());
    ArgumentCaptor<MimeType> mfMimeTypeCaptor = ArgumentCaptor.forClass(MimeType.class);
    verify(manifestDocument1).setMimeType(mfMimeTypeCaptor.capture());
    verifyNoMoreInteractions(timestampDocument1, manifestDocument1, timestampDocument2, manifestDocument2);
    assertThat(tstMimeTypeCaptor.getValue().getMimeTypeString(), equalTo("tst-mimetype"));
    assertThat(mfMimeTypeCaptor.getValue().getMimeTypeString(), equalTo("mf-mimetype"));
    verifyNoInteractions(referenceMimeTypeListener);
  }

  @Test
  public void getTimestampsInSortedOrder_WhenNoTimestampsArePresent_ReturnsEmptyList() {
    List<ContainerTimestampWrapper> result = timestampProcessor.getTimestampsInSortedOrder();

    assertThat(result, empty());
  }

  @Test
  public void getTimestampsInSortedOrder_WhenTimestampWithoutManifestIsPresent_ReturnsSingleElementList() {
    CadesTimestamp cadesTimestamp = createTimestampWithName("timestamp-name");
    timestampProcessor.addTimestamp(cadesTimestamp);

    List<ContainerTimestampWrapper> result = timestampProcessor.getTimestampsInSortedOrder();

    assertThat(result, hasSize(1));
    assertThat(result.get(0), notNullValue(ContainerTimestampWrapper.class));
    assertThat(result.get(0).getCadesTimestamp(), sameInstance(cadesTimestamp));
    assertThat(result.get(0).getArchiveManifest(), nullValue());
  }

  @Test
  public void getTimestampsInSortedOrder_WhenTimestampWithManifestIsPresent_ReturnsSingleElementList() {
    CadesTimestamp cadesTimestamp = createTimestampWithName("timestamp-name");
    timestampProcessor.addTimestamp(cadesTimestamp);
    AsicArchiveManifest archiveManifest = new AsicArchiveManifest(new InMemoryDocument(
            AsicManifestTestUtils.createAsicManifestXmlString(
                    AsicManifestTestUtils.createAsicSigReferenceXmlElement(null, "timestamp-name")
            ).getBytes(StandardCharsets.UTF_8),
            "manifest-name"
    ));
    timestampProcessor.addManifest(archiveManifest, null);

    List<ContainerTimestampWrapper> result = timestampProcessor.getTimestampsInSortedOrder();

    assertThat(result, hasSize(1));
    assertThat(result.get(0), notNullValue(ContainerTimestampWrapper.class));
    assertThat(result.get(0).getCadesTimestamp(), sameInstance(cadesTimestamp));
    assertThat(result.get(0).getArchiveManifest(), sameInstance(archiveManifest));
  }

  @Test
  public void getTimestampsInSortedOrder_WhenMultipleTimestampsWithManifestsPresent_ReturnsListInSortedOrder() {
    CadesTimestamp firstCadesTimestamp = createTimestampWithName("first-timestamp-name");
    CadesTimestamp secondCadesTimestamp = createTimestampWithName("second-timestamp-name");
    AsicArchiveManifest secondTimestampManifest = new AsicArchiveManifest(new InMemoryDocument(
            AsicManifestTestUtils.createAsicManifestXmlString(
                    AsicManifestTestUtils.createAsicSigReferenceXmlElement(null, "second-timestamp-name"),
                    AsicManifestTestUtils.createAsicDataObjectReferenceXmlElement(null, "first-timestamp-name")
            ).getBytes(StandardCharsets.UTF_8),
            "second-timestamp-manifest-name"
    ));
    CadesTimestamp thirdCadesTimestamp = createTimestampWithName("third-timestamp-name");
    AsicArchiveManifest thirdTimestampManifest = new AsicArchiveManifest(new InMemoryDocument(
            AsicManifestTestUtils.createAsicManifestXmlString(
                    AsicManifestTestUtils.createAsicSigReferenceXmlElement(null, "third-timestamp-name"),
                    AsicManifestTestUtils.createAsicDataObjectReferenceXmlElement(null, "first-timestamp-name"),
                    AsicManifestTestUtils.createAsicDataObjectReferenceXmlElement(null, "second-timestamp-name"),
                    AsicManifestTestUtils.createAsicDataObjectReferenceXmlElement(null, "second-timestamp-manifest-name")
            ).getBytes(StandardCharsets.UTF_8),
            "third-timestamp-manifest-name"
    ));
    CadesTimestamp fourthCadesTimestamp = createTimestampWithName("fourth-timestamp-name");
    AsicArchiveManifest fourthTimestampManifest = new AsicArchiveManifest(new InMemoryDocument(
            AsicManifestTestUtils.createAsicManifestXmlString(
                    AsicManifestTestUtils.createAsicSigReferenceXmlElement(null, "fourth-timestamp-name"),
                    AsicManifestTestUtils.createAsicDataObjectReferenceXmlElement(null, "first-timestamp-name"),
                    AsicManifestTestUtils.createAsicDataObjectReferenceXmlElement(null, "second-timestamp-name"),
                    AsicManifestTestUtils.createAsicDataObjectReferenceXmlElement(null, "second-timestamp-manifest-name"),
                    AsicManifestTestUtils.createAsicDataObjectReferenceXmlElement(null, "third-timestamp-name"),
                    AsicManifestTestUtils.createAsicDataObjectReferenceXmlElement(null, "third-timestamp-manifest-name")
            ).getBytes(StandardCharsets.UTF_8),
            "fourth-timestamp-manifest-name"
    ));
    timestampProcessor.addTimestamp(fourthCadesTimestamp);
    timestampProcessor.addTimestamp(firstCadesTimestamp);
    timestampProcessor.addTimestamp(thirdCadesTimestamp);
    timestampProcessor.addTimestamp(secondCadesTimestamp);
    timestampProcessor.addManifest(thirdTimestampManifest, null);
    timestampProcessor.addManifest(secondTimestampManifest, null);
    timestampProcessor.addManifest(fourthTimestampManifest, null);

    List<ContainerTimestampWrapper> result = timestampProcessor.getTimestampsInSortedOrder();

    assertThat(result, hasSize(4));
    assertThat(result.get(0), notNullValue(ContainerTimestampWrapper.class));
    assertThat(result.get(0).getCadesTimestamp(), sameInstance(firstCadesTimestamp));
    assertThat(result.get(0).getArchiveManifest(), nullValue());
    assertThat(result.get(1), notNullValue(ContainerTimestampWrapper.class));
    assertThat(result.get(1).getCadesTimestamp(), sameInstance(secondCadesTimestamp));
    assertThat(result.get(1).getArchiveManifest(), sameInstance(secondTimestampManifest));
    assertThat(result.get(2), notNullValue(ContainerTimestampWrapper.class));
    assertThat(result.get(2).getCadesTimestamp(), sameInstance(thirdCadesTimestamp));
    assertThat(result.get(2).getArchiveManifest(), sameInstance(thirdTimestampManifest));
    assertThat(result.get(3), notNullValue(ContainerTimestampWrapper.class));
    assertThat(result.get(3).getCadesTimestamp(), sameInstance(fourthCadesTimestamp));
    assertThat(result.get(3).getArchiveManifest(), sameInstance(fourthTimestampManifest));
  }

  private static CadesTimestamp createTimestampWithName(String name) {
    DSSDocument document = new InMemoryDocument(EMPTY_BYTE_ARRAY, name, MimeTypeEnum.TST);
    return new CadesTimestamp(document);
  }

  private static AsicArchiveManifest createManifestWithName(String name) {
    DSSDocument document = new InMemoryDocument(EMPTY_BYTE_ARRAY, name, MimeTypeEnum.XML);
    return new AsicArchiveManifest(document);
  }

  private static AsicArchiveManifest createManifestMockWithTimestampReferenceName(
          String manifestName, String timestampName
  ) {
    return createManifestMockWithTimestampReference(manifestName, createReference(timestampName));
  }

  private static AsicArchiveManifest createManifestMockWithTimestampReferenceName(
          DSSDocument manifestDocument, String timestampName
  ) {
    return createManifestMockWithTimestampReference(manifestDocument, createReference(timestampName));
  }

  private static AsicArchiveManifest createManifestMockWithTimestampReference(
          String manifestName, AsicArchiveManifest.Reference timestampReference
  ) {
    return createManifestMockWithTimestampReference(
            new InMemoryDocument(EMPTY_BYTE_ARRAY, manifestName, MimeTypeEnum.XML),
            timestampReference
    );
  }

  private static AsicArchiveManifest createManifestMockWithTimestampReference(
          DSSDocument manifestDocument, AsicArchiveManifest.Reference timestampReference
  ) {
    AsicArchiveManifest archiveManifest = mock(AsicArchiveManifest.class);
    doReturn(manifestDocument).when(archiveManifest).getManifestDocument();
    doReturn(timestampReference).when(archiveManifest).getReferencedTimestamp();
    return archiveManifest;
  }

  private static AsicArchiveManifest.Reference createReference(String name, String mimeType) {
    AsicArchiveManifest.Reference reference = createReference(name);
    doReturn(mimeType).when(reference).getMimeType();
    return reference;
  }

  private static AsicArchiveManifest.Reference createReference(String name) {
    AsicArchiveManifest.Reference reference = mock(AsicArchiveManifest.Reference.class);
    doReturn(name).when(reference).getName();
    return reference;
  }

  @SuppressWarnings("unchecked")
  private static Function<String, CadesTimestamp> createTimestampResolverMock() {
    return (Function<String, CadesTimestamp>) mock(Function.class);
  }

  private static Function<String, CadesTimestamp> createTimestampResolverMock(CadesTimestamp resolvedTimestamp) {
    Function<String, CadesTimestamp> timestampResolver = createTimestampResolverMock();
    doReturn(resolvedTimestamp).when(timestampResolver).apply(anyString());
    return timestampResolver;
  }

  @SuppressWarnings("unchecked")
  private static BiConsumer<String, MimeType> createReferenceMimeTypeListenerMock() {
    return (BiConsumer<String, MimeType>) mock(BiConsumer.class);
  }

}
