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

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.digidoc4j.exceptions.TechnicalException;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;

import static org.digidoc4j.impl.asic.cades.AsicManifestTestUtils.MANIFEST_NAME;
import static org.digidoc4j.impl.asic.cades.AsicManifestTestUtils.createAsicDataObjectReferenceXmlElement;
import static org.digidoc4j.impl.asic.cades.AsicManifestTestUtils.createAsicManifestXmlDocument;
import static org.digidoc4j.impl.asic.cades.AsicManifestTestUtils.createAsicSigReferenceXmlElement;
import static org.digidoc4j.impl.asic.cades.AsicManifestTestUtils.createDsDigestMethodXmlElement;
import static org.digidoc4j.impl.asic.cades.AsicManifestTestUtils.createDsDigestValueXmlElement;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

public class AsicArchiveManifestTest {

  @Test
  public void createInstance_WhenWrappedDocumentIsMock_DocumentIsWrappedWithoutParsingIt() {
    DSSDocument manifestDocument = mock(DSSDocument.class);
    AsicArchiveManifest asicArchiveManifest = new AsicArchiveManifest(manifestDocument);

    DSSDocument result = asicArchiveManifest.getManifestDocument();

    assertThat(result, sameInstance(manifestDocument));
    verifyNoInteractions(manifestDocument);
  }

  @Test
  public void getReferencedTimestamp_WhenDocumentIsNotParsable_ThrowsException() {
    DSSDocument manifestDocument = new InMemoryDocument(
            "Not XML".getBytes(StandardCharsets.UTF_8),
            MANIFEST_NAME,
            MimeTypeEnum.XML
    );
    AsicArchiveManifest asicArchiveManifest = new AsicArchiveManifest(manifestDocument);

    TechnicalException caughtException = assertThrows(
            TechnicalException.class,
            asicArchiveManifest::getReferencedTimestamp
    );

    assertThat(caughtException.getMessage(), equalTo("Failed to parse manifest file: ManifestName.xml"));
  }

  @Test
  public void getReferencedTimestamp_WhenManifestDoesNotContainSigReference_ReturnsEmptyTimestampReference() {
    DSSDocument manifestDocument = createAsicManifestXmlDocument();
    AsicArchiveManifest asicArchiveManifest = new AsicArchiveManifest(manifestDocument);

    AsicArchiveManifest.Reference result = asicArchiveManifest.getReferencedTimestamp();

    assertThat(result, notNullValue());
    assertThat(result.getUri(), nullValue());
    assertThat(result.getName(), nullValue());
    assertThat(result.getMimeType(), nullValue());
  }

  @Test
  public void getReferencedTimestamp_WhenManifestContainsEmptySigReference_ReturnsEmptyTimestampReference() {
    DSSDocument manifestDocument = createAsicManifestXmlDocument(
            createAsicSigReferenceXmlElement(null, null)
    );
    AsicArchiveManifest asicArchiveManifest = new AsicArchiveManifest(manifestDocument);

    AsicArchiveManifest.Reference result = asicArchiveManifest.getReferencedTimestamp();

    assertThat(result, notNullValue());
    assertThat(result.getUri(), nullValue());
    assertThat(result.getName(), nullValue());
    assertThat(result.getMimeType(), nullValue());
  }

  @Test
  public void getReferencedTimestamp_WhenManifestContainsValidSigReference_ReturnsTimestampReferenceWithGivenValues() {
    DSSDocument manifestDocument = createAsicManifestXmlDocument(
            createAsicSigReferenceXmlElement("custom-mimetype-string", "custom-uri-string")
    );
    AsicArchiveManifest asicArchiveManifest = new AsicArchiveManifest(manifestDocument);

    AsicArchiveManifest.Reference result = asicArchiveManifest.getReferencedTimestamp();

    assertThat(result, notNullValue());
    assertThat(result.getUri(), equalTo("custom-uri-string"));
    assertThat(result.getName(), equalTo("custom-uri-string"));
    assertThat(result.getMimeType(), equalTo("custom-mimetype-string"));
  }

  @Test
  public void getReferencedTimestamp_WhenSigReferenceUriContainsPercentEncodedSpecialCharacters_ReturnsTimestampReferenceWithExpectedValues() {
    DSSDocument manifestDocument = createAsicManifestXmlDocument(
            createAsicSigReferenceXmlElement(null,
                    "%21%23%24%25%26%27%28%29%2B%2C-.%3B%3D%40%5B%5D%5E_%60%7B%7D%7E%20%C3%B5%C3%A4%C3%B6%C3%BC")
    );
    AsicArchiveManifest asicArchiveManifest = new AsicArchiveManifest(manifestDocument);

    AsicArchiveManifest.Reference result = asicArchiveManifest.getReferencedTimestamp();

    assertThat(result, notNullValue());
    assertThat(result.getUri(),
            equalTo("%21%23%24%25%26%27%28%29%2B%2C-.%3B%3D%40%5B%5D%5E_%60%7B%7D%7E%20%C3%B5%C3%A4%C3%B6%C3%BC"));
    assertThat(result.getName(), equalTo("!#$%&'()+,-.;=@[]^_`{}~ õäöü"));
    assertThat(result.getMimeType(), nullValue());
  }

  @Test
  public void getReferencedTimestamp_WhenSigReferenceUriContainsUnencodedSpecialCharacters_ReturnsTimestampReferenceWithExpectedValues() {
    DSSDocument manifestDocument = createAsicManifestXmlDocument(
            createAsicSigReferenceXmlElement(null, "!#$&amp;'()+,-.;=@[]^_`{}~ õäöü")
    );
    AsicArchiveManifest asicArchiveManifest = new AsicArchiveManifest(manifestDocument);

    AsicArchiveManifest.Reference result = asicArchiveManifest.getReferencedTimestamp();

    assertThat(result, notNullValue());
    assertThat(result.getUri(), equalTo("!#$&'()+,-.;=@[]^_`{}~ õäöü"));
    assertThat(result.getName(), equalTo("!#$&'()+,-.;=@[]^_`{}~ õäöü"));
    assertThat(result.getMimeType(), nullValue());
  }

  @Test
  public void getName_WhenSigReferenceUriIsUnencodedPercentCharacter_ThrowsException() {
    DSSDocument manifestDocument = createAsicManifestXmlDocument(
            createAsicSigReferenceXmlElement(null, "%")
    );
    AsicArchiveManifest asicArchiveManifest = new AsicArchiveManifest(manifestDocument);
    AsicArchiveManifest.Reference referencedTimestamp = asicArchiveManifest.getReferencedTimestamp();

    assertThrows(
            IllegalArgumentException.class,
            referencedTimestamp::getName
    );
  }

  @Test
  public void getReferencedDataObjects_WhenDocumentIsNotParsable_ThrowsException() {
    DSSDocument manifestDocument = new InMemoryDocument(
            "Not XML".getBytes(StandardCharsets.UTF_8),
            MANIFEST_NAME,
            MimeTypeEnum.XML
    );
    AsicArchiveManifest asicArchiveManifest = new AsicArchiveManifest(manifestDocument);

    TechnicalException caughtException = assertThrows(
            TechnicalException.class,
            asicArchiveManifest::getReferencedDataObjects
    );

    assertThat(caughtException.getMessage(), equalTo("Failed to parse manifest file: ManifestName.xml"));
  }

  @Test
  public void getReferencedDataObjects_WhenManifestDoesNotContainDataObjectReferences_ReturnsEmptyList() {
    DSSDocument manifestDocument = createAsicManifestXmlDocument();
    AsicArchiveManifest asicArchiveManifest = new AsicArchiveManifest(manifestDocument);

    List<AsicArchiveManifest.DataReference> result = asicArchiveManifest.getReferencedDataObjects();

    assertThat(result, empty());
  }

  @Test
  public void getReferencedDataObjects_WhenManifestContainsEmptyDataObjectReference_ReturnsListOfOneEmptyReference() {
    DSSDocument manifestDocument = createAsicManifestXmlDocument(
            createAsicDataObjectReferenceXmlElement(null, null)
    );
    AsicArchiveManifest asicArchiveManifest = new AsicArchiveManifest(manifestDocument);

    List<AsicArchiveManifest.DataReference> result = asicArchiveManifest.getReferencedDataObjects();

    assertThat(result, hasSize(1));
    assertThat(result.get(0).getUri(), nullValue());
    assertThat(result.get(0).getName(), nullValue());
    assertThat(result.get(0).getMimeType(), nullValue());
    assertThat(result.get(0).getDigestAlgorithm(), nullValue());
    assertThat(result.get(0).getDigestValue(), nullValue());
  }

  @Test
  public void getReferencedDataObjects_WhenManifestContainsValidDataObjectReference_ReturnsListOfOneEquivalentReference() {
    DSSDocument manifestDocument = createAsicManifestXmlDocument(
            createAsicDataObjectReferenceXmlElement(
                    "custom-mimetype-string", "custom-uri-string",
                    createDsDigestMethodXmlElement("custom-algorithm-string"),
                    createDsDigestValueXmlElement("custom-digest-string")
            )
    );
    AsicArchiveManifest asicArchiveManifest = new AsicArchiveManifest(manifestDocument);

    List<AsicArchiveManifest.DataReference> result = asicArchiveManifest.getReferencedDataObjects();

    assertThat(result, hasSize(1));
    assertThat(result.get(0).getUri(), equalTo("custom-uri-string"));
    assertThat(result.get(0).getName(), equalTo("custom-uri-string"));
    assertThat(result.get(0).getMimeType(), equalTo("custom-mimetype-string"));
    assertThat(result.get(0).getDigestAlgorithm(), equalTo("custom-algorithm-string"));
    assertThat(result.get(0).getDigestValue(), equalTo("custom-digest-string"));
  }

  @Test
  public void getReferencedDataObjects_WhenDataObjectReferenceUriContainsPercentEncodedSpecialCharacters_ReturnsListOfOneExpectedReference() {
    DSSDocument manifestDocument = createAsicManifestXmlDocument(
            createAsicDataObjectReferenceXmlElement(null,
                    "%21%23%24%25%26%27%28%29%2B%2C-.%3B%3D%40%5B%5D%5E_%60%7B%7D%7E%20%C3%B5%C3%A4%C3%B6%C3%BC")
    );
    AsicArchiveManifest asicArchiveManifest = new AsicArchiveManifest(manifestDocument);

    List<AsicArchiveManifest.DataReference> result = asicArchiveManifest.getReferencedDataObjects();

    assertThat(result, hasSize(1));
    assertThat(result.get(0).getUri(),
            equalTo("%21%23%24%25%26%27%28%29%2B%2C-.%3B%3D%40%5B%5D%5E_%60%7B%7D%7E%20%C3%B5%C3%A4%C3%B6%C3%BC"));
    assertThat(result.get(0).getName(), equalTo("!#$%&'()+,-.;=@[]^_`{}~ õäöü"));
    assertThat(result.get(0).getMimeType(), nullValue());
    assertThat(result.get(0).getDigestAlgorithm(), nullValue());
    assertThat(result.get(0).getDigestValue(), nullValue());
  }

  @Test
  public void getReferencedDataObjects_WhenDataObjectReferenceUriContainsUnencodedSpecialCharacters_ReturnsListOfOneExpectedReference() {
    DSSDocument manifestDocument = createAsicManifestXmlDocument(
            createAsicDataObjectReferenceXmlElement(null, "!#$&amp;'()+,-.;=@[]^_`{}~ õäöü")
    );
    AsicArchiveManifest asicArchiveManifest = new AsicArchiveManifest(manifestDocument);

    List<AsicArchiveManifest.DataReference> result = asicArchiveManifest.getReferencedDataObjects();

    assertThat(result, hasSize(1));
    assertThat(result.get(0).getUri(), equalTo("!#$&'()+,-.;=@[]^_`{}~ õäöü"));
    assertThat(result.get(0).getName(), equalTo("!#$&'()+,-.;=@[]^_`{}~ õäöü"));
    assertThat(result.get(0).getMimeType(), nullValue());
    assertThat(result.get(0).getDigestAlgorithm(), nullValue());
    assertThat(result.get(0).getDigestValue(), nullValue());
  }

  @Test
  public void getName_WhenDataObjectReferenceUriIsUnencodedPercentCharacter_ThrowsException() {
    DSSDocument manifestDocument = createAsicManifestXmlDocument(
            createAsicDataObjectReferenceXmlElement(null, "%")
    );
    AsicArchiveManifest asicArchiveManifest = new AsicArchiveManifest(manifestDocument);
    List<AsicArchiveManifest.DataReference> referencedDataObjects = asicArchiveManifest.getReferencedDataObjects();
    assertThat(referencedDataObjects, hasSize(1));
    AsicArchiveManifest.DataReference referencedDataObject = referencedDataObjects.get(0);

    assertThrows(
            IllegalArgumentException.class,
            referencedDataObject::getName
    );
  }

  @Test
  public void getNonNullEntryNames_WhenDocumentIsNotParsable_ThrowsException() {
    DSSDocument manifestDocument = new InMemoryDocument(
            "Not XML".getBytes(StandardCharsets.UTF_8),
            MANIFEST_NAME,
            MimeTypeEnum.XML
    );
    AsicArchiveManifest asicArchiveManifest = new AsicArchiveManifest(manifestDocument);

    TechnicalException caughtException = assertThrows(
            TechnicalException.class,
            asicArchiveManifest::getNonNullEntryNames
    );

    assertThat(caughtException.getMessage(), equalTo("Failed to parse manifest file: ManifestName.xml"));
  }

  @Test
  public void getNonNullEntryNames_WhenManifestDoesNotContainDataObjectReferences_ReturnsEmptySet() {
    DSSDocument manifestDocument = createAsicManifestXmlDocument();
    AsicArchiveManifest asicArchiveManifest = new AsicArchiveManifest(manifestDocument);

    Set<String> result = asicArchiveManifest.getNonNullEntryNames();

    assertThat(result, empty());
  }

  @Test
  public void getNonNullEntryNames_WhenManifestContainsDataObjectReferences_ReturnsSetOfNonNullReferenceNames() {
    DSSDocument manifestDocument = createAsicManifestXmlDocument(
            createAsicDataObjectReferenceXmlElement(null, null),
            createAsicDataObjectReferenceXmlElement("element-2-mimetype", null),
            createAsicDataObjectReferenceXmlElement(null, "element-3-uri"),
            createAsicDataObjectReferenceXmlElement("element-4-mimetype", "element-4-uri")
    );
    AsicArchiveManifest asicArchiveManifest = new AsicArchiveManifest(manifestDocument);

    Set<String> result = asicArchiveManifest.getNonNullEntryNames();

    assertThat(result, hasSize(2));
    assertThat(result, containsInAnyOrder("element-3-uri", "element-4-uri"));
  }

  @Test
  public void getNonNullEntryNames_WhenDataObjectReferenceUriIsUnencodedPercentCharacter_ThrowsException() {
    DSSDocument manifestDocument = createAsicManifestXmlDocument(
            createAsicDataObjectReferenceXmlElement(null, "%")
    );
    AsicArchiveManifest asicArchiveManifest = new AsicArchiveManifest(manifestDocument);

    assertThrows(
            IllegalArgumentException.class,
            asicArchiveManifest::getNonNullEntryNames
    );
  }

}
