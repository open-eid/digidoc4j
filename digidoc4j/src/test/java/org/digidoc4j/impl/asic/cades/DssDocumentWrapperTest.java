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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

public class DssDocumentWrapperTest {

  @Test
  public void createInstance_WhenDocumentIsNull_ThrowsNullPointerException() {
    NullPointerException caughtException = assertThrows(
            NullPointerException.class,
            () -> new DssDocumentWrapper(null)
    );

    assertThat(caughtException.getMessage(), equalTo("Document cannot be null"));
  }

  @Test
  public void createInstance_WhenDocumentIsNotNull_DocumentNameAndMimeTypeAreQueried() {
    DSSDocument dssDocument = mock(DSSDocument.class);

    new DssDocumentWrapper(dssDocument);

    verify(dssDocument).getName();
    verify(dssDocument).getMimeType();
    verifyNoMoreInteractions(dssDocument);
  }

  @Test
  public void getWrapperDocument_WrappedDocumentIsReturnedWithoutAnyAdditionalInteractions() {
    DSSDocument dssDocument = mock(DSSDocument.class);
    DssDocumentWrapper documentWrapper = new DssDocumentWrapper(dssDocument);

    DSSDocument result = documentWrapper.getWrappedDocument();

    assertThat(result, sameInstance(dssDocument));
    verify(dssDocument).getName();
    verify(dssDocument).getMimeType();
    verifyNoMoreInteractions(dssDocument);
  }

  @Test
  public void getDigest_MethodCallIsDelegatedToWrappedDocumentWithoutAnyAdditionalInteractions() {
    DSSDocument dssDocument = mock(DSSDocument.class);
    DigestAlgorithm digestAlgorithm = DigestAlgorithm.WHIRLPOOL;
    Digest digest = mock(Digest.class);
    doReturn(digest).when(dssDocument).getDigest(digestAlgorithm);
    DssDocumentWrapper documentWrapper = new DssDocumentWrapper(dssDocument);

    Digest result = documentWrapper.getDigest(digestAlgorithm);

    assertThat(result, sameInstance(digest));
    verify(dssDocument).getName();
    verify(dssDocument).getMimeType();
    verify(dssDocument).getDigest(digestAlgorithm);
    verifyNoMoreInteractions(dssDocument);
    verifyNoInteractions(digest);
  }

  @Test
  public void getDigestValue_MethodCallIsDelegatedToWrappedDocumentWithoutAnyAdditionalInteractions() {
    DSSDocument dssDocument = mock(DSSDocument.class);
    DigestAlgorithm digestAlgorithm = DigestAlgorithm.WHIRLPOOL;
    doReturn("digest".getBytes(StandardCharsets.UTF_8)).when(dssDocument).getDigestValue(digestAlgorithm);
    DssDocumentWrapper documentWrapper = new DssDocumentWrapper(dssDocument);

    byte[] result = documentWrapper.getDigestValue(digestAlgorithm);

    assertThat(result, is("digest".getBytes(StandardCharsets.UTF_8)));
    verify(dssDocument).getName();
    verify(dssDocument).getMimeType();
    verify(dssDocument).getDigestValue(digestAlgorithm);
    verifyNoMoreInteractions(dssDocument);
  }

  @Test
  @SuppressWarnings("resource")
  public void openStream_MethodCallIsDelegatedToWrappedDocumentWithoutAnyAdditionalInteractions() {
    DSSDocument dssDocument = mock(DSSDocument.class);
    InputStream documentStream = mock(InputStream.class);
    doReturn(documentStream).when(dssDocument).openStream();
    DssDocumentWrapper documentWrapper = new DssDocumentWrapper(dssDocument);

    InputStream result = documentWrapper.openStream();

    assertThat(result, sameInstance(documentStream));
    verify(dssDocument).getName();
    verify(dssDocument).getMimeType();
    verify(dssDocument).openStream();
    verifyNoMoreInteractions(dssDocument);
    verifyNoInteractions(documentStream);
  }

  @Test
  public void save_MethodCallIsDelegatedToWrappedDocumentWithoutAnyAdditionalInteractions() throws Exception {
    DSSDocument dssDocument = mock(DSSDocument.class);
    DssDocumentWrapper documentWrapper = new DssDocumentWrapper(dssDocument);

    documentWrapper.save("/path/to/file");

    verify(dssDocument).getName();
    verify(dssDocument).getMimeType();
    verify(dssDocument).save("/path/to/file");
    verifyNoMoreInteractions(dssDocument);
  }

  @Test
  public void writeTo_MethodCallIsDelegatedToWrappedDocumentWithoutAnyAdditionalInteractions() throws Exception {
    DSSDocument dssDocument = mock(DSSDocument.class);
    DssDocumentWrapper documentWrapper = new DssDocumentWrapper(dssDocument);
    OutputStream outputStream = mock(OutputStream.class);

    documentWrapper.writeTo(outputStream);

    verify(dssDocument).getName();
    verify(dssDocument).getMimeType();
    verify(dssDocument).writeTo(outputStream);
    verifyNoMoreInteractions(dssDocument);
    verifyNoInteractions(outputStream);
  }

  @Test
  public void getName_WhenWrappedDocumentHasSpecifiedName_ReturnsExpectedName() {
    DSSDocument dssDocument = mock(DSSDocument.class);
    doReturn("some-specific-name.extension").when(dssDocument).getName();
    DssDocumentWrapper documentWrapper = new DssDocumentWrapper(dssDocument);

    String result = documentWrapper.getName();

    assertThat(result, equalTo("some-specific-name.extension"));
    verify(dssDocument).getName();
    verify(dssDocument).getMimeType();
    verifyNoMoreInteractions(dssDocument);
  }

  @Test
  public void setName_WrapperRegistersNameChangeButNameIsNotChangedInTheOriginalWrappedDocument() {
    DSSDocument dssDocument = mock(DSSDocument.class);
    doReturn("old-name").when(dssDocument).getName();
    DssDocumentWrapper documentWrapper = new DssDocumentWrapper(dssDocument);

    documentWrapper.setName("new-name");

    assertThat(documentWrapper.getName(), equalTo("new-name"));
    verify(dssDocument).getName();
    verify(dssDocument).getMimeType();
    verifyNoMoreInteractions(dssDocument);
  }

  @Test
  public void isNameUpdated_WhenSetNameHasNotBeenCalled_ReturnsFalse() {
    DSSDocument dssDocument = mock(DSSDocument.class);
    doReturn("original-name").when(dssDocument).getName();
    DssDocumentWrapper documentWrapper = new DssDocumentWrapper(dssDocument);

    boolean result = documentWrapper.isNameUpdated();

    assertThat(result, is(false));
    verify(dssDocument, times(2)).getName();
    verify(dssDocument).getMimeType();
    verifyNoMoreInteractions(dssDocument);
  }

  @Test
  public void isNameUpdated_WhenSetNameHasBeenCalledWithTheSameName_ReturnsFalse() {
    DSSDocument dssDocument = mock(DSSDocument.class);
    doReturn("original-name").when(dssDocument).getName();
    DssDocumentWrapper documentWrapper = new DssDocumentWrapper(dssDocument);
    documentWrapper.setName("original-name");

    boolean result = documentWrapper.isNameUpdated();

    assertThat(result, is(false));
    verify(dssDocument, times(2)).getName();
    verify(dssDocument).getMimeType();
    verifyNoMoreInteractions(dssDocument);
  }

  @Test
  public void isNameUpdated_WhenSetNameHasBeenCalledWithDifferentName_ReturnsTrue() {
    DSSDocument dssDocument = mock(DSSDocument.class);
    doReturn("old-name").when(dssDocument).getName();
    DssDocumentWrapper documentWrapper = new DssDocumentWrapper(dssDocument);
    documentWrapper.setName("new-name");

    boolean result = documentWrapper.isNameUpdated();

    assertThat(result, is(true));
    verify(dssDocument, times(2)).getName();
    verify(dssDocument).getMimeType();
    verifyNoMoreInteractions(dssDocument);
  }

  @Test
  public void getMimeType_WhenWrappedDocumentHasSpecifiedMimeType_ReturnsExpectedMimeType() {
    DSSDocument dssDocument = mock(DSSDocument.class);
    MimeType documentMimeType = mock(MimeType.class);
    doReturn(documentMimeType).when(dssDocument).getMimeType();
    DssDocumentWrapper documentWrapper = new DssDocumentWrapper(dssDocument);

    MimeType result = documentWrapper.getMimeType();

    assertThat(result, sameInstance(documentMimeType));
    verify(dssDocument).getName();
    verify(dssDocument).getMimeType();
    verifyNoMoreInteractions(dssDocument);
  }

  @Test
  public void setMimeType_WrapperRegistersMimeTypeChangeButMimeTypeIsNotChangedInTheOriginalWrappedDocument() {
    DSSDocument dssDocument = mock(DSSDocument.class);
    MimeType oldMimeType = mock(MimeType.class);
    doReturn(oldMimeType).when(dssDocument).getMimeType();
    DssDocumentWrapper documentWrapper = new DssDocumentWrapper(dssDocument);
    MimeType newMimeType = mock(MimeType.class);

    documentWrapper.setMimeType(newMimeType);

    assertThat(documentWrapper.getMimeType(), sameInstance(newMimeType));
    verify(dssDocument).getName();
    verify(dssDocument).getMimeType();
    verifyNoMoreInteractions(dssDocument);
    verifyNoInteractions(oldMimeType, newMimeType);
  }

  @Test
  public void isMimeTypeUpdated_WhenSetMimeTypeHasNotBeenCalled_ReturnsFalse() {
    DSSDocument dssDocument = mock(DSSDocument.class);
    MimeType originalMimeType = mock(MimeType.class);
    doReturn(originalMimeType).when(dssDocument).getMimeType();
    DssDocumentWrapper documentWrapper = new DssDocumentWrapper(dssDocument);

    boolean result = documentWrapper.isMimeTypeUpdated();

    assertThat(result, is(false));
    verify(dssDocument).getName();
    verify(dssDocument, times(2)).getMimeType();
    verifyNoMoreInteractions(dssDocument);
    verifyNoInteractions(originalMimeType);
  }

  @Test
  public void isMimeTypeUpdated_WhenSetMimeTypeHasBeenCalledWithTheSameMimeType_ReturnsFalse() {
    DSSDocument dssDocument = mock(DSSDocument.class);
    MimeType originalMimeType = mock(MimeType.class);
    doReturn(originalMimeType).when(dssDocument).getMimeType();
    DssDocumentWrapper documentWrapper = new DssDocumentWrapper(dssDocument);
    documentWrapper.setMimeType(originalMimeType);

    boolean result = documentWrapper.isMimeTypeUpdated();

    assertThat(result, is(false));
    verify(dssDocument).getName();
    verify(dssDocument, times(2)).getMimeType();
    verifyNoMoreInteractions(dssDocument);
    verifyNoInteractions(originalMimeType);
  }

  @Test
  public void isMimeTypeUpdated_WhenSetMimeTypeHasBeenCalledWithDifferentMimeType_ReturnsTrue() {
    DSSDocument dssDocument = mock(DSSDocument.class);
    MimeType oldMimeType = mock(MimeType.class);
    doReturn(oldMimeType).when(dssDocument).getMimeType();
    DssDocumentWrapper documentWrapper = new DssDocumentWrapper(dssDocument);
    MimeType newMimeType = mock(MimeType.class);
    documentWrapper.setMimeType(newMimeType);

    boolean result = documentWrapper.isMimeTypeUpdated();

    assertThat(result, is(true));
    verify(dssDocument).getName();
    verify(dssDocument, times(2)).getMimeType();
    verifyNoMoreInteractions(dssDocument);
    verifyNoInteractions(oldMimeType, newMimeType);
  }

}
