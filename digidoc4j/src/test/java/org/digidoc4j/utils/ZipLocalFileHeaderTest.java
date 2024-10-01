/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.utils;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

public class ZipLocalFileHeaderTest {

  @Test
  public void readStaticHeaderPart_WhenInputIsShorterThanHeaderSignature_ThrowsEOFException() {
    ByteArrayInputStream input = getInputStreamFromHex("504b03");

    EOFException caughtException = assertThrows(
            EOFException.class,
            () -> ZipLocalFileHeader.readStaticHeaderPart(input)
    );

    assertThat(caughtException.getMessage(), equalTo("Unexpected EOF"));
  }

  @Test
  public void readStaticHeaderPart_WhenInputIsNoLongerThanHeaderSignature_ThrowsEOFException() {
    ByteArrayInputStream input = getInputStreamFromHex("504b0304");

    EOFException caughtException = assertThrows(
            EOFException.class,
            () -> ZipLocalFileHeader.readStaticHeaderPart(input)
    );

    assertThat(caughtException.getMessage(), equalTo("Unexpected EOF"));
  }

  @Test
  public void readStaticHeaderPart_WhenInputIsNotZipLocalHeader_ThrowsUnrecognizedSignatureException() {
    ByteArrayInputStream input = getInputStreamFromUtf8("This is a text file.");

    ZipLocalFileHeader.UnrecognizedSignatureException caughtException = assertThrows(
            ZipLocalFileHeader.UnrecognizedSignatureException.class,
            () -> ZipLocalFileHeader.readStaticHeaderPart(input)
    );

    assertThat(caughtException.getMessage(), equalTo("Not a ZIP local file header signature"));
  }

  @Test
  public void readStaticHeaderPart_WhenInputIsReadableAsZipLocalFileHeader_ReturnsEquivalentHeaderObject() throws Exception {
    ByteArrayInputStream input = getInputStreamFromHex("504b0304" +
            "0102030405060708090a0b0c0d0e0f101112131415161718191a");

    ZipLocalFileHeader result = ZipLocalFileHeader.readStaticHeaderPart(input);

    assertThat(result, notNullValue());
    assertThat(result.getSignature(), equalTo(ZipLocalFileHeader.LOCAL_FILE_HEADER_SIGNATURE));
    assertThat(result.getMinimumVersion(), equalTo((short) 0x0201));
    assertThat(result.getGeneralPurposeBitFlag(), equalTo((short) 0x0403));
    assertThat(result.getCompressionMethod(), equalTo((short) 0x0605));
    assertThat(result.getFileLastModifiedTime(), equalTo((short) 0x0807));
    assertThat(result.getFileLastModifiedDate(), equalTo((short) 0x0a09));
    assertThat(result.getCrc32OfUncompressedData(), equalTo(0x0e0d0c0b));
    assertThat(result.getCompressedSize(), equalTo(0x1211100f));
    assertThat(result.getUncompressedSize(), equalTo(0x16151413));
    assertThat(result.getFileNameLength(), equalTo((short) 0x1817));
    assertThat(result.getExtraFieldLength(), equalTo((short) 0x1a19));
    assertThat(input.available(), equalTo(0));
  }

  @Test
  public void readFileNameFrom_WhenNameLengthIs0_ReturnsEmptyArray() throws Exception {
    ZipLocalFileHeader header = createHeaderMockWithNameLength(0);
    ByteArrayInputStream input = getInputStreamFromBytes();

    byte[] result = header.readFileNameFrom(input);

    assertThat(result, notNullValue());
    assertThat(result.length, equalTo(0));
    verify(header).readFileNameFrom(input);
    verify(header).getFileNameLength();
    verifyNoMoreInteractions(header);
  }

  @Test
  public void readFileNameFrom_WhenNameLengthIsGreaterThanInputLength_ThrowsEOFException() throws Exception {
    ZipLocalFileHeader header = createHeaderMockWithNameLength(10);
    ByteArrayInputStream input = getInputStreamFromUtf8("too short");

    EOFException caughtException = assertThrows(
            EOFException.class,
            () -> header.readFileNameFrom(input)
    );

    assertThat(caughtException.getMessage(), equalTo("Unexpected EOF"));
    verify(header).readFileNameFrom(input);
    verify(header, times(2)).getFileNameLength();
    verifyNoMoreInteractions(header);
  }

  @Test
  public void readFileNameFrom_WhenNameLengthFitsInsideInput_ReturnsNameBytes() throws Exception {
    ZipLocalFileHeader header = createHeaderMockWithNameLength(14);
    ByteArrayInputStream input = getInputStreamFromUtf8("some very long input");

    byte[] result = header.readFileNameFrom(input);

    assertThat(result, notNullValue());
    assertArrayEquals("some very long".getBytes(StandardCharsets.UTF_8), result);
    verify(header).readFileNameFrom(input);
    verify(header, times(2)).getFileNameLength();
    verifyNoMoreInteractions(header);
  }

  private static ByteArrayInputStream getInputStreamFromBytes(byte... bytes) {
    return new ByteArrayInputStream(bytes);
  }

  private static ByteArrayInputStream getInputStreamFromHex(String hexString) {
    try {
      return getInputStreamFromBytes(Hex.decodeHex(hexString));
    } catch (DecoderException e) {
      throw new IllegalArgumentException("Failed to decode HEX", e);
    }
  }

  private static ByteArrayInputStream getInputStreamFromUtf8(String utf8String) {
    return getInputStreamFromBytes(utf8String.getBytes(StandardCharsets.UTF_8));
  }

  private static ZipLocalFileHeader createHeaderMockWithNameLength(int fileNameLength) throws Exception {
    ZipLocalFileHeader zipLocalFileHeaderMock = mock(ZipLocalFileHeader.class);
    doCallRealMethod().when(zipLocalFileHeaderMock).readFileNameFrom(any(InputStream.class));
    doReturn((short) fileNameLength).when(zipLocalFileHeaderMock).getFileNameLength();
    return zipLocalFileHeaderMock;
  }

}
