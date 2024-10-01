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

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * A low-level helper class for reading and extracting information from ZIP local file headers.
 * https://en.wikipedia.org/wiki/ZIP_(file_format)#Local_file_header
 */
public class ZipLocalFileHeader {

  public static final int LOCAL_FILE_HEADER_SIGNATURE = 0x04034b50;

  public static final short COMPRESSION_METHOD_NONE = 0;
  public static final short COMPRESSION_METHOD_DEFLATE = 8;

  private static final int LOCAL_FILE_HEADER_SIGNATURE_OFFSET = 0;
  private static final int MINIMUM_VERSION_OFFSET = 4;
  private static final int GENERAL_PURPOSE_BIT_FLAG_OFFSET = 6;
  private static final int COMPRESSION_METHOD_OFFSET = 8;
  private static final int FILE_LAST_MODIFIED_TIME_OFFSET = 10;
  private static final int FILE_LAST_MODIFIED_DATE_OFFSET = 12;
  private static final int CRC32_OF_UNCOMPRESSED_DATA_OFFSET = 14;
  private static final int COMPRESSED_SIZE_OFFSET = 18;
  private static final int UNCOMPRESSED_SIZE_OFFSET = 22;
  private static final int FILE_NAME_LENGTH_OFFSET = 26;
  private static final int EXTRA_FIELD_LENGTH_OFFSET = 28;
  private static final int FILE_NAME_OFFSET = 30;

  private final ByteBuffer headerBuffer;

  /**
   * Tries to read the static part of the first ZIP local file header from the specified input.
   *
   * @param inputStream input stream to read the ZIP local file header from
   * @return the static part of the first ZIP local file header read from the input stream
   *
   * @throws EOFException if EOF is reached before reading the entire ZIP local file header
   * @throws UnrecognizedSignatureException if the input stream does not begin with the ZIP local file header signature
   * @throws IOException if an I/O exception occurs while reading from the input stream
   */
  public static ZipLocalFileHeader readStaticHeaderPart(InputStream inputStream) throws IOException {
    byte[] staticHeaderBytes = new byte[FILE_NAME_OFFSET];
    readExactly(inputStream, staticHeaderBytes, 0, Integer.BYTES);

    ByteBuffer staticHeaderBuffer = wrapIntoByteBuffer(staticHeaderBytes);
    if (staticHeaderBuffer.getInt(LOCAL_FILE_HEADER_SIGNATURE_OFFSET) != LOCAL_FILE_HEADER_SIGNATURE) {
      throw new UnrecognizedSignatureException();
    }

    readExactly(inputStream, staticHeaderBytes, Integer.BYTES, FILE_NAME_OFFSET - Integer.BYTES);
    return new ZipLocalFileHeader(staticHeaderBuffer);
  }

  /**
   * Tries to read ZIP local file header file name field from the specified input.
   * Expects the specified input stream to be position at the beginning of the file name field to read.
   * Can be called right after calling {@link #readStaticHeaderPart(InputStream)}.
   *
   * @param inputStream input stream to read the ZIP local file header file name field from
   * @return file name as an array of bytes
   *
   * @throws EOFException if EOF is reached before reading the entire file name
   * @throws IOException if an I/O exception occurs while reading from the input stream
   */
  public byte[] readFileNameFrom(InputStream inputStream) throws IOException {
    if (getFileNameLength() == 0) {
      return ArrayUtils.EMPTY_BYTE_ARRAY;
    }

    byte[] fileNameBytes = new byte[getFileNameLength() & 0xffff];
    readExactly(inputStream, fileNameBytes, 0, fileNameBytes.length);
    return fileNameBytes;
  }

  private ZipLocalFileHeader(ByteBuffer headerBuffer) {
    this.headerBuffer = headerBuffer;
  }

  public int getSignature() {
    return headerBuffer.getInt(LOCAL_FILE_HEADER_SIGNATURE_OFFSET);
  }

  public short getMinimumVersion() {
    return headerBuffer.getShort(MINIMUM_VERSION_OFFSET);
  }

  public short getGeneralPurposeBitFlag() {
    return headerBuffer.getShort(GENERAL_PURPOSE_BIT_FLAG_OFFSET);
  }

  public short getCompressionMethod() {
    return headerBuffer.getShort(COMPRESSION_METHOD_OFFSET);
  }

  public short getFileLastModifiedTime() {
    return headerBuffer.getShort(FILE_LAST_MODIFIED_TIME_OFFSET);
  }

  public short getFileLastModifiedDate() {
    return headerBuffer.getShort(FILE_LAST_MODIFIED_DATE_OFFSET);
  }

  public int getCrc32OfUncompressedData() {
    return headerBuffer.getInt(CRC32_OF_UNCOMPRESSED_DATA_OFFSET);
  }

  public int getCompressedSize() {
    return headerBuffer.getInt(COMPRESSED_SIZE_OFFSET);
  }

  public int getUncompressedSize() {
    return headerBuffer.getInt(UNCOMPRESSED_SIZE_OFFSET);
  }

  public short getFileNameLength() {
    return headerBuffer.getShort(FILE_NAME_LENGTH_OFFSET);
  }

  public short getExtraFieldLength() {
    return headerBuffer.getShort(EXTRA_FIELD_LENGTH_OFFSET);
  }

  private static ByteBuffer wrapIntoByteBuffer(byte[] bytes) {
    return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
  }

  private static void readExactly(InputStream inputStream, byte[] buffer, int offset, int length) throws IOException {
    if (IOUtils.read(inputStream, buffer, offset, length) < length) {
      throw new EOFException("Unexpected EOF");
    }
  }

  public static class UnrecognizedSignatureException extends IOException {

    public UnrecognizedSignatureException() {
      super("Not a ZIP local file header signature");
    }

  }

}
