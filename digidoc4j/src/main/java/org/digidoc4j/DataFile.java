/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.InvalidDataFileException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.StreamDocument;
import org.digidoc4j.utils.MimeTypeUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Data file wrapper providing methods for handling signed files or files to be signed in Container.
 */
public class DataFile implements Serializable {
  private static final Logger logger = LoggerFactory.getLogger(DataFile.class);

  private DSSDocument document = null;
  private String id;

  /**
   * Creates container.
   *
   * @param path     file name with path
   * @param mimeType MIME type of the data file, for example 'text/plain' or 'application/msword'
   */
  public DataFile(String path, String mimeType) {
    logger.debug("Path: {}, mime type: {}", path, mimeType);
    try {
      document = new FileDocument(path);
      document.setMimeType(getMimeType(mimeType));
    } catch (Exception e) {
      logger.error(e.getMessage());
      throw new InvalidDataFileException(e);
    }
  }

  /**
   * Creates in memory document container.
   *
   * @param data     file content
   * @param fileName file name with path
   * @param mimeType MIME type of the data file, for example 'text/plain' or 'application/msword'
   */
  public DataFile(byte[] data, String fileName, String mimeType) {
    logger.debug("File name: {}, mime type: {}", fileName, mimeType);
    document = new InMemoryDocument(data.clone(), fileName, getMimeType(mimeType));
  }

  /**
   * Creates in memory document container.
   *
   * @param stream   file content from stream
   * @param fileName file name with path
   * @param mimeType MIME type of the stream file, for example 'text/plain' or 'application/msword'
   */
  public DataFile(InputStream stream, String fileName, String mimeType) {
    logger.debug("File name: {}, mime type: {}", fileName, mimeType);
    try {
      document = new InMemoryDocument(stream, fileName, getMimeType(mimeType));
    } catch (Exception e) {
      logger.error(e.getMessage());
      throw new InvalidDataFileException(e);
    }
  }

  protected DataFile(DSSDocument document) {
    this.document = document;
  }

  /**
   * @deprecated Deprecated for removal.
   * Use parameterized constructors to create instances that do not need post-construct mutation.
   */
  @Deprecated
  public DataFile() {
  }

  protected static MimeType getMimeType(String mimeType) {
    try {
      MimeType mimeTypeCode = MimeTypeUtil.fromMimeTypeString(mimeType);
      logger.debug("Mime type: {}", mimeTypeCode);
      return mimeTypeCode;
    } catch (DSSException e) {
      logger.error(e.getMessage());
      throw new InvalidDataFileException(e);
    }
  }

  /**
   * Calculates digest http://www.w3.org/2001/04/xmlenc#sha256 for the data file.
   * If digest values are cached by the implementation and the digest has already been calculated,
   * then the cached value will be returned, otherwise the digest value is calculated and returned.
   *
   * @return calculated digest
   */
  public byte[] calculateDigest() {
    return calculateDigest(getSha256DigestMethodUrl());
  }

  /**
   * Calculates digest for data file.
   * If digest values are cached by the implementation and the digest has already been calculated,
   * then the cached value will be returned, otherwise the digest value is calculated and returned.
   *
   * <p>Supported uris for BDoc:</p>
   * <br>http://www.w3.org/2000/09/xmldsig#sha1
   * <br>http://www.w3.org/2001/04/xmldsig-more#sha224
   * <br>http://www.w3.org/2001/04/xmlenc#sha256
   * <br>http://www.w3.org/2001/04/xmldsig-more#sha384
   * <br>http://www.w3.org/2001/04/xmlenc#sha512
   * <p>In case of DDoc files the parameter is ignored and SHA1 hash is always returned</p>
   *
   * @param method method uri for calculating the digest
   * @return calculated digest
   */
  public byte[] calculateDigest(URL method) {
    logger.debug("URL method: {}", method);
    DigestAlgorithm digestAlgorithm = DigestAlgorithm.forXML(method.toString());
    String digestBase64String = document.getDigest(digestAlgorithm);
    return Base64.decodeBase64(digestBase64String);
  }

  /**
   * @param digestType digest algorithm type
   * @return digest algorithm uri
   */
  public byte[] calculateDigest(org.digidoc4j.DigestAlgorithm digestType) {
    return calculateDigest(digestType.uri());
  }

  /**
   * Returns the data file name.
   *
   * @return filename
   */
  public String getName() {
    String documentName = document.getName();
    String name = FilenameUtils.getName(documentName);
    logger.trace("File name for document {}: {}", documentName, name);
    return name;
  }

  /**
   * Returns file ID
   * For BDoc it will return the filename
   *
   * @return id or name
   */
  public String getId() {
    return (id == null ? getName() : id);
  }

  /**
   * Returns the data file size.
   *
   * @return file size in bytes
   */
  public long getFileSize() {
    Long knownFileSize = getFileSizeIfKnown();
    if (knownFileSize != null) {
      return knownFileSize;
    }
    long fileSize = 0L;
    try (InputStream inputStream = getStream()) {
      // Read the entire stream, but do not build yet another byte[] to hold the entire contents. Just skip and count the bytes.
      //  InputStream.skip(long) is not reliable to count the actual number of bytes available via an input stream.
      byte[] skipBuffer = new byte[IOUtils.DEFAULT_BUFFER_SIZE];
      int bytesRead;
      while ((bytesRead = inputStream.read(skipBuffer)) > 0) {
        fileSize += bytesRead;
      }
    } catch (IOException e) {
      throw new TechnicalException("Error reading document bytes: " + e.getMessage(), e);
    }
    logger.debug("File document size: {}", fileSize);
    return fileSize;
  }

  /**
   * Returns {@code true} if the data file size is 0 bytes.
   *
   * @return {@code true} if the data file is empty
   */
  public boolean isFileEmpty() {
    Long knownFileSize = getFileSizeIfKnown();
    if (knownFileSize != null) {
      return (knownFileSize < 1L);
    }
    try (InputStream inputStream = getStream()) {
      return (inputStream.read() < 0); // read() returns -1 if no bytes to read
    } catch (IOException e) {
      throw new TechnicalException("Error reading document bytes: " + e.getMessage(), e);
    }
  }

  private Long getFileSizeIfKnown() {
    if (document instanceof InMemoryDocument) {
      InMemoryDocument inMemoryDocument = (InMemoryDocument) document;
      if (inMemoryDocument.getBytes() != null) {
        return (long) (inMemoryDocument.getBytes().length);
      }
    } else if (document instanceof StreamDocument) {
      StreamDocument streamDocument = (StreamDocument) document;
      return streamDocument.getStreamLengthIfKnown();
    } else if (document instanceof FileDocument) {
      FileDocument fileDocument = (FileDocument) document;
      try {
        long fileSize = Files.size(Paths.get(fileDocument.getAbsolutePath()));
        logger.debug("Document size: {}", fileSize);
        return fileSize;
      } catch (IOException e) {
        logger.error(e.getMessage());
        throw new DigiDoc4JException(e);
      }
    }
    return null;
  }

  /**
   * Returns the file media type.
   *
   * @return media type
   */
  public String getMediaType() {
    String mediaType = document.getMimeType().getMimeTypeString();
    logger.debug("Media type: {}", mediaType);
    return mediaType;
  }

  /**
   * @deprecated Deprecated for removal.
   * Use parameterized constructors to create instances that do not need post-construct mutation.
   */
  @Deprecated
  public void setMediaType(String mediaType) {
    MimeType mimeType = getMimeType(mediaType);
    document.setMimeType(mimeType);
  }

  /**
   * Saves a copy of the data file as a file to the specified stream.
   *
   * @param out stream where data is written to
   * @throws java.io.IOException on file write error
   */
  public void saveAs(OutputStream out) throws IOException {
    try (OutputStream outputStream = out) {
      document.writeTo(outputStream);
    }
  }

  /**
   * Saves a copy of the data file as a file with the specified file name.
   *
   * @param path full file path where the data file should be saved to. If the file exists it will be overwritten
   */
  //TODO exception - method throws DSSException which can be caused by other exceptions
  public void saveAs(String path) {
    try {
      logger.debug("Path: {}", path);
      document.save(path);
    } catch (IOException e) {
      logger.error("Failed to save path {}", path);
      throw new TechnicalException("Failed to save path " + path, e);
    }
  }

  /**
   * Gives file bytes
   *
   * @return data as bytes
   */
  public byte[] getBytes() {
    try {
      return IOUtils.toByteArray(document.openStream());
    } catch (IOException e) {
      throw new TechnicalException("Error reading document bytes: " + e.getMessage(), e);
    }
  }

  /**
   * Gives data file as stream
   *
   * @return data file stream
   */
  public InputStream getStream() {
    return document.openStream();
  }

  /**
   * Set id for the dataFile (DDoc usage only)
   *
   * @param dataFileId id for the dataFile
   */
  public void setId(String dataFileId) {
    this.id = dataFileId;
  }

  public DSSDocument getDocument() {
    return document;
  }

  /**
   * @deprecated Deprecated for removal.
   * Use parameterized constructors to create instances that do not need post-construct mutation.
   */
  @Deprecated
  public void setDocument(DSSDocument document) {
    this.document = document;
  }

  private static URL getSha256DigestMethodUrl() {
    try {
      return new URL("http://www.w3.org/2001/04/xmlenc#sha256");
    } catch (MalformedURLException e) {
      throw new DigiDoc4JException(e);
    }
  }
}
