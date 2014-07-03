package org.digidoc4j.api;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.Digest;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import org.apache.commons.io.IOUtils;
import org.digidoc4j.api.exceptions.DigiDoc4JException;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;

/**
 * Data file wrapper providing methods for handling signed files or files to be signed in Container.
 */
public class DataFile {

  private DSSDocument document = null;
  private Digest digest = null;

  /**
   * Creates container.
   *
   * @param path     file name with path
   * @param mimeType MIME type of the data file, for example 'text/plain' or 'application/msword'
   */
  public DataFile(String path, String mimeType) {
    try {
      FileInputStream stream = new FileInputStream(path);
      loadDocument(IOUtils.toByteArray(stream), path, mimeType);
      stream.close();
    }
    catch (Exception e) {
      throw new DigiDoc4JException(e);
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
    loadDocument(data, fileName, mimeType);
  }

  private void loadDocument(byte[] data, String fileName, String mimeType) {
    MimeType mimeTypeCode = getMimeType(mimeType);
    document = new InMemoryDocument(data, fileName, mimeTypeCode);
  }

  private MimeType getMimeType(String mimeType) {
    MimeType mimeTypeCode = MimeType.fromCode(mimeType);
    if (mimeTypeCode == null) throw new DigiDoc4JException("Unknown mime type");
    return mimeTypeCode;
  }

  /**
   * Calculates digest http://www.w3.org/2001/04/xmlenc#sha256 for the data file.
   * If the digest has already been calculated it will return it, otherwise it calculates the digest.
   * <p/>
   *
   * @return calculated digest
   * @throws Exception thrown if the file does not exist or the digest calculation fails.
   */
  public byte[] calculateDigest() throws Exception {
    return calculateDigest(new URL("http://www.w3.org/2001/04/xmlenc#sha256"));
  }

  /**
   * Calculates digest for data file. If digest is already calculated returns it, otherwise calculates the digest.
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
  public byte[] calculateDigest(URL method) {        // TODO exceptions to throw
    if (digest == null) {
      DigestAlgorithm digestAlgorithm = DigestAlgorithm.forXML(method.toString());
      digest = new Digest(digestAlgorithm, calculateDigestInternal(digestAlgorithm));
    }
    return digest.getValue();
  }

  byte[] calculateDigestInternal(DigestAlgorithm digestAlgorithm) {
    return DSSUtils.digest(digestAlgorithm, document.getBytes());
  }

  /**
   * Returns the data file name.
   *
   * @return filename
   */
  public String getFileName() {
    if (document instanceof InMemoryDocument)
      return document.getName();
    return document.getAbsolutePath();
  }

  /**
   * Returns the data file size.
   *
   * @return file size
   */
  public long getFileSize() {
    return document.getBytes().length;
  }

  /**
   * Returns the file media type.
   *
   * @return media type
   */
  public String getMediaType() {
    return document.getMimeType().getCode();
  }

  /**
   * Saves a copy of the data file as a file to the specified stream.
   *
   * @param out stream where data is written to
   */
  public void saveAs(OutputStream out) throws IOException {
    out.write(document.getBytes());
  }

  /**
   * Saves a copy of the data file as a file with the specified file name.
   *
   * @param path full file path where the data file should be saved to. If the file exists it will be overwritten
   */
  //TODO exception - method throws DSSException which can be caused by other exceptions
  public void saveAs(String path) {
    document.save(path);
  }

  public byte[] getBytes() {
    return document.getBytes();
  }
}
