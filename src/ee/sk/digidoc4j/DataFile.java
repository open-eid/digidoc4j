package ee.sk.digidoc4j;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.Digest;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.signature.MimeType;

import java.io.FileNotFoundException;
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
   * <p/>
   *
   * @param path     file name with path
   * @param mimeType MIME type of the data file, for example 'text/plain' or 'application/msword'
   * @throws Exception is thrown when file not exists
   */
  public DataFile(final String path, final String mimeType) throws Exception {
    try {
      document = new FileDocument(path);
      document.setMimeType(MimeType.fromCode(mimeType));
    } catch (Exception e) {
      if (e.getMessage().toLowerCase().contains("file not found")) {
        throw new FileNotFoundException(e.getMessage());
      }
      throw e;
    }
  }

  /**
   * Calculates digest http://www.w3.org/2001/04/xmlenc#sha256 for the data file.
   * If the digest has already been calculated it will return it, otherwise it calculates the digest.
   * <p/>
   *
   * @return calculated digest
   * @throws Exception thrown if the file does not exist or the digest calculation fails.
   */
  public final byte[] calculateDigest() throws Exception {
    return calculateDigest(new URL("http://www.w3.org/2001/04/xmlenc#sha256"));
  }

  /**
   * Calculates digest for data file. If digest is already calculated returns it, otherwise calculates the digest.
   * <p>Supported uris for BDoc:</p>
   * <br></br>http://www.w3.org/2000/09/xmldsig#sha1
   * <br>http://www.w3.org/2001/04/xmldsig-more#sha224
   * <br>http://www.w3.org/2001/04/xmlenc#sha256
   * <br>http://www.w3.org/2001/04/xmldsig-more#sha384
   * <br>http://www.w3.org/2001/04/xmlenc#sha512
   * <p>In case of DDoc files the parameter is ignored and SHA1 hash is always returned</p>
   *
   * @param method method uri for calculating the digest
   * @return calculated digest
   * @throws Exception thrown if the file does not exist or the digest calculation fails.
   */
  public final byte[] calculateDigest(final URL method) throws Exception {
    if (digest == null) {
      DigestAlgorithm digestAlgorithm = DigestAlgorithm.forXML(method.toString());
      digest = new Digest(digestAlgorithm, calculateDigestInternal(digestAlgorithm));
    }
    return digest.getValue();
  }

  protected final byte[] calculateDigestInternal(final DigestAlgorithm digestAlgorithm) {
    return DSSUtils.digest(digestAlgorithm, document.getBytes());
  }

  /**
   * Returns the data file name.
   *
   * @return file name
   */
  public final String getFileName() {
    return document.getName();
  }

  /**
   * @return the data file size
   */
  public final long getFileSize() {
    return document.getBytes().length;
  }

  /**
   * Returns file media type.
   *
   * @return media type
   */
  public final String getMediaType() {
    return document.getMimeType().getCode();
  }

  /**
   * Saves a copy of the data file as file specified by the stream.
   *
   * @param out stream where data is written
   * @throws java.io.IOException is thrown when not possible to write to stream
   */
  public final void saveAs(final OutputStream out) throws IOException {
    out.write(document.getBytes());
  }

  /**
   * Saves a copy of the data file as file specified by the path.
   *
   * @param path full file path where the data file should be saved to. If the file exists it will be overwritten
   * @throws java.io.IOException thrown if part of the path does not exist
   *                             or the path is an existing directory (without file name)
   */
  public final void saveAs(final String path) throws IOException {
    document.save(path);
  }

}
