package org.digidoc4j;

import java.util.Arrays;

import org.apache.commons.codec.binary.Base64;
import org.digidoc4j.exceptions.InvalidDataFileException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DigestDocument;
import eu.europa.esig.dss.MimeType;

public class DigestDataFile extends DataFile {

  private static final Logger logger = LoggerFactory.getLogger(DigestDataFile.class);

  private String contentType = null;

  /**
   * Creates digest based data file.
   * In other words only the content's digest (not the content itself) is provided.
   *
   * @param fileName        name of the file
   * @param digestAlgorithm algorithm of the digest
   * @param digest          digest of the file contents
   * @param mimeType        mime-type of the data file, for example 'text/plain' or 'application/msword'
   */
  public DigestDataFile(String fileName, DigestAlgorithm digestAlgorithm, byte[] digest, String mimeType) {
    setDigestDataFile(fileName, digestAlgorithm, digest, getMimeType(mimeType));
  }

  /**
   * Creates digest based data file.
   * In other words only the content's digest (not the content itself) is provided.
   *
   * @param fileName        name of the file
   * @param digestAlgorithm algorithm of the digest
   * @param digest          digest of the file contents
   * @deprecated use DigestDataFile(String fileName, DigestAlgorithm digestAlgorithm, byte[] digest, String mimeType)
   * https://github.com/open-eid/digidoc4j/wiki/Examples-of-using-it#detached-xades-containerless-signature-handling
   */
  @Deprecated
  public DigestDataFile(String fileName, DigestAlgorithm digestAlgorithm, byte[] digest) {
    setDigestDataFile(fileName, digestAlgorithm, digest, null);
  }

  private void setDigestDataFile(String fileName, DigestAlgorithm digestAlgorithm, byte[] digest, MimeType mimeType) {
    logger.debug("File name: " + fileName +
        ", digest algorithm: " + digestAlgorithm + ", digest: " + Arrays.toString(digest));
    try {
      DigestDocument document = new DigestDocument();
      document.setName(fileName);
      document.addDigest(digestAlgorithm.getDssDigestAlgorithm(), Base64.encodeBase64String(digest));
      if (mimeType != null)
        document.setMimeType(mimeType);
      setDocument(document);
    } catch (Exception e) {
      logger.error(e.getMessage());
      throw new InvalidDataFileException(e);
    }
  }

  public String getContentType() {
    return contentType;
  }

  public void setContentType(String contentType) {
    this.contentType = contentType;
  }
}
