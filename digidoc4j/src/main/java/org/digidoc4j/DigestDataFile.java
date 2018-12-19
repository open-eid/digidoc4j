package org.digidoc4j;

import eu.europa.esig.dss.DigestDocument;
import org.apache.commons.codec.binary.Base64;
import org.digidoc4j.exceptions.InvalidDataFileException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

public class DigestDataFile extends DataFile {

  private static final Logger logger = LoggerFactory.getLogger(DigestDataFile.class);


  private String contentType = null;

  /**
   * Creates digest based data file.
   * In other words only the content's digest (not the content itself) is provided.
   *
   * @param fileName name of the file
   * @param digestAlgorithm algorithm of the digest
   * @param digest digest of the file contents
   */
  public DigestDataFile(String fileName, DigestAlgorithm digestAlgorithm, byte[] digest) {
    logger.debug("File name: " + fileName +
        ", digest algorithm: " + digestAlgorithm + ", digest: " + Arrays.toString(digest));
    try {
      DigestDocument document = new DigestDocument();
      document.setName(fileName);
      document.addDigest(digestAlgorithm.getDssDigestAlgorithm(), Base64.encodeBase64String(digest));
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
