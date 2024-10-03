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

import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.model.DigestDocument;
import org.apache.commons.codec.binary.Base64;
import org.digidoc4j.exceptions.InvalidDataFileException;
import org.digidoc4j.exceptions.NotSupportedException;
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
   * @param fileName        name of the file
   * @param digestAlgorithm algorithm of the digest
   * @param digest          digest of the file contents
   * @param mimeType        mime-type of the data file, for example 'text/plain' or 'application/msword'
   */
  public DigestDataFile(String fileName, DigestAlgorithm digestAlgorithm, byte[] digest, String mimeType) {
    super(createDigestDocument(fileName, digestAlgorithm, digest, getMimeType(mimeType)));
  }

  private static DigestDocument createDigestDocument(String fileName, DigestAlgorithm digestAlgorithm, byte[] digest, MimeType mimeType) {
    if (logger.isDebugEnabled()) {
      logger.debug("File name: {}, digest algorithm: {}, digest: {}",
              fileName, digestAlgorithm, Arrays.toString(digest));
    }
    try {
      DigestDocument document = new DigestDocument();
      document.setName(fileName);
      document.addDigest(digestAlgorithm.getDssDigestAlgorithm(), Base64.encodeBase64String(digest));
      if (mimeType != null) {
        document.setMimeType(mimeType);
      }
      return document;
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

  @Override
  public long getFileSize() {
    throw new NotSupportedException("Querying size of digest datafile is not supported");
  }

  @Override
  public boolean isFileEmpty() {
    return false;
  }

}
