/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl;


import eu.europa.esig.dss.model.CommonDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.MimeType;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * @see eu.europa.esig.dss.model.DSSDocument implementation to handle big files. It writes data to temporary
 * files.
 */
public class StreamDocument extends CommonDocument {
  private static final Logger logger = LoggerFactory.getLogger(StreamDocument.class);

  private static final int MAX_SIZE_IN_MEMORY = 1024 * 5;
  File temporaryFile;

  //TODO if file is small enough you can read it into byte[] and cache it

  /**
   * Add javadoc here
   *
   * @param stream       stream
   * @param documentName document Name
   * @param mimeType     mime type
   */
  public StreamDocument(InputStream stream, String documentName, MimeType mimeType) {
    logger.debug("Document name: " + documentName + ", mime type: " + mimeType);
    createTemporaryFileOfStream(stream);
    super.name = documentName;
    super.mimeType = mimeType;
  }

  private void createTemporaryFileOfStream(InputStream stream) {
    byte[] bytes = new byte[MAX_SIZE_IN_MEMORY];

    FileOutputStream out = null;

    try {
      temporaryFile = File.createTempFile("digidoc4j", ".tmp");
      out = new FileOutputStream(temporaryFile);
      int result;
      while ((result = stream.read(bytes)) > 0) {
        out.write(bytes, 0, result);
      }
      out.flush();
      temporaryFile.deleteOnExit();
    } catch (IOException e) {
      logger.error(e.getMessage());
      throw new DSSException(e);
    } finally {
      IOUtils.closeQuietly(out);
    }
  }


  @Override
  public InputStream openStream() throws DSSException {
    try {
      return getTemporaryFileAsStream();
    } catch (FileNotFoundException e) {
      logger.error(e.getMessage());
      throw new DSSException(e);
    }
  }

  @Override
  public void setName(String s) {
  }

  @Override
  public String getAbsolutePath() {
    return temporaryFile.getAbsolutePath();
  }

  @Override
  public MimeType getMimeType() {
    MimeType mimeType = super.getMimeType();
    logger.debug("Mime type: " + mimeType);
    return mimeType;
  }

  @Override
  public void setMimeType(MimeType mimeType) {
    logger.debug("Mime type: " + mimeType);
    super.setMimeType(mimeType);
  }

  @Override
  public void save(String filePath) {
    logger.debug("File Path: " + filePath);
    try {
      FileOutputStream fileOutputStream = new FileOutputStream(filePath);
      try {
        IOUtils.copy(getTemporaryFileAsStream(), fileOutputStream);
      } finally {
        fileOutputStream.close();
      }
    } catch (IOException e) {
      logger.error(e.getMessage());
      throw new DSSException(e);
    }
  }

  @Override
  public String getDigest(DigestAlgorithm digestAlgorithm) {
    logger.debug("Digest algorithm: " + digestAlgorithm);
    byte[] digestBytes;
    try {
      digestBytes = DSSUtils.digest(digestAlgorithm, getTemporaryFileAsStream());
    } catch (FileNotFoundException e) {
      logger.error(e.getMessage());
      throw new DSSException(e);
    }
    return Base64.encodeBase64String(digestBytes);
  }

  protected FileInputStream getTemporaryFileAsStream() throws FileNotFoundException {
    return new FileInputStream(this.temporaryFile);
  }

}
