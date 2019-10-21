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

import java.io.InputStream;

import org.digidoc4j.exceptions.InvalidDataFileException;
import org.digidoc4j.impl.StreamDocument;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSDocument;

/**
 * Handling large files from a stream to be stored temporarily on disk.
 * <p/>
 * If you would like to add a large file from a stream to a container that is too large to be stored in memory.
 */
public class LargeDataFile extends DataFile {

  private static final Logger logger = LoggerFactory.getLogger(LargeDataFile.class);

  /**
   * Creates a data file from a stream that is going to be stored as a temporary file on the file system.
   *
   * @param stream   data file stream.
   * @param fileName name of the file
   * @param mimeType MIME type of the stream file, for example 'text/plain' or 'application/msword'
   */
  public LargeDataFile(InputStream stream, String fileName, String mimeType) {
    logger.debug("Large file name: " + fileName + ", mime type: " + mimeType);
    try {
      DSSDocument document = new StreamDocument(stream, fileName, getMimeType(mimeType));
      setDocument(document);
    } catch (Exception e) {
      logger.error(e.getMessage());
      throw new InvalidDataFileException(e);
    }
  }
}
