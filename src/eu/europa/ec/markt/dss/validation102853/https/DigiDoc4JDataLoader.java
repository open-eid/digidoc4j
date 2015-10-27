/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package eu.europa.ec.markt.dss.validation102853.https;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSCannotFetchDataException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URL;

/**
 *
 */
public class DigiDoc4JDataLoader extends CommonsDataLoader {
  private static final Logger logger = LoggerFactory.getLogger(DigiDoc4JDataLoader.class);

  @Override
  public byte[] get(String urlString) throws DSSCannotFetchDataException {
    if (urlString.toLowerCase().startsWith("jar")) {
      try {
        return DSSUtils.toByteArray(new URL(urlString).openStream());
      } catch (IOException e) {
        logger.warn(e.toString(), e);
      }
      return null;
    }

    return super.get(urlString);
  }
}
