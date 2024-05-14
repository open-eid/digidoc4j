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

import org.bouncycastle.tsp.TimeStampToken;

import java.io.Serializable;
import java.util.Date;

/**
 * An interface for handling timestamp tokens and their parameters.
 */
public interface Timestamp extends Serializable {

  /**
   * Returns the identifier that uniquely identifies this timestamp.
   *
   * @return unique identifier
   */
  String getUniqueId();

  /**
   * Returns the signing certificate of this timestamp, if available.
   *
   * @return timestamp certificate or {@code null}
   */
  X509Cert getCertificate();

  /**
   * Returns the creation time of this timestamp.
   *
   * @return creation time
   */
  Date getCreationTime();

  /**
   * Returns the digest algorithm of this timestamp.
   *
   * @return digest algorithm
   */
  DigestAlgorithm getDigestAlgorithm();

  /**
   * Returns the raw {@code TimeStampToken} that this timestamp represents.
   *
   * @return raw timestamp token
   */
  TimeStampToken getTimeStampToken();

}
