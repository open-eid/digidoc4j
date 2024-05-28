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

/**
 * An interface representing the set of timestamp parameters.
 */
public interface TimestampParameters {

  /**
   * Returns reference digest algorithm.
   * Reference digest algorithm is used when a timestamp will cover a collection of references (e.g. an
   * {@code ASiCArchiveManifest.xml} file), and each reference needs to incorporate the digest of the entity it
   * references.
   *
   * @return timestamp reference digest algorithm
   */
  DigestAlgorithm getReferenceDigestAlgorithm();

  /**
   * Returns timestamp digest algorithm.
   *
   * @return timestamp digest algorithm
   */
  DigestAlgorithm getTimestampDigestAlgorithm();

  /**
   * Returns TSP (Time-Stamp Protocol) source URL string.
   *
   * @return TSP source URL string
   */
  String getTspSource();

}
