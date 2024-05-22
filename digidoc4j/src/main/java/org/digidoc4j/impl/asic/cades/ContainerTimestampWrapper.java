/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.cades;

import java.util.Objects;

/**
 * An immutable wrapper that holds a CAdES timestamp and an optional ASiCArchiveManifest associated with it.
 */
public class ContainerTimestampWrapper implements TimestampAndManifestPair {

  private final CadesTimestamp cadesTimestamp;
  private final AsicArchiveManifest archiveManifest;

  /**
   * Creates a new instance by wrapping a CAdES timestamp.
   *
   * @param cadesTimestamp CAdES timestamp
   */
  public ContainerTimestampWrapper(CadesTimestamp cadesTimestamp) {
    this.cadesTimestamp = Objects.requireNonNull(cadesTimestamp);
    this.archiveManifest = null;
  }

  /**
   * Creates a new instance by wrapping a CAdES timestamp and an ASiCArchiveManifest.
   *
   * @param cadesTimestamp CAdES timestamp
   * @param archiveManifest ASiCArchiveManifest
   */
  public ContainerTimestampWrapper(CadesTimestamp cadesTimestamp, AsicArchiveManifest archiveManifest) {
    this.cadesTimestamp = Objects.requireNonNull(cadesTimestamp);
    this.archiveManifest = Objects.requireNonNull(archiveManifest);
  }

  /**
   * Creates a copy of the initial wrapper by wrapping the specified ASiCArchiveManifest, retaining the original
   * CAdES signature.
   *
   * @param archiveManifest ASiCArchiveManifest
   * @return new wrapper with the original CAdES timestamp and the specified ASiCArchiveManifest
   */
  public ContainerTimestampWrapper withArchiveManifest(AsicArchiveManifest archiveManifest) {
    return new ContainerTimestampWrapper(getCadesTimestamp(), archiveManifest);
  }

  @Override
  public CadesTimestamp getCadesTimestamp() {
    return cadesTimestamp;
  }

  @Override
  public AsicArchiveManifest getArchiveManifest() {
    return archiveManifest;
  }

}
