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

import org.bouncycastle.tsp.TimeStampToken;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Timestamp;
import org.digidoc4j.X509Cert;

import java.util.Date;
import java.util.Objects;

/**
 * An implementation of timestamp token that covers the contents of ASiC containers.
 */
public abstract class AsicContainerTimestamp implements Timestamp, TimestampAndManifestPair {

  private final CadesTimestamp cadesTimestamp;
  private final AsicArchiveManifest archiveManifest;

  protected AsicContainerTimestamp(CadesTimestamp cadesTimestamp, AsicArchiveManifest archiveManifest) {
    this.cadesTimestamp = Objects.requireNonNull(cadesTimestamp);
    this.archiveManifest = archiveManifest;
  }

  @Override
  public String getUniqueId() {
    return ""; // TODO (DD4J-1044): implement
  }

  @Override
  public X509Cert getCertificate() {
    return cadesTimestamp.getCertificate();
  }

  @Override
  public Date getCreationTime() {
    return cadesTimestamp.getCreationTime();
  }

  @Override
  public DigestAlgorithm getDigestAlgorithm() {
    return null; // TODO (DD4J-1044): implement
  }

  @Override
  public TimeStampToken getTimeStampToken() {
    return cadesTimestamp.getTimeStampToken();
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
