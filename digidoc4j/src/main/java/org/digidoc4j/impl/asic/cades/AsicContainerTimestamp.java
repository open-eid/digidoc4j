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

import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.tsp.TimestampIdentifierBuilder;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Timestamp;
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.TechnicalException;

import java.util.Date;
import java.util.Objects;
import java.util.Optional;

/**
 * An implementation of timestamp token that covers the contents of ASiC containers.
 */
public abstract class AsicContainerTimestamp implements Timestamp, TimestampAndManifestPair {

  private final CadesTimestamp cadesTimestamp;
  private final AsicArchiveManifest archiveManifest;

  private transient String uniqueId;
  private transient DigestAlgorithm digestAlgorithm;

  protected AsicContainerTimestamp(CadesTimestamp cadesTimestamp, AsicArchiveManifest archiveManifest) {
    this.cadesTimestamp = Objects.requireNonNull(cadesTimestamp);
    this.archiveManifest = archiveManifest;
  }

  @Override
  public String getUniqueId() {
    if (uniqueId == null) {
      uniqueId = calculateUniqueId();
    }

    return uniqueId;
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
    if (digestAlgorithm == null) {
      digestAlgorithm = extractDigestAlgorithm();
    }

    return digestAlgorithm;
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

  private String calculateUniqueId() {
    return new TimestampIdentifierBuilder(getEncodedTimestampForUniqueId())
            .setFilename(cadesTimestamp.getTimestampDocument().getName())
            .build()
            .asXmlId();
  }

  private byte[] getEncodedTimestampForUniqueId() {
    // The following method is used for calculating timestamp identifiers in eu.europa.esig.dss.spi.x509.tsp.TimestampToken.
    // NB: For some reason, this gives a different result than using the contents of the original DSSDocument of the timestamp token.
    try {
      return DSSASN1Utils.getDEREncoded(cadesTimestamp.getTimeStampToken());
    } catch (Exception e) {
      throw new TechnicalException("Failed to encode timestamp token", e);
    }
  }

  private DigestAlgorithm extractDigestAlgorithm() {
    return Optional
            .of(cadesTimestamp.getTimeStampToken())
            .map(TimeStampToken::getTimeStampInfo)
            .map(TimeStampTokenInfo::getMessageImprintAlgOID)
            .map(ASN1ObjectIdentifier::toString)
            .map(oid -> Optional
                    .ofNullable(DigestAlgorithm.findByOid(oid))
                    .orElseThrow(() -> new IllegalStateException("Unrecognizable digest algorithm with OID: " + oid))
            )
            .orElse(null);
  }

}
