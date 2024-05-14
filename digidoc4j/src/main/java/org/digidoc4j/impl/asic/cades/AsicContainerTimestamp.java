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

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import org.apache.commons.collections4.CollectionUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Timestamp;
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.utils.CertificateUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Date;
import java.util.Objects;

/**
 * An implementation of timestamp token that covers the contents of ASiC containers.
 */
public abstract class AsicContainerTimestamp implements Timestamp {

  private static final Logger log = LoggerFactory.getLogger(AsicContainerTimestamp.class);

  private final DSSDocument timestampDocument;
  private final AsicArchiveManifest archiveManifest;

  private transient TimeStampToken timeStampToken;
  private transient X509Cert certificate;

  protected AsicContainerTimestamp(DSSDocument timestampDocument, AsicArchiveManifest archiveManifest) {
    this.timestampDocument = Objects.requireNonNull(timestampDocument);
    this.archiveManifest = archiveManifest;
  }

  @Override
  public String getUniqueId() {
    return ""; // TODO (DD4J-1044): implement
  }

  @Override
  public X509Cert getCertificate() {
    if (certificate == null) {
      certificate = parseTimestampCertificate(getTimeStampToken());
    }

    return certificate;
  }

  @Override
  public Date getCreationTime() {
    return getTimeStampToken().getTimeStampInfo().getGenTime();
  }

  @Override
  public DigestAlgorithm getDigestAlgorithm() {
    return null; // TODO (DD4J-1044): implement
  }

  @Override
  public TimeStampToken getTimeStampToken() {
    if (timeStampToken == null) {
      timeStampToken = parseTimeStampToken(timestampDocument);
    }

    return timeStampToken;
  }

  public DSSDocument getTimestampDocument() {
    return timestampDocument;
  }

  public AsicArchiveManifest getTimestampManifest() {
    return archiveManifest;
  }

  private static TimeStampToken parseTimeStampToken(DSSDocument timestampDocument) {
    log.debug("Parsing timestamp document: {}", timestampDocument);
    try {
      CMSSignedData cmsSignedData = DSSUtils.toCMSSignedData(timestampDocument);
      return new TimeStampToken(cmsSignedData);
    } catch (Exception e) {
      throw new TechnicalException("Failed to parse TimeStampToken", e);
    }
  }

  private static X509Cert parseTimestampCertificate(TimeStampToken timeStampToken) {
    log.debug("Parsing timestamp token signer certificate from TimeStampToken");
    Collection<X509CertificateHolder> matchingCertificates = getSignerCertificateMatches(timeStampToken);
    if (CollectionUtils.isEmpty(matchingCertificates)) {
      log.warn("Unable to extract timestamp signer certificate");
      return null;
    } else if (matchingCertificates.size() > 1) {
      log.warn("Found more than one candidate for timestamp signer certificate; returning the first one");
    }
    return CertificateUtils.toX509Cert(matchingCertificates.iterator().next());
  }

  @SuppressWarnings("unchecked")
  private static Collection<X509CertificateHolder> getSignerCertificateMatches(TimeStampToken timeStampToken) {
    try {
      return timeStampToken.getCertificates().getMatches(timeStampToken.getSID());
    } catch (Exception e) {
      throw new TechnicalException("Failed to extract signer certificate from timestamp token", e);
    }
  }

}
