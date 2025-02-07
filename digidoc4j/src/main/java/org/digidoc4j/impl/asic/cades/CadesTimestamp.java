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
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.utils.CertificateUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.Collection;
import java.util.Date;
import java.util.Objects;

/**
 * An entity for handling instances of CAdES timestamp tokens.
 */
public class CadesTimestamp implements Serializable {

  private static final Logger log = LoggerFactory.getLogger(CadesTimestamp.class);

  private final DSSDocument timestampDocument;

  private transient TimeStampToken timeStampToken;
  private transient X509Cert certificate;

  /**
   * Creates an instance of CadesTimestamp by wrapping the specified DSSDocument.
   * NB: the constructor does not parse the timestamp token! The timestamp token is parsed lazily as needed.
   *
   * @param timestampDocument DSSDocument of a CAdES timestamp token
   */
  public CadesTimestamp(DSSDocument timestampDocument) {
    this.timestampDocument = Objects.requireNonNull(timestampDocument);
  }

  /**
   * Returns the DSSDocument of the timestamp token.
   *
   * @return DSSDocument of the timestamp token
   */
  public DSSDocument getTimestampDocument() {
    return timestampDocument;
  }

  /**
   * Returns the signing certificate of this timestamp token, if available.
   * Calling this method triggers the parsing process of the timestamp token if it has not been parsed already.
   *
   * @return timestamp token signing certificate or {@code null}
   */
  public X509Cert getCertificate() {
    if (certificate == null) {
      certificate = parseTimestampCertificate(getTimeStampToken());
    }

    return certificate;
  }

  /**
   * Returns the creation time of this timestamp token.
   * Calling this method triggers the parsing process of the timestamp token if it has not been parsed already.
   *
   * @return timestamp token creation time
   */
  public Date getCreationTime() {
    return getTimeStampToken().getTimeStampInfo().getGenTime();
  }

  /**
   * Returns the raw {@code TimeStampToken} that this timestamp represents.
   * Calling this method triggers the parsing process of the timestamp token if it has not been parsed already.
   *
   * @return raw timestamp token
   */
  public TimeStampToken getTimeStampToken() {
    if (timeStampToken == null) {
      timeStampToken = parseTimeStampToken(timestampDocument);
    }

    return timeStampToken;
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
