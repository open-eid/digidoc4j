/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.xades;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.xades.definition.XAdESPath;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.CertificateNotFoundException;
import org.digidoc4j.exceptions.TechnicalException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Objects;

public class TimestampSignatureComponent implements Serializable {

  private final static Logger logger = LoggerFactory.getLogger(TimestampSignatureComponent.class);

  private final XAdESSignature xAdESSignature;

  private transient TimeStampToken timeStampToken;
  private transient X509Cert timestampTokenCertificate;

  public TimestampSignatureComponent(XAdESSignature xAdESSignature) {
    this.xAdESSignature = Objects.requireNonNull(xAdESSignature, "XAdES signature cannot be null");
  }

  public X509Cert getTimeStampTokenCertificate() {
    if (timestampTokenCertificate != null) {
      return timestampTokenCertificate;
    }
    XAdESSignature origin = xAdESSignature;
    if (origin.getSignatureTimestamps() == null || origin.getSignatureTimestamps().isEmpty()) {
      throwTimestampNotFoundException(origin.getId());
    }
    TimestampToken timestampToken = origin.getSignatureTimestamps().get(0);

    CertificateToken issuerToken = getIssuerToken(timestampToken);
    if (issuerToken == null) {
      return throwTimestampNotFoundException(origin.getId());
    }
    X509Certificate certificate = issuerToken.getCertificate();
    timestampTokenCertificate = new X509Cert(certificate);
    return timestampTokenCertificate;
  }

  public Date getTimeStampCreationTime() {
    if (timeStampToken == null) {
      timeStampToken = findTimestampToken();
    }
    if (timeStampToken == null || timeStampToken.getTimeStampInfo() == null) {
      logger.warn("Timestamp token was not found");
      return null;
    }
    return timeStampToken.getTimeStampInfo().getGenTime();
  }

  private TimeStampToken findTimestampToken() {
    XAdESPath xAdESPaths = xAdESSignature.getXAdESPaths();
    logger.debug("Finding timestamp token");
    NodeList timestampNodes = DomUtils.getNodeList(xAdESSignature.getSignatureElement(), xAdESPaths.getSignatureTimestampPath());
    if (timestampNodes.getLength() == 0) {
      logger.warn("Signature timestamp element was not found");
      return null;
    }
    if (timestampNodes.getLength() > 1) {
      logger.warn("Signature contains more than one timestamp: {}. Using only the first one", timestampNodes.getLength());
    }
    Node timestampNode = timestampNodes.item(0);

    Element timestampTokenNode = DomUtils.getElement(timestampNode, xAdESPaths.getCurrentEncapsulatedTimestamp());
    if (timestampTokenNode == null) {
      logger.warn("The timestamp cannot be extracted from the signature");
      return null;
    }
    String base64EncodedTimestamp = timestampTokenNode.getTextContent();
    return createTimeStampToken(base64EncodedTimestamp);
  }

  private TimeStampToken createTimeStampToken(final String base64EncodedTimestamp) throws DSSException {
    logger.debug("Creating timestamp token");
    try {
      byte[] tokenBytes = Base64.decodeBase64(base64EncodedTimestamp);
      CMSSignedData signedData = new CMSSignedData(tokenBytes);
      return new TimeStampToken(signedData);
    } catch (Exception e) {
      logger.error("Error parsing timestamp token: {}", e.getMessage());
      throw new TechnicalException("Error parsing timestamp token", e);
    }
  }

  private X509Cert throwTimestampNotFoundException(String sigId) {
    logger.error("TimeStamp certificate not found, Signature id: {}", sigId);
    throw new CertificateNotFoundException("TimeStamp certificate not found", sigId);
  }

  private CertificateToken getIssuerToken(TimestampToken timestampToken) {
    for (CertificateToken certificateToken : timestampToken.getCertificates()) {
      if (timestampToken.isSignedBy(certificateToken)) {
        return certificateToken;
      }
    }
    return null;
  }
}
