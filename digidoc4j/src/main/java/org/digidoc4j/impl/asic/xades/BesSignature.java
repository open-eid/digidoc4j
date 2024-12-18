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

import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.SignatureProductionPlace;
import eu.europa.esig.dss.validation.SignerRole;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.xades.definition.XAdESPath;
import org.apache.commons.codec.binary.Base64;
import org.apache.xml.security.signature.Reference;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.X509Cert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * BES signature
 */
public class BesSignature extends DssXadesSignature {

  private final static Logger logger = LoggerFactory.getLogger(BesSignature.class);
  private final static String XPATH_KEY_INFO_X509_CERTIFICATE = "./ds:KeyInfo/ds:X509Data/ds:X509Certificate";
  private SignatureProductionPlace signerLocation;
  private transient Element signatureElement;
  private XAdESPath xAdESPaths; // This variable contains the XAdESPaths adapted to the signature schema.
  private X509Cert signingCertificate;
  private Set<CertificateToken> encapsulatedCertificates;

  /**
   * @param xadesReportGenerator XADES validation report generator
   */
  public BesSignature(XadesValidationReportGenerator xadesReportGenerator) {
    super(xadesReportGenerator);
    this.xAdESPaths = getDssSignature().getXAdESPaths();
    logger.debug("Using xpath query holder: " + xAdESPaths.getClass());
  }

  @Override
  public String getId() {
    return getDssSignature().getDAIdentifier();
  }

  @Override
  public String getUniqueId() {
    return getDssSignature().getId();
  }

  @Override
  public String getSignatureMethod() {
    String xmlId = null;
    SignatureAlgorithm algorithm = this.getDssSignature().getSignatureAlgorithm();
    if (algorithm != null) {
      xmlId = algorithm.getUri();
    }
    return xmlId == null ? "" : xmlId;
  }

  @Override
  public Date getSigningTime() {
    return getDssSignature().getSigningTime();
  }

  @Override
  public String getCity() {
    return getSignerLocation() == null ? "" : getSignerLocation().getCity();
  }

  @Override
  public String getStateOrProvince() {
    return getSignerLocation() == null ? "" : getSignerLocation().getStateOrProvince();
  }

  @Override
  public String getPostalCode() {
    return getSignerLocation() == null ? "" : getSignerLocation().getPostalCode();
  }

  @Override
  public String getCountryName() {
    return getSignerLocation() == null ? "" : getSignerLocation().getCountryName();
  }

  @Override
  public List<String> getSignerRoles() {
    return getDssSignature()
            .getClaimedSignerRoles()
            .stream()
            .map(SignerRole::getRole)
            .collect(Collectors.toList());
  }

  @Override
  public X509Cert getSigningCertificate() {
    if (signingCertificate != null) {
      return signingCertificate;
    }
    CertificateToken keyInfoCertificate = findKeyInfoCertificate();
    if (keyInfoCertificate == null) {
      logger.warn("Signing certificate not found");
      return null;
    }
    X509Certificate certificate = keyInfoCertificate.getCertificate();
    signingCertificate = new X509Cert(certificate);
    return signingCertificate;
  }

  @Override
  public SignatureProfile getProfile() {
    return SignatureProfile.B_BES;
  }

  @Override
  public byte[] getSignatureValue() {
    logger.debug("Getting signature value");
    return getDssSignature().getSignatureValue();
  }

  /**
   * B_BES signature does not contain OCSP response
   *
   * @return null
   */
  @Override
  public byte[] getOCSPNonce() {
    logger.info("B_BES signature does not contain OCSP response");
    return null;
  }

  /**
   * B_BES signature does not contain OCSP response time or Timestamp to provide trusted signing time.
   *
   * @return null
   */
  @Override
  public Date getTrustedSigningTime() {
    logger.info("B_BES signature does not contain OCSP response time or Timestamp to provide trusted signing time");
    return null;
  }

  /**
   * B_BES signature does not contain OCSP response
   *
   * @return null
   */
  @Override
  public Date getOCSPResponseCreationTime() {
    logger.info("The signature does not contain OCSP response");
    return null;
  }

  /**
   * B_BES signature does not contain OCSP response
   *
   * @return null
   */
  @Override
  public X509Cert getOCSPCertificate() {
    logger.info("The signature does not contain OCSP response");
    return null;
  }

  /**
   * B_BES signature does not contain OCSP response
   *
   * @return null
   */
  @Override
  public List<BasicOCSPResp> getOcspResponses() {
    logger.info("The signature does not contain OCSP response");
    return Collections.emptyList();
  }

  /**
   * B_BES signature does not contain Timestamp
   *
   * @return null
   */
  @Override
  public Date getTimeStampCreationTime() {
    logger.info("The signature does not contain Timestamp");
    return null;
  }

  /**
   * B_BES signature does not contain Timestamp
   *
   * @return null
   */
  @Override
  public X509Cert getTimeStampTokenCertificate() {
    logger.info("The signature does not contain Timestamp");
    return null;
  }

  @Override
  public List<Reference> getReferences() {
    return getDssSignature().getReferences();
  }

  protected Element getSignatureElement() {
    if (signatureElement == null) {
      signatureElement = getDssSignature().getSignatureElement();
    }
    return signatureElement;
  }

  protected Set<CertificateToken> getEncapsulatedCertificates() {
    if (encapsulatedCertificates == null) {
      logger.debug("Finding encapsulated certificates");
      encapsulatedCertificates = findCertificates(xAdESPaths.getEncapsulatedCertificateValuesPath());
      logger.debug("Found " + encapsulatedCertificates.size() + " encapsulated certificates");
    }
    return encapsulatedCertificates;
  }

  private CertificateToken findKeyInfoCertificate() {
    logger.debug("Finding key info certificate");
    Set<CertificateToken> keyInfoCertificates = findCertificates(XPATH_KEY_INFO_X509_CERTIFICATE);
    if (keyInfoCertificates.isEmpty()) {
      logger.debug("Signing certificate not found");
      return null;
    }
    if (keyInfoCertificates.size() > 1) {
      logger.warn("Found more than one signing certificate in the key info block: " + keyInfoCertificates.size());
    }
    return keyInfoCertificates.iterator().next();
  }

  protected Set<CertificateToken> findCertificates(String xPath) {
    Set<CertificateToken> certificates = new HashSet<>();
    NodeList nodeList = DomUtils.getNodeList(getSignatureElement(), xPath);
    for (int i = 0; i < nodeList.getLength(); i++) {
      Element certificateElement = (Element) nodeList.item(i);
      CertificateToken certToken = createCertificateToken(certificateElement);
      if (!certificates.contains(certToken)) {
        certificates.add(certToken);
      }
    }
    return certificates;
  }

  private CertificateToken createCertificateToken(Element certificateElement) {
    byte[] derEncoded = Base64.decodeBase64(certificateElement.getTextContent());
    return DSSUtils.loadCertificate(derEncoded);
  }

  private SignatureProductionPlace getSignerLocation() {
    if (signerLocation == null) {
      logger.debug("Getting signature production place");
      signerLocation = getDssSignature().getSignatureProductionPlace();
    }
    return signerLocation;
  }
}
