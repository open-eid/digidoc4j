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

import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.impl.asic.xades.validation.XadesSignatureValidator;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.x509.SignaturePolicy;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

/**
 * XadesSignatureParser
 */
public class XadesSignatureParser {

  private final static Logger logger = LoggerFactory.getLogger(XadesSignatureParser.class);

  /**
   * Method for converting Xades signature into Signature object.
   * @param xadesReportGenerator
   * @return
   */
  public XadesSignature parse(XadesValidationReportGenerator xadesReportGenerator) {
    logger.debug("Parsing XAdES signature");
    XAdESSignature xAdESSignature = xadesReportGenerator.openDssSignature();
    SignatureLevel signatureLevel = xAdESSignature.getDataFoundUpToLevel();
    logger.debug("Signature profile is " + signatureLevel);
    if (isEpesSignature(signatureLevel, xAdESSignature)) {
      logger.debug("Using EPES signature");
      return new EpesSignature(xadesReportGenerator);
    }
    if (isBesSignature(signatureLevel)) {
      logger.debug("Using BES signature");
      return new BesSignature(xadesReportGenerator);
    }
    if (isTimeMarkSignature(xAdESSignature)) {
      logger.debug("Using Time Mark signature");
      return new TimemarkSignature(xadesReportGenerator);
    }
    if (isTimestampArchiveSignature(signatureLevel)) {
      logger.debug("Using Time Stamp Archive signature");
      return new TimestampArchiveSignature(xadesReportGenerator);
    }
    logger.debug("Using Timestamp signature");
    return new TimestampSignature(xadesReportGenerator);
  }

  private boolean isEpesSignature(SignatureLevel signatureLevel, XAdESSignature xAdESSignature) {
    return isBesSignature(signatureLevel) && containsPolicyId(xAdESSignature);
  }

  private boolean isBesSignature(SignatureLevel signatureLevel) {
    return signatureLevel == SignatureLevel.XAdES_BASELINE_B;
  }

  private boolean isTimestampArchiveSignature(SignatureLevel signatureLevel) {
    return signatureLevel == SignatureLevel.XAdES_BASELINE_LTA || signatureLevel == SignatureLevel.XAdES_A;
  }

  private boolean containsPolicyId(XAdESSignature xAdESSignature) {
    xAdESSignature.checkSignaturePolicy(new SignaturePolicyProvider());

    SignaturePolicy policyId = xAdESSignature.getPolicyId();
    if (policyId == null) {
      return false;
    }
    return StringUtils.isNotBlank(policyId.getIdentifier());
  }

  private boolean isTimeMarkSignature(XAdESSignature xAdESSignature) {
    if (!containsPolicyId(xAdESSignature)) {
      return false;
    }
    SignaturePolicy policyId = xAdESSignature.getPolicyId();
    String identifier = Helper.getIdentifier(policyId.getIdentifier());
    return StringUtils.equals(XadesSignatureValidator.TM_POLICY, identifier);
  }
}
