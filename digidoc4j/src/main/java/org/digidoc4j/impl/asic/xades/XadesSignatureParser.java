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

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.validation.SignaturePolicy;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.xades.definition.XAdESPath;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.impl.asic.TmSignaturePolicyType;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.NodeList;

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
    assertNoExcessEncapsulatedTimeStamps(xAdESSignature);
    logger.debug("Signature profile is " + signatureLevel);
    if (isEpesSignature(signatureLevel, xAdESSignature)) {
      logger.debug("Using EPES signature (B_EPES)");
      return new EpesSignature(xadesReportGenerator);
    }
    if (isBesSignature(signatureLevel)) {
      logger.debug("Using BES signature (B_BES)");
      return new BesSignature(xadesReportGenerator);
    }
    if (isTimeMarkSignature(xAdESSignature)) {
      logger.debug("Using Time Mark signature (LT_TM)");
      return new TimemarkSignature(xadesReportGenerator);
    }
    if (isTimestampArchiveSignature(signatureLevel)) {
      logger.debug("Using Signature with Long Term Data and Archive timestamp (LTA)");
      return new LongTermArchiveSignature(xadesReportGenerator);
    }
    if (isTimestampSignature(signatureLevel)) {
      logger.debug("Using Signature with a timestamp (T)");
      return new TimestampSignature(xadesReportGenerator);
    }
    logger.debug("Using Signature with Long Term Data (LT)");
    return new LongTermSignature(xadesReportGenerator);
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

  private boolean isTimestampSignature(SignatureLevel signatureLevel) {
    return signatureLevel == SignatureLevel.XAdES_BASELINE_T;
  }

  private boolean containsPolicyId(XAdESSignature xAdESSignature) {
    SignaturePolicy policyId = xAdESSignature.getSignaturePolicy();
    if (policyId == null) {
      return false;
    }
    return StringUtils.isNotBlank(policyId.getIdentifier());
  }

  private boolean isTimeMarkSignature(XAdESSignature xAdESSignature) {
    if (!containsPolicyId(xAdESSignature)) {
      return false;
    }
    SignaturePolicy policyId = xAdESSignature.getSignaturePolicy();
    String identifier = Helper.getIdentifier(policyId.getIdentifier());
    return StringUtils.equals(TmSignaturePolicyType.BDOC_2_1_0.getOid(), identifier);
  }

  /*
   * This is a temporary solution that mimics the behaviour of DSS 5.7 where
   * eu.europa.esig.dss.model.DSSException: More than one result for XPath: ./xades132:EncapsulatedTimeStamp
   * is thrown if more than one EncapsulatedTimeStamp elements are encountered in a single SignatureTimeStamp
   * element when parsing a signature.
   *
   * TODO (DD4J-782): remove this solution after it has been verified to be sufficiently handled in DSS.
   */
  private static void assertNoExcessEncapsulatedTimeStamps(final XAdESSignature xadesSignature) {
    final XAdESPath xadesPaths = xadesSignature.getXAdESPaths();

    final NodeList signatureTimeStamps = DomUtils.getNodeList(xadesSignature.getSignatureElement(), xadesPaths.getSignatureTimestampPath());
    if (signatureTimeStamps == null || signatureTimeStamps.getLength() < 1) {
      return;
    }

    for (int i = 0; i < signatureTimeStamps.getLength(); ++i) {
      DomUtils.getNode(signatureTimeStamps.item(i), xadesPaths.getCurrentEncapsulatedTimestamp());
    }
  }
}
