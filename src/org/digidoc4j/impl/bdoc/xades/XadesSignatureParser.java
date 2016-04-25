/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.xades;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.x509.SignaturePolicy;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

public class XadesSignatureParser {

  private final static Logger logger = LoggerFactory.getLogger(XadesSignatureParser.class);

  public XadesSignature parse(XadesValidationReportGenerator xadesReportGenerator) {
    logger.debug("Parsing XAdES signature");
    XAdESSignature xAdESSignature = xadesReportGenerator.openDssSignature();
    SignatureLevel signatureLevel = xAdESSignature.getDataFoundUpToLevel();
    logger.debug("Signature profile is " + signatureLevel);
    if(isBesSignature(signatureLevel)) {
      return new BesSignature(xadesReportGenerator);
    }
    if(isTimeMarkSignature(xAdESSignature)) {
      return new TimemarkSignature(xadesReportGenerator);
    }
    if (isTimestampArchiveSignature(signatureLevel)) {
      return new TimestampArchiveSignature(xadesReportGenerator);
    }
    return new TimestampSignature(xadesReportGenerator);
  }

  private boolean isBesSignature(SignatureLevel signatureLevel) {
    return signatureLevel == SignatureLevel.XAdES_BASELINE_B;
  }

  private boolean isTimestampArchiveSignature(SignatureLevel signatureLevel) {
    return signatureLevel == SignatureLevel.XAdES_BASELINE_LTA || signatureLevel == SignatureLevel.XAdES_A;
  }

  private boolean isTimeMarkSignature(XAdESSignature xAdESSignature) {
    SignaturePolicy policyId = xAdESSignature.getPolicyId();
    if (policyId == null) {
      return false;
    }
    return StringUtils.equals(XadesSignatureValidator.TM_POLICY, policyId.getIdentifier());
  }
}
