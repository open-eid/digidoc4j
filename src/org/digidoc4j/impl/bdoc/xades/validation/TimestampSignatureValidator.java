/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.xades.validation;

import java.util.Date;
import java.util.List;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.digidoc4j.Configuration;
import org.digidoc4j.exceptions.TimestampAfterOCSPResponseTimeException;
import org.digidoc4j.exceptions.TimestampAndOcspResponseTimeDeltaTooLargeException;
import org.digidoc4j.impl.bdoc.xades.XadesSignature;
import org.digidoc4j.impl.bdoc.xades.XadesValidationReportGenerator;
import org.digidoc4j.utils.DateUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

public class TimestampSignatureValidator extends TimemarkSignatureValidator {

  private final static Logger logger = LoggerFactory.getLogger(TimemarkSignatureValidator.class);
  private XAdESSignature xAdESSignature;
  private Configuration configuration;

  public TimestampSignatureValidator(XadesValidationReportGenerator reportGenerator, XadesSignature signature, Configuration configuration) {
    super(reportGenerator, signature);
    this.configuration = configuration;
    xAdESSignature = signature.getDssSignature();
  }

  @Override
  protected void populateValidationErrors() {
    super.populateValidationErrors();
    addSigningTimeErrors();
  }

  private void addSigningTimeErrors() {
    List<TimestampToken> signatureTimestamps = xAdESSignature.getSignatureTimestamps();
    if (signatureTimestamps == null || signatureTimestamps.isEmpty()) {
      return;
    }
    Date timestamp = signatureTimestamps.get(0).getGenerationTime();
    if (timestamp == null) {
      return;
    }
    List<BasicOCSPResp> ocspResponses = xAdESSignature.getOCSPSource().getContainedOCSPResponses();
    if (ocspResponses == null || ocspResponses.isEmpty()) {
      return;
    }
    Date ocspTime = ocspResponses.get(0).getProducedAt();
    if (ocspTime == null) {
      return;
    }
    if (!DateUtils.isInRangeMinutes(timestamp, ocspTime, configuration.getRevocationAndTimestampDeltaInMinutes())) {
      logger.error("The difference between the OCSP response production time and the signature time stamp is too large");
      addValidationError(new TimestampAndOcspResponseTimeDeltaTooLargeException());
    }
    if (ocspTime.before(timestamp)) {
      logger.error("OCSP response production time is before timestamp time");
      addValidationError(new TimestampAfterOCSPResponseTimeException());
    }
  }
}
