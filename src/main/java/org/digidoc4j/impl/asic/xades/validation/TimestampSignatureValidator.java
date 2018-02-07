/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.asic.xades.validation;

import java.util.Date;
import java.util.List;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.digidoc4j.Configuration;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.TimestampAndOcspResponseTimeDeltaTooLargeException;
import org.digidoc4j.impl.asic.xades.XadesSignature;
import org.digidoc4j.utils.DateUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

public class TimestampSignatureValidator extends TimemarkSignatureValidator {

  private final Logger log = LoggerFactory.getLogger(TimestampSignatureValidator.class);
  private Configuration configuration;

  public TimestampSignatureValidator(XadesSignature signature, Configuration configuration) {
    super(signature);
    this.configuration = configuration;
  }

  @Override
  protected void populateValidationErrors() {
    super.populateValidationErrors();
    this.addSigningTimeErrors();
  }

  private void addSigningTimeErrors() {
    XAdESSignature signature = this.getDssSignature();
    List<TimestampToken> signatureTimestamps = signature.getSignatureTimestamps();
    if (signatureTimestamps == null || signatureTimestamps.isEmpty()) {
      return;
    }
    Date timestamp = signatureTimestamps.get(0).getGenerationTime();
    if (timestamp == null) {
      return;
    }
    List<BasicOCSPResp> ocspResponses = signature.getOCSPSource().getContainedOCSPResponses();
    if (ocspResponses == null || ocspResponses.isEmpty()) {
      return;
    }
    Date ocspTime = ocspResponses.get(0).getProducedAt();
    if (ocspTime == null) {
      return;
    }
    int deltaLimit = this.configuration.getRevocationAndTimestampDeltaInMinutes();
    long differenceInMinutes = DateUtils.differenceInMinutes(timestamp, ocspTime);
    this.log.debug("Difference in minutes: <{}>", differenceInMinutes);
    if (!DateUtils.isInRangeMinutes(timestamp, ocspTime, deltaLimit)) {
      this.log.error("The difference between the OCSP response production time and the signature timestamp is too large <{} minutes>", differenceInMinutes);
      this.addValidationError(new TimestampAndOcspResponseTimeDeltaTooLargeException());
    } else if (this.configuration.getAllowedTimestampAndOCSPResponseDeltaInMinutes() < differenceInMinutes && differenceInMinutes < deltaLimit) {
      this.log.warn("The difference (in minutes) between the OCSP response production time and the signature timestamp is in allowable range (<{}>, allowed maximum <{}>)", differenceInMinutes, deltaLimit);
      this.addValidationWarning(new DigiDoc4JException("The difference between the OCSP response time and the signature timestamp is in allowable range"));
    }
  }

}
