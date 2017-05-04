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

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;

import javax.annotation.processing.SupportedSourceVersion;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.digidoc4j.Configuration;
import org.digidoc4j.exceptions.TimestampAfterOCSPResponseTimeException;
import org.digidoc4j.exceptions.TimestampAndOcspResponseTimeDeltaTooLargeException;
import org.digidoc4j.impl.bdoc.xades.XadesSignature;
import org.digidoc4j.utils.DateUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.xml.internal.bind.v2.TODO;

import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

public class TimestampSignatureValidator extends TimemarkSignatureValidator {

  private final static Logger logger = LoggerFactory.getLogger(TimemarkSignatureValidator.class);
  private XadesSignature signature;
  private Configuration configuration;

  public TimestampSignatureValidator(XadesSignature signature, Configuration configuration) {
    super(signature);
    this.signature = signature;
    this.configuration = configuration;
  }

  @Override
  protected void populateValidationErrors() {
    super.populateValidationErrors();
    addSigningTimeErrors();
  }

  private void addSigningTimeErrors() {
    XAdESSignature xAdESSignature = signature.getDssSignature();
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

    //TODO: kontroll, kas java 1.8 võib kasutada ning millist tuleks süsteemiparameetrina kasutada, ConfigurationValue või JDigiDocConfigurationValue?
    LocalDateTime localDateTime = ocspTime.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
    localDateTime = localDateTime.plusSeconds(configuration.getAllowedTimestampDelayAfterOCSPResponse());
    Date timestampDelayAfterOCSP = Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());

    if (timestampDelayAfterOCSP.before(timestamp)) {
      logger.error("OCSP response production time is before timestamp time");
      addValidationError(new TimestampAfterOCSPResponseTimeException());
    }

  }
}
