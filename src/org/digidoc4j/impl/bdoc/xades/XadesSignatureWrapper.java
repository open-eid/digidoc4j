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

import static org.digidoc4j.SignatureProfile.B_BES;
import static org.digidoc4j.SignatureProfile.LT;
import static org.digidoc4j.SignatureProfile.LTA;
import static org.digidoc4j.SignatureProfile.LT_TM;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.impl.bdoc.XadesSignatureValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.validation.SignatureProductionPlace;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.x509.SignaturePolicy;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

public class XadesSignatureWrapper implements Serializable {

  private final static Logger logger = LoggerFactory.getLogger(XadesSignatureWrapper.class);
  private XAdESSignature origin;
  private static final Map<SignatureLevel, SignatureProfile> signatureProfileMap =
      new HashMap<SignatureLevel, SignatureProfile>() {
        {
          put(SignatureLevel.XAdES_BASELINE_B, B_BES);
          put(SignatureLevel.XAdES_BASELINE_T, LT);
          put(SignatureLevel.XAdES_BASELINE_LT, LT);
          put(SignatureLevel.XAdES_BASELINE_LTA, LTA);
          put(SignatureLevel.XAdES_A, LTA);
        }
      };

  public XadesSignatureWrapper(XAdESSignature xAdESSignature) {
    this.origin = xAdESSignature;
  }

  public SignatureProfile getProfile() {
    if (isTimeMarkSignature()) {
      return LT_TM;
    }
    SignatureLevel dataFoundUpToLevel = origin.getDataFoundUpToLevel();
    logger.debug("getting profile for: " + dataFoundUpToLevel);
    return signatureProfileMap.get(dataFoundUpToLevel);
  }

  public Date getTrustedSigningTime() {
    if (getProfile() == B_BES) {
      return null;
    }
    if (getProfile() == LT_TM) {
      return getOCSPResponseCreationTime();
    }
    return getTimestampOrOcspResponseTime();
  }

  public Date getOCSPResponseCreationTime() {
    List<BasicOCSPResp> ocspResponses = origin.getOCSPSource().getContainedOCSPResponses();
    if (ocspResponses.isEmpty()) {
      logger.warn("Signature is missing OCSP response");
      return null;
    }
    Date date = ocspResponses.get(0).getProducedAt();
    logger.debug("Produced at date: " + date);
    return date;
  }

  public Date getTimeStampCreationTime() {
    List<TimestampToken> signatureTimestamps = origin.getSignatureTimestamps();
    if (signatureTimestamps.size() == 0) {
      return null;
    }
    Date date = signatureTimestamps.get(0).getGenerationTime();
    logger.debug("Time stamp creation time: " + date);
    return date;
  }

  private Date getTimestampOrOcspResponseTime() {
    Date timeStampCreationTime = getTimeStampCreationTime();
    if (timeStampCreationTime != null) {
      return timeStampCreationTime;
    }
    Date ocspResponseTime = getOCSPResponseCreationTime();
    if (ocspResponseTime != null) {
      return ocspResponseTime;
    }
    return null;
  }

  private boolean isTimeMarkSignature() {
    SignaturePolicy policyId = origin.getPolicyId();
    if (policyId == null) {
      return false;
    }
    return StringUtils.equals(XadesSignatureValidator.TM_POLICY, policyId.getIdentifier());
  }

  public SignatureProductionPlace getSignatureProductionPlace() {
    return origin.getSignatureProductionPlace();
  }

  public XAdESSignature getOrigin() {
    return origin;
  }
}
