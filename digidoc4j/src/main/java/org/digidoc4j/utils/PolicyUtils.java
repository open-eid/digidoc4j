package org.digidoc4j.utils;

import eu.europa.esig.dss.Policy;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.impl.asic.xades.validation.XadesSignatureValidator;

import static eu.europa.esig.dss.DigestAlgorithm.SHA256;

public final class PolicyUtils {

  /**
   * Prepare signature policy data for BDOC signature.
   *
   * @return Policy
   */
  public static Policy createBDocSignaturePolicy() {
    Policy signaturePolicy = new Policy();
    signaturePolicy.setId("urn:oid:" + XadesSignatureValidator.TM_POLICY);
    signaturePolicy.setDigestValue(Base64.decodeBase64("7pudpH4eXlguSZY2e/pNbKzGsq+fu//woYL1SZFws1A="));
    signaturePolicy.setQualifier("OIDAsURN");
    signaturePolicy.setDigestAlgorithm(SHA256);
    signaturePolicy.setSpuri("https://www.sk.ee/repository/bdoc-spec21.pdf");
    return signaturePolicy;
  }

  public static boolean areAllPolicyValuesDefined(Policy policy) {
    return StringUtils.isNotBlank(policy.getId())
            && policy.getDigestValue() != null
            && StringUtils.isNotBlank(policy.getQualifier())
            && policy.getDigestAlgorithm() != null
            && StringUtils.isNotBlank(policy.getSpuri());
  }
}
