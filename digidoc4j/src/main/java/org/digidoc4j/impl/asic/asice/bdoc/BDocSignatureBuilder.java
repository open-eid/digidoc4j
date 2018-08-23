package org.digidoc4j.impl.asic.asice.bdoc;

import static eu.europa.esig.dss.DigestAlgorithm.SHA256;
import static org.apache.commons.codec.binary.Base64.decodeBase64;

import org.digidoc4j.impl.asic.asice.AsicESignatureBuilder;
import org.digidoc4j.impl.asic.xades.validation.XadesSignatureValidator;

import eu.europa.esig.dss.Policy;

/**
 * Created by Andrei on 29.11.2017.
 */
public class BDocSignatureBuilder extends AsicESignatureBuilder {

  /**
   * Prepare signature policy data for BDOC signature.
   *
   * @return Policy
   */
  public static Policy createBDocSignaturePolicy() {
    if (policyDefinedByUser != null && isDefinedAllPolicyValues()) {
      return policyDefinedByUser;
    }
    Policy signaturePolicy = new Policy();
    signaturePolicy.setId("urn:oid:" + XadesSignatureValidator.TM_POLICY);
    signaturePolicy.setDigestValue(decodeBase64("7pudpH4eXlguSZY2e/pNbKzGsq+fu//woYL1SZFws1A="));
    signaturePolicy.setQualifier("OIDAsURN");
    signaturePolicy.setDigestAlgorithm(SHA256);
    signaturePolicy.setSpuri("https://www.sk.ee/repository/bdoc-spec21.pdf");
    return signaturePolicy;
  }

  @Override
  protected void setSignaturePolicy() {
    if (isTimeMarkProfile() || isEpesProfile()) {
      Policy signaturePolicy = createBDocSignaturePolicy();
      facade.setSignaturePolicy(signaturePolicy);
    }
  }
}

