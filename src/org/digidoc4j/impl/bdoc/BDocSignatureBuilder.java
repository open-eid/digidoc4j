package org.digidoc4j.impl.bdoc;

import static eu.europa.esig.dss.DigestAlgorithm.SHA256;
import static org.apache.commons.codec.binary.Base64.decodeBase64;

import org.digidoc4j.impl.bdoc.xades.validation.XadesSignatureValidator;

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
    signaturePolicy.setDigestValue(decodeBase64("0xRLPsW1UIpxtermnTGE+5+5620UsWi5bYJY76Di3o0="));
    signaturePolicy.setQualifier("OIDAsURN");
    signaturePolicy.setDigestAlgorithm(SHA256);
    signaturePolicy.setSpuri("https://www.sk.ee/repository/bdoc-spec21.pdf");
    return signaturePolicy;
  }

  protected void setSignaturePolicy() {
    if (isTimeMarkProfile() || isEpesProfile()) {
      Policy signaturePolicy = createBDocSignaturePolicy();
      facade.setSignaturePolicy(signaturePolicy);
    }
  }
}

