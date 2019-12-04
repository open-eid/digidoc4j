/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.utils;

import eu.europa.esig.dss.model.Policy;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.impl.asic.xades.validation.XadesSignatureValidator;

import static eu.europa.esig.dss.enumerations.DigestAlgorithm.SHA256;

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

  /**
   * Determines if all required fields are defined for given policy.
   * @param policy policy to be validated
   * @return whether all policy required fields are defined
   */
  public static boolean areAllPolicyValuesDefined(Policy policy) {
    return StringUtils.isNotBlank(policy.getId())
            && policy.getDigestValue() != null
            && StringUtils.isNotBlank(policy.getQualifier())
            && policy.getDigestAlgorithm() != null
            && StringUtils.isNotBlank(policy.getSpuri());
  }
}
