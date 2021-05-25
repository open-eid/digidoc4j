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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.Policy;
import org.apache.commons.codec.binary.Base64;
import org.digidoc4j.impl.asic.xades.validation.XadesSignatureValidator;
import org.hamcrest.core.IsEqual;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

public class PolicyUtilsTest {

  @Test
  public void createBDocSignaturePolicy() {
    Policy policy = PolicyUtils.createBDocSignaturePolicy();
    assertEquals("urn:oid:" + XadesSignatureValidator.TM_POLICY, policy.getId());
    assertEquals("OIDAsURN", policy.getQualifier().getValue());
    assertEquals(DigestAlgorithm.SHA256, policy.getDigestAlgorithm());
    assertEquals("https://www.sk.ee/repository/bdoc-spec21.pdf", policy.getSpuri());
    assertThat(Base64.decodeBase64("3Tl1oILSvOAWomdI9VeWV6IA/32eSXRUri9kPEz1IVs="), IsEqual.equalTo(policy.getDigestValue()));
  }

  @Test
  public void allPolicyValuesDefined() {
    Policy policy = PolicyUtils.createBDocSignaturePolicy();
    assertTrue(PolicyUtils.areAllPolicyValuesDefined(policy));
  }

  @Test
  public void allPolicyValuesNotDefined() {
    Policy policy = PolicyUtils.createBDocSignaturePolicy();
    policy.setSpuri(null);
    assertFalse(PolicyUtils.areAllPolicyValuesDefined(policy));
  }
}
