package org.digidoc4j.impl.asic.asice.bdoc;

import eu.europa.esig.dss.Policy;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.impl.asic.asice.AsicESignatureFinalizer;
import org.digidoc4j.utils.PolicyUtils;

import java.util.List;

public class BDocSignatureFinalizer extends AsicESignatureFinalizer {

  public BDocSignatureFinalizer(List<DataFile> dataFilesToSign, SignatureParameters signatureParameters, Configuration configuration) {
    super(dataFilesToSign, signatureParameters, configuration);
  }

  @Override
  protected void setSignaturePolicy() {
    if (isTimeMarkProfile() || isEpesProfile()) {
      Policy signaturePolicy = determineSignaturePolicy();
      facade.setSignaturePolicy(signaturePolicy);
    }
  }

  @Override
  protected void validateSignatureCompatibilityWithContainer() {
    // Do nothing
  }

  private Policy determineSignaturePolicy() {
    Policy policyDefinedByUser = signatureParameters.getPolicy();
    if (policyDefinedByUser != null && PolicyUtils.areAllPolicyValuesDefined(policyDefinedByUser)) {
      return policyDefinedByUser;
    }
    return PolicyUtils.createBDocSignaturePolicy();
  }

  private boolean isTimeMarkProfile() {
    return SignatureProfile.LT_TM == signatureParameters.getSignatureProfile();
  }

  private boolean isEpesProfile() {
    return SignatureProfile.B_EPES == signatureParameters.getSignatureProfile();
  }
}
