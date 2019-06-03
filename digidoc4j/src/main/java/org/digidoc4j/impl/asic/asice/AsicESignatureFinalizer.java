package org.digidoc4j.impl.asic.asice;

import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.SignatureContainerMatcherValidator;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.exceptions.IllegalSignatureProfileException;
import org.digidoc4j.impl.asic.AsicSignatureFinalizer;

import java.util.List;

public class AsicESignatureFinalizer extends AsicSignatureFinalizer {

  public AsicESignatureFinalizer(List<DataFile> dataFilesToSign, SignatureParameters signatureParameters, Configuration configuration) {
    super(dataFilesToSign, signatureParameters, configuration);
  }

  @Override
  protected void setSignaturePolicy() {
    // Do nothing
  }

  @Override
  protected void validateSignatureCompatibilityWithContainer() {
    super.validateSignatureCompatibilityWithContainer();
    if (SignatureContainerMatcherValidator.isBDocOnlySignature(signatureParameters.getSignatureProfile())) {
      throw new IllegalSignatureProfileException(
              "Cannot add BDoc specific (" + signatureParameters.getSignatureProfile() + ") signature to ASiCE container");
    }
  }
}
