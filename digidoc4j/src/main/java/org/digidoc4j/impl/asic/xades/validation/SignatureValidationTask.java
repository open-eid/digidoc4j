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

import java.util.concurrent.Callable;

import org.digidoc4j.Signature;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.impl.asic.asice.AsicESignature;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignature;
import org.digidoc4j.impl.asic.asics.AsicSSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SignatureValidationTask implements Callable<SignatureValidationData> {

  private final static Logger logger = LoggerFactory.getLogger(SignatureValidationTask.class);

  private Signature signature;

  public SignatureValidationTask(Signature signature) {
    this.signature = signature;
  }

  @Override
  public SignatureValidationData call() throws Exception {
    logger.debug("Starting to validate signature " + signature.getId());
    ValidationResult validationResult = signature.validateSignature();
    SignatureValidationData validationData = new SignatureValidationData();
    validationData.setValidationResult(validationResult);
    validationData.setSignatureId(signature.getId());
    validationData.setSignatureUniqueId(signature.getUniqueId());
    validationData.setSignatureProfile(signature.getProfile());
    if (signature.getClass() == BDocSignature.class) {
      validationData.setReport(((BDocSignature) signature).getDssValidationReport());
    } else if (signature.getClass() == AsicESignature.class) {
      validationData.setReport(((AsicESignature) signature).getDssValidationReport());
    } else if (signature.getClass() == AsicSSignature.class) {
      validationData.setReport(((AsicSSignature) signature).getDssValidationReport());
    }
    return validationData;
  }

}
