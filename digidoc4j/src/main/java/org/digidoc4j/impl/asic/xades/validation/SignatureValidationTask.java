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

import org.digidoc4j.Signature;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.impl.ValidatableSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.concurrent.Callable;

public class SignatureValidationTask implements Callable<SignatureValidationData> {

  private final static Logger logger = LoggerFactory.getLogger(SignatureValidationTask.class);

  private final Signature signature;
  private final Date validationTime;

  public SignatureValidationTask(Signature signature) {
    this(signature, null);
  }

  public SignatureValidationTask(Signature signature, Date validationTime) {
    this.signature = signature;
    this.validationTime = validationTime;
  }

  @Override
  public SignatureValidationData call() throws Exception {
    logger.debug("Starting to validate signature {}", signature.getId());
    ValidationResult validationResult = validateSignature();
    SignatureValidationData validationData = new SignatureValidationData();
    validationData.setValidationResult(validationResult);
    validationData.setSignatureId(signature.getId());
    validationData.setSignatureUniqueId(signature.getUniqueId());
    validationData.setSignatureProfile(signature.getProfile());
    if (validationResult instanceof XadesValidationResult.Holder) {
      validationData.setReport(((XadesValidationResult.Holder) validationResult).getXadesValidationResult());
    }
    return validationData;
  }

  private ValidationResult validateSignature() {
    if (validationTime != null && signature instanceof ValidatableSignature) {
      logger.trace("Validating signature {} @ {}", signature.getUniqueId(), validationTime);
      return ((ValidatableSignature) signature).validateSignatureAt(validationTime);
    } else {
      logger.trace("Executing default validation of signature {}", signature.getUniqueId());
      return signature.validateSignature();
    }
  }

}
