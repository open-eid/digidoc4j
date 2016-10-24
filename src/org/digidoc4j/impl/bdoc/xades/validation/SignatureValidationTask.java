/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.xades.validation;

import java.util.concurrent.Callable;

import org.digidoc4j.Signature;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.impl.bdoc.BDocSignature;
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
    SignatureValidationResult validationResult = signature.validateSignature();
    SignatureValidationData validationData = new SignatureValidationData();
    validationData.setValidationResult(validationResult);
    validationData.setSignatureId(signature.getId());
    validationData.setSignatureProfile(signature.getProfile());
    validationData.setReport(((BDocSignature) signature).getDssValidationReport());
    return validationData;
  }

}
