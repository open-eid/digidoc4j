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

import java.io.Serializable;

import org.digidoc4j.SignatureValidationResult;

public class SignatureValidationData implements Serializable {

  private SignatureValidationResult validationResult;
  private String signatureId;
  private XadesValidationResult report;

  public void setValidationResult(SignatureValidationResult validationResult) {
    this.validationResult = validationResult;
  }

  public SignatureValidationResult getValidationResult() {
    return validationResult;
  }

  public void setSignatureId(String signatureId) {
    this.signatureId = signatureId;
  }

  public String getSignatureId() {
    return signatureId;
  }

  public void setReport(XadesValidationResult report) {
    this.report = report;
  }

  public XadesValidationResult getReport() {
    return report;
  }
}
