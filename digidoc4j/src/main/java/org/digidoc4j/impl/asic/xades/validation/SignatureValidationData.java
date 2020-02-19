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

import org.digidoc4j.SignatureProfile;
import org.digidoc4j.ValidationResult;

public class SignatureValidationData {

  private ValidationResult validationResult;
  private String signatureId;
  private String signatureUniqueId;
  private XadesValidationResult report;
  private SignatureProfile signatureProfile;

  public void setValidationResult(ValidationResult validationResult) {
    this.validationResult = validationResult;
  }

  public ValidationResult getValidationResult() {
    return validationResult;
  }

  public void setSignatureId(String signatureId) {
    this.signatureId = signatureId;
  }

  public String getSignatureId() {
    return signatureId;
  }

  public void setSignatureUniqueId(String signatureUniqueId) {
    this.signatureUniqueId = signatureUniqueId;
  }

  public String getSignatureUniqueId() {
    return signatureUniqueId;
  }

  public void setReport(XadesValidationResult report) {
    this.report = report;
  }

  public XadesValidationResult getReport() {
    return report;
  }

  public void setSignatureProfile(SignatureProfile signatureProfile) {
    this.signatureProfile = signatureProfile;
  }

  public SignatureProfile getSignatureProfile() {
    return signatureProfile;
  }
}
