/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc;

import java.io.Serializable;
import java.util.List;

import org.digidoc4j.Signature;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.validation102853.report.Reports;

public class AsicContainerValidationResult implements Serializable {

  private List<Signature> signatures;
  private DigestAlgorithm containerDigestAlgorithm;
  private ValidationResultForBDoc bDocValidationResult;
  private Reports validationReport;
  private List<DSSDocument> signedDocuments;

  public boolean isValid() {
    return bDocValidationResult.isValid();
  }

  public List<Signature> getSignatures() {
    return signatures;
  }

  public void setSignatures(List<Signature> signatures) {
    this.signatures = signatures;
  }

  public DigestAlgorithm getContainerDigestAlgorithm() {
    return containerDigestAlgorithm;
  }

  public void setContainerDigestAlgorithm(DigestAlgorithm containerDigestAlgorithm) {
    this.containerDigestAlgorithm = containerDigestAlgorithm;
  }

  public ValidationResultForBDoc getbDocValidationResult() {
    return bDocValidationResult;
  }

  public void setbDocValidationResult(ValidationResultForBDoc bDocValidationResult) {
    this.bDocValidationResult = bDocValidationResult;
  }

  public Reports getValidationReport() {
    return validationReport;
  }

  public void setValidationReport(Reports validationReport) {
    this.validationReport = validationReport;
  }

  public List<DSSDocument> getSignedDocuments() {
    return signedDocuments;
  }

  public void setSignedDocuments(List<DSSDocument> signedDocuments) {
    this.signedDocuments = signedDocuments;
  }
}
