/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j;

import java.nio.file.Path;
import java.util.List;

import org.digidoc4j.impl.asic.report.SignatureValidationReport;

import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.simplereport.SimpleReport;

/**
 * Validation result information.
 *
 * For Asic the SignatureValidationResult contains only information for the first signature of each signature XML file
 */
public interface SignatureValidationResult extends ValidationResult {

  /**
   * Get SignatureValidationReports from signature validation data.
   *
   * @return SignatureValidationReport
   */
  List<SignatureValidationReport> getReports();

  /**
   * Get SignatureSimpleReport from signature validation data.
   *
   * @return SignatureValidationReport
   */
  List<SimpleReport> getSimpleReports();

  /**
   * Get indication from simple report.
   *
   * @param signatureId id of signature
   * @return signatureId
   */
  Indication getIndication(String signatureId);

  /**
   * Get subIndication from simple report.
   *
   * @param signatureId id of signature
   * @return subIndication
   */
  SubIndication getSubIndication(String signatureId);

  /**
   * Get SignatureQualification from simple report.
   *
   * @param signatureId id of signature
   * @return SignatureQualification
   */
  SignatureQualification getSignatureQualification(String signatureId);

  /**
   * Get validation report.
   *
   * @return report
   */
  String getReport();

  /**
   * Save validation reports in given directory.
   *
   * @param directory Directory where to save XML files.
   */
  void saveXmlReports(Path directory);

}
