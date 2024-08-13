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

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.simplereport.SimpleReport;
import org.digidoc4j.impl.asic.report.SignatureValidationReport;

import java.nio.file.Path;
import java.util.List;

/**
 * Validation result information.
 *
 * For Asic the SignatureValidationResult contains only information for the first signature of each signature XML file
 */
public interface SignatureValidationResult extends ValidationResult {

  /**
   * Get SignatureValidationReports from signature validation data.
   *
   * @return list of SignatureValidationReport
   * @deprecated Deprecated for removal. Use {@link #getSignatureReports()} instead.
   */
  @Deprecated
  default List<SignatureValidationReport> getReports() {
    return getSignatureReports();
  }

  /**
   * Get SignatureValidationReports from signature validation data.
   *
   * @return list of SignatureValidationReport
   */
  List<SignatureValidationReport> getSignatureReports();

  /**
   * Get SimpleReports from signature validation data.
   *
   * @return list of SimpleReport
   */
  List<SimpleReport> getSimpleReports();

  /**
   * Get indication of the signature with the specified ID.
   *
   * @see Signature#getUniqueId()
   * @see Signature#getId()
   *
   * @param signatureId ID of a signature
   * @return indication of the specified signature or {@code null} if the specified ID does not map to any signature in
   * this validation result
   */
  Indication getIndication(String signatureId);

  /**
   * Get subIndication of the signature with the specified ID.
   *
   * @see Signature#getUniqueId()
   * @see Signature#getId()
   *
   * @param signatureId id of a signature
   * @return subIndication of the specified signature or {@code null} if the specified ID does not map to any signature
   * in this validation result
   */
  SubIndication getSubIndication(String signatureId);

  /**
   * Get SignatureQualification of the signature with specified ID.
   *
   * @see Signature#getUniqueId()
   * @see Signature#getId()
   *
   * @param signatureId ID of a signature
   * @return signature qualification of the specified signature or {@code null} if the specified ID does not map to any
   * signature in this validation result
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
