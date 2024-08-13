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
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.asic.report.TimestampValidationReport;

import java.util.List;

/**
 * An entity encapsulating the validation result information for a whole container.
 */
public interface ContainerValidationResult extends SignatureValidationResult {

  /**
   * Get indication of the token (signature or timestamp) with the specified ID.
   *
   * @see Signature#getUniqueId()
   * @see Timestamp#getUniqueId()
   * @see Signature#getId()
   *
   * @param tokenId ID of a token (signature or timestamp)
   * @return indication of the specified token or {@code null} if the specified ID does not map to any token in
   * this validation result
   */
  @Override
  Indication getIndication(String tokenId);

  /**
   * Get subIndication of the token (signature or timestamp) with the specified ID.
   *
   * @see Signature#getUniqueId()
   * @see Timestamp#getUniqueId()
   * @see Signature#getId()
   *
   * @param tokenId ID of a token (signature or timestamp)
   * @return subIndication of the specified token or {@code null} if the specified ID does not map to any token
   * in this validation result
   */
  @Override
  SubIndication getSubIndication(String tokenId);

  /**
   * Get TimestampQualification of the timestamp with the specified ID.
   *
   * @see Timestamp#getUniqueId()
   *
   * @param timestampId ID of a timestamp
   * @return timestamp qualification of the specified timestamp or {@code null} if the specified ID does not map to any
   * timestamp in this validation result
   */
  TimestampQualification getTimestampQualification(String timestampId);

  /**
   * Get TimestampValidationReports from signature validation data.
   *
   * @return list of TimestampValidationReport
   */
  List<TimestampValidationReport> getTimestampReports();

  /**
   * Get list container related errors.
   *
   * DDOC returns a list of errors encountered when validating meta data
   * ASIC returns a list of errors encountered when opening the container
   *
   * @return List of exceptions
   */
  List<DigiDoc4JException> getContainerErrors();

  /**
   * Get list container related warnings.
   *
   * @return List of exceptions
   */
  List<DigiDoc4JException> getContainerWarnings();

}
