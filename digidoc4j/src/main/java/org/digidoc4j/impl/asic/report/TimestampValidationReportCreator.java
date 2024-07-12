/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.report;

import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.impl.asic.cades.TimestampValidationData;

/**
 * Timestamp validation report creator.
 */
public class TimestampValidationReportCreator extends TokenValidationReportCreator {

  private final TimestampValidationData timestampValidationData;

  public static TimestampValidationReport create(TimestampValidationData timestampValidationData) {
    return new TimestampValidationReportCreator(timestampValidationData).createTimestampValidationReport();
  }

  private TimestampValidationReportCreator(TimestampValidationData timestampValidationData) {
    super(timestampValidationData.getEncapsulatingReports());
    this.timestampValidationData = timestampValidationData;
  }

  private TimestampValidationReport createTimestampValidationReport() {
    TimestampValidationReport timestampValidationReport = cloneTimestampValidationReport();
    updateMissingErrors(timestampValidationData.getValidationResult(), timestampValidationReport);
    return timestampValidationReport;
  }

  private TimestampValidationReport cloneTimestampValidationReport() {
    final String timestampId = timestampValidationData.getTimestampUniqueId();
    return simpleReport.getSignatureOrTimestampOrEvidenceRecord().stream()
            .filter(XmlTimestamp.class::isInstance)
            .map(XmlTimestamp.class::cast)
            .filter(t -> StringUtils.equals(t.getId(), timestampId))
            .map(TimestampValidationReport::create)
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException("Timestamp not found from simple report"));
  }

}
