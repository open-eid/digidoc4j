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

import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.reports.Reports;
import org.apache.commons.collections4.CollectionUtils;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public class XadesValidationResult {

  public interface Holder {
    XadesValidationResult getXadesValidationResult();
  }

  private final Reports reports;

  /**
   * @param reports validation report
   */
  public XadesValidationResult(Reports reports) {
    this.reports = Objects.requireNonNull(reports);
  }

  /**
   * @return map of simple reports
   */
  public Map<String, SimpleReport> buildSimpleReports() {
    Map<String, SimpleReport> simpleReports = new LinkedHashMap<>();
    SimpleReport simpleReport = reports.getSimpleReport();
    if (CollectionUtils.isNotEmpty(simpleReport.getSignatureIdList())) {
      simpleReports.put(simpleReport.getSignatureIdList().get(0), simpleReport);
    }
    return simpleReports;
  }

  /*
   * ACCESSORS
   */

  public Reports getReports() {
    return reports;
  }

}
