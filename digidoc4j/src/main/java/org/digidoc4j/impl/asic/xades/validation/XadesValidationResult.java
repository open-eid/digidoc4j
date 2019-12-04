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

import java.util.LinkedHashMap;
import java.util.Map;

import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.simplereport.SimpleReport;

public class XadesValidationResult {

  private Reports reports;

  /**
   * @param reports validation report
   */
  public XadesValidationResult(Reports reports) {
    this.reports = reports;
  }

  /**
   * @return map of simple reports
   */
  public Map<String, SimpleReport> buildSimpleReports() {
    Map<String, SimpleReport> simpleReports = new LinkedHashMap<>();
    SimpleReport simpleReport = this.reports.getSimpleReport();
    if (simpleReport.getSignatureIdList().size() > 0) {
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
