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

import java.util.LinkedHashMap;
import java.util.Map;

import eu.europa.esig.dss.validation.report.Reports;
import eu.europa.esig.dss.validation.report.SimpleReport;

public class XadesValidationResult {

  private Reports validationReport;

  public XadesValidationResult(Reports validationReport) {
    this.validationReport = validationReport;
  }

  public Reports getReport() {
    return validationReport;
  }

  public Map<String, SimpleReport> extractSimpleReports() {
    Map<String, SimpleReport> simpleReports = new LinkedHashMap<>();
    do {
      SimpleReport simpleReport = validationReport.getSimpleReport();
      if (simpleReport.getSignatureIdList().size() > 0) {
        simpleReports.put(simpleReport.getSignatureIdList().get(0), simpleReport);
      }
      validationReport = validationReport.getNextReports();
    } while (validationReport != null);
    return simpleReports;
  }

}
