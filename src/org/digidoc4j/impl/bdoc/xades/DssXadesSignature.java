/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.xades;

import org.digidoc4j.impl.bdoc.xades.validation.XadesValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

public abstract class DssXadesSignature implements XadesSignature {

  private final static Logger logger = LoggerFactory.getLogger(DssXadesSignature.class);
  private XadesValidationReportGenerator reportGenerator;

  public DssXadesSignature(XadesValidationReportGenerator reportGenerator) {
    this.reportGenerator = reportGenerator;
  }

  @Override
  public XadesValidationResult validate() {
    logger.debug("Validating xades signature");
    Reports validationReport = reportGenerator.openValidationReport();
    return new XadesValidationResult(validationReport);
  }

  @Override
  public XAdESSignature getDssSignature() {
    return reportGenerator.openDssSignature();
  }
}
