/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.xades;

import eu.europa.esig.dss.xades.validation.XAdESSignature;
import org.digidoc4j.impl.asic.xades.validation.XadesValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;

/**
 * DSS XADES signature
 */
public abstract class DssXadesSignature implements XadesSignature {

  private static final Logger LOGGER = LoggerFactory.getLogger(DssXadesSignature.class);
  private final XadesValidationReportGenerator reportGenerator;

  /**
   * @param reportGenerator XADES validation report generator
   */
  public DssXadesSignature(XadesValidationReportGenerator reportGenerator) {
    this.reportGenerator = reportGenerator;
  }

  @Override
  public XadesValidationResult validate() {
    LOGGER.debug("Validating XAdES signature");
    return new XadesValidationResult(reportGenerator.openValidationReport());
  }

  @Override
  public XadesValidationResult validateAt(Date validationTime) {
    LOGGER.debug("Validating XAdES signature @ {}", validationTime);
    return new XadesValidationResult(reportGenerator.generateReports(validationTime));
  }

  @Override
  public XAdESSignature getDssSignature() {
    return reportGenerator.openDssSignature();
  }

}
