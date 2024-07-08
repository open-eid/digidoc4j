/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.cades;

import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.digidoc4j.Configuration;
import org.digidoc4j.impl.AiaSourceFactory;
import org.digidoc4j.impl.asic.AbstractValidationReportGenerator;

/**
 * Abstract base class of validation report generator for CAdES.
 */
public abstract class CadesValidationReportGenerator extends AbstractValidationReportGenerator {

  protected CadesValidationReportGenerator(Configuration configuration) {
    super(configuration);
  }

  /**
   * Configures an instance of {@link CadesValidationDssFacade} for validation.
   *
   * @param validationDssFacade the facade to configure for validation
   */
  protected abstract void configureValidationFacade(CadesValidationDssFacade validationDssFacade);

  @Override
  protected SignedDocumentValidator createValidator() {
    CadesValidationDssFacade validationFacade = new CadesValidationDssFacade();

    validationFacade.setAiaSource(new AiaSourceFactory(configuration).create());
    validationFacade.setCertificateSource(configuration.getTSL());
    configureValidationFacade(validationFacade);

    return validationFacade.openValidator();
  }

  @Override
  protected Reports generateReports() {
    return validate(getSignedDocumentValidator());
  }

}
