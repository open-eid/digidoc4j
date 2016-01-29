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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.lang.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.exceptions.ContainerWithoutSignaturesException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.TechnicalException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.report.Reports;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;

public class XadesValidationReportGenerator implements Serializable {

  private final static Logger logger = LoggerFactory.getLogger(XadesValidationReportGenerator.class);
  private DSSDocument xadesSignatureFile;
  private CertificateVerifier certificateVerifier;
  private Configuration configuration;
  private transient SignedDocumentValidator validator;
  private transient Reports validationReport;

  public XadesValidationReportGenerator(SignedDocumentValidator validator, CertificateVerifier certificateVerifier, Configuration configuration) {
    this.certificateVerifier = certificateVerifier;
    this.configuration = configuration;
    this.validator = validator;
  }

  public XadesValidationReportGenerator(Reports validationReport) {
    this.validationReport = validationReport;
  }

  public Reports openValidationReport() {
    if (validationReport != null) {
      logger.debug("Using existing validation report");
      return validationReport;
    }
    if (validator == null) {
      validator = openValidator();
    }
    generateReport();
    return validationReport;
  }

  private SignedDocumentValidator openValidator() throws ContainerWithoutSignaturesException {
    logger.debug("Opening xades signature validator");
    try {
      return XMLDocumentValidator.fromDocument(xadesSignatureFile);
    } catch (DSSException e) {
      if (StringUtils.equalsIgnoreCase("This is not an ASiC container. The signature cannot be found!", e.getMessage())) {
        throw new ContainerWithoutSignaturesException();
      }
      if (StringUtils.equalsIgnoreCase("Document format not recognized/handled", e.getMessage())) {
        throw new ContainerWithoutSignaturesException();
      }
      logger.error("Error validating container: " + e.getMessage());
      throw new TechnicalException("Error validating container: " + e.getMessage(), e);
    }
  }

  private Reports generateReport() {
    if (validationReport != null) {
      logger.debug("Using existing validation report");
      return validationReport;
    }
    validationReport = createNewValidationReport();
    printReport(validationReport);
    return validationReport;
  }

  private Reports createNewValidationReport() {
    try {
      logger.debug("Creating a new validation report");
      //prepareValidator();
      InputStream validationPolicyAsStream = getValidationPolicyAsStream();
      return validator.validateDocument(validationPolicyAsStream);
    } catch (DSSException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    }
  }

  private void prepareValidator() {
    certificateVerifier.setOcspSource(null);
    certificateVerifier.setTrustedCertSource(configuration.getTSL());
    validator.setCertificateVerifier(certificateVerifier);
  }

  private InputStream getValidationPolicyAsStream() {
    String policyFile = configuration.getValidationPolicy();
    if (Files.exists(Paths.get(policyFile))) {
      try {
        return new FileInputStream(policyFile);
      } catch (FileNotFoundException ignore) {
        logger.warn(ignore.getMessage());
      }
    }
    return getClass().getClassLoader().getResourceAsStream(policyFile);
  }

  private void printReport(Reports report) {
    if (logger.isTraceEnabled()) {
      Reports currentReports = report;
      do {
        logger.trace("----------------Validation report---------------");
        logger.trace(currentReports.getDetailedReport().toString());

        logger.trace("----------------Simple report-------------------");
        logger.trace(currentReports.getSimpleReport().toString());

        currentReports = currentReports.getNextReports();
      } while (currentReports != null);
    }
  }

}
