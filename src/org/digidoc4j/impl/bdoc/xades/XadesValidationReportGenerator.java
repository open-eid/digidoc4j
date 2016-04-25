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
import java.util.List;

import org.digidoc4j.Configuration;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.SignatureNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.report.Reports;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

public class XadesValidationReportGenerator implements Serializable {

  private final static Logger logger = LoggerFactory.getLogger(XadesValidationReportGenerator.class);
  private transient SignedDocumentValidator validator;
  private transient Reports validationReport;
  private transient XAdESSignature dssSignature;
  private DSSDocument signatureDocument;
  private List<DSSDocument> detachedContents;
  private Configuration configuration;

  public XadesValidationReportGenerator(DSSDocument signatureDocument, List<DSSDocument> detachedContents, Configuration configuration) {
    this.signatureDocument = signatureDocument;
    this.detachedContents = detachedContents;
    this.configuration = configuration;
  }

  public Reports openValidationReport() {
    if (validationReport != null) {
      logger.debug("Using existing validation report");
      return validationReport;
    }
    validationReport = createNewValidationReport();
    printReport(validationReport);
    return validationReport;
  }

  public XAdESSignature openDssSignature() {
    if (dssSignature == null) {
      initXadesValidator();
      dssSignature = getXAdESSignature();
    }
    return dssSignature;
  }

  public void setValidator(SignedDocumentValidator validator) {
    this.validator = validator;
  }

  private Reports createNewValidationReport() {
    try {
      logger.debug("Creating a new validation report");
      InputStream validationPolicyAsStream = getValidationPolicyAsStream();
      initXadesValidator();
      return validator.validateDocument(validationPolicyAsStream);
    } catch (DSSException e) {
      logger.error("Error creating a new validation report: " + e.getMessage());
      throw new DigiDoc4JException(e);
    }
  }

  private void initXadesValidator() {
    if (validator == null) {
      validator = createXadesValidator();
    }
  }

  private SignedDocumentValidator createXadesValidator() {
    logger.debug("Creating a new xades validator");
    XadesValidationDssFacade validationFacade = new XadesValidationDssFacade(detachedContents, configuration);
    SignedDocumentValidator validator = validationFacade.openXadesValidator(signatureDocument);
    return validator;
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

  private XAdESSignature getXAdESSignature() {
    logger.debug("Opening XAdES signature");
    List<AdvancedSignature> signatures = validator.getSignatures();
    if (signatures == null || signatures.isEmpty()) {
      logger.error("Unable to open XAdES signature. Content is empty");
      throw new SignatureNotFoundException();
    }
    if (signatures.size() > 1) {
      logger.warn("Signatures xml file contains more than one signature. This is not properly supported.");
    }
    return (XAdESSignature) signatures.get(0);
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
