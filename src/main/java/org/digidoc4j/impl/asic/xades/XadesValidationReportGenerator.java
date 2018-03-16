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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import org.apache.commons.collections4.CollectionUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.SignatureNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

public class XadesValidationReportGenerator implements Serializable {

  private static final Logger LOGGER = LoggerFactory.getLogger(XadesValidationReportGenerator.class);
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
    if (this.validationReport != null) {
      LOGGER.debug("Using existing validation report");
      return this.validationReport;
    }
    this.validationReport = this.createNewValidationReport();
    this.print();
    return this.validationReport;
  }

  public XAdESSignature openDssSignature() {
    if (this.dssSignature == null) {
      this.dssSignature = this.getXAdESSignature();
    }
    return this.dssSignature;
  }

  /*
   * RESTRICTED METHODS
   */

  private Reports createNewValidationReport() {
    try {
      LOGGER.debug("Creating a new validation report");
      return this.getSignedDocumentValidator().validateDocument(this.getValidationPolicyAsStream());
    } catch (DSSException e) {
      LOGGER.error("Error creating a new validation report: {}", e.getMessage());
      throw new DigiDoc4JException(e);
    }
  }

  private InputStream getValidationPolicyAsStream() {
    String policyFile = this.configuration.getValidationPolicy();
    if (Files.exists(Paths.get(policyFile))) {
      try {
        return new FileInputStream(policyFile);
      } catch (FileNotFoundException ignore) {
        LOGGER.warn(ignore.getMessage());
      }
    }
    return this.getClass().getClassLoader().getResourceAsStream(policyFile);
  }

  private XAdESSignature getXAdESSignature() {
    LOGGER.debug("Opening XAdES signature");
    List<AdvancedSignature> signatures = this.getSignedDocumentValidator().getSignatures();
    if (CollectionUtils.isEmpty(signatures)) {
      throw new SignatureNotFoundException("Unable to open XAdES signature. Content is empty");
    }
    if (signatures.size() > 1) {
      LOGGER.warn("Signatures xml file contains more than one signature. This is not properly supported");
    }
    return (XAdESSignature) signatures.get(0);
  }

  private SignedDocumentValidator getSignedDocumentValidator() {
    if (this.validator == null) {
      this.validator = this.createXadesValidator();
    }
    return this.validator;
  }

  private SignedDocumentValidator createXadesValidator() {
    LOGGER.debug("Creating a new xades validator");
    return new XadesValidationDssFacade(this.detachedContents, this.configuration).openXadesValidator(this.signatureDocument);
  }

  private void print() {
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace("----------------Validation report---------------");
      LOGGER.trace(this.validationReport.getXmlDetailedReport());
      LOGGER.trace("----------------Simple report-------------------");
      LOGGER.trace(this.validationReport.getXmlSimpleReport());
    }
  }

  /*
   * ACCESSORS
   */

  public void setValidator(SignedDocumentValidator validator) {
    this.validator = validator;
  }

}
