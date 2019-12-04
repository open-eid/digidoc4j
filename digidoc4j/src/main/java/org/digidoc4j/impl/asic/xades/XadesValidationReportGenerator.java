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

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import org.apache.commons.collections4.CollectionUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.SignatureNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

public class XadesValidationReportGenerator implements Serializable {

  private final Logger log = LoggerFactory.getLogger(XadesValidationReportGenerator.class);
  private transient SignedDocumentValidator signedDocumentValidator;
  private transient Reports reports;
  private transient XAdESSignature xadesSignature;
  private DSSDocument document;
  private List<DSSDocument> detachedContents;
  private Configuration configuration;

  /**
   * @param document signature document
   * @param detachedContents detached content
   * @param configuration configuration context
   */
  public XadesValidationReportGenerator(DSSDocument document, List<DSSDocument> detachedContents,
                                        Configuration configuration) {
    this.document = document;
    this.detachedContents = detachedContents;
    this.configuration = configuration;
  }

  public Reports openValidationReport() {
    if (this.reports == null) {
      this.reports = this.generateReports();
      print();
    }
    return this.reports;
  }

  public XAdESSignature openDssSignature() {
    if (this.xadesSignature == null) {
      this.xadesSignature = this.getXAdESSignature();
    }
    return this.xadesSignature;
  }

  /*
   * RESTRICTED METHODS
   */

  private Reports generateReports() {
    try {
      this.log.debug("Creating a new validation report");
      Reports validationReports = this.getSignedDocumentValidator().validateDocument(this.getValidationPolicyAsStream());
      XadesValidationReportProcessor.process(validationReports);
      return validationReports;
    } catch (DSSException e) {
      throw new DigiDoc4JException(e);
    }
  }

  private InputStream getValidationPolicyAsStream() {
    String policyFile = this.configuration.getValidationPolicy();
    if (Files.exists(Paths.get(policyFile))) {
      try {
        return new FileInputStream(policyFile);
      } catch (FileNotFoundException ignore) {
        this.log.warn(ignore.getMessage());
      }
    }
    return this.getClass().getClassLoader().getResourceAsStream(policyFile);
  }

  private XAdESSignature getXAdESSignature() {
    this.log.debug("Opening XAdES signature");
    List<AdvancedSignature> signatures = this.getSignedDocumentValidator().getSignatures();
    if (CollectionUtils.isEmpty(signatures)) {
      throw new SignatureNotFoundException("No any XAdES signature found");
    }
    if (signatures.size() > 1) {
      this.log.warn("Signatures xml file contains more than one XAdES signature. This is not properly supported");
    }
    return (XAdESSignature) signatures.get(0);
  }

  private SignedDocumentValidator getSignedDocumentValidator() {
    if (this.signedDocumentValidator == null) {
      this.signedDocumentValidator = this.createValidator();
    }
    return this.signedDocumentValidator;
  }

  private SignedDocumentValidator createValidator() {
    this.log.debug("Creating a new XAdES validator");
    return new XadesValidationDssFacade(this.detachedContents, this.configuration).openXadesValidator(
        this.document);
  }

  private void print() {
    if (this.log.isTraceEnabled()) {
      this.log.trace("----------------Validation report---------------");
      this.log.trace(this.reports.getXmlDetailedReport());
      this.log.trace("----------------Simple report-------------------");
      this.log.trace(this.reports.getXmlSimpleReport());
    }
  }
}
