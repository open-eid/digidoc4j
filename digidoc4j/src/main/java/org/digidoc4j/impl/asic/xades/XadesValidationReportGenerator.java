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
import org.digidoc4j.impl.asic.AbstractValidationReportGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Validation report generator for XAdES signatures.
 */
public class XadesValidationReportGenerator extends AbstractValidationReportGenerator {

  private static final Logger log = LoggerFactory.getLogger(XadesValidationReportGenerator.class);

  private final DSSDocument document;
  private final List<DSSDocument> detachedContents;

  private transient XAdESSignature xadesSignature;

  /**
   * @param document signature document
   * @param detachedContents detached content
   * @param configuration configuration context
   */
  public XadesValidationReportGenerator(DSSDocument document, List<DSSDocument> detachedContents,
                                        Configuration configuration) {
    super(configuration);
    this.document = document;
    this.detachedContents = detachedContents;
  }

  public XAdESSignature openDssSignature() {
    if (this.xadesSignature == null) {
      this.xadesSignature = getXAdESSignature();
    }
    return this.xadesSignature;
  }

  @Override
  protected Reports generateReports() {
    try {
      log.debug("Creating a new validation report");
      Reports validationReports = validate(getSignedDocumentValidator());
      XadesValidationReportProcessor.process(validationReports);
      return validationReports;
    } catch (DSSException e) {
      throw new DigiDoc4JException(e);
    }
  }

  private XAdESSignature getXAdESSignature() {
    log.debug("Opening XAdES signature");
    List<AdvancedSignature> signatures = getSignedDocumentValidator().getSignatures();
    if (CollectionUtils.isEmpty(signatures)) {
      throw new SignatureNotFoundException("No any XAdES signature found");
    }
    if (signatures.size() > 1) {
      log.warn("Signatures xml file contains more than one XAdES signature. This is not properly supported");
    }
    return (XAdESSignature) signatures.get(0);
  }

  @Override
  protected SignedDocumentValidator createValidator() {
    log.debug("Creating a new XAdES validator");
    return new XadesValidationDssFacade(detachedContents, configuration).openXadesValidator(document);
  }

}
