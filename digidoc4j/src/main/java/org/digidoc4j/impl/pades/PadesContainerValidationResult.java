package org.digidoc4j.impl.pades;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.AbstractSignatureValidationResult;

import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.reports.SimpleReport;

/**
 * Created by Andrei on 20.11.2017.
 */
public class PadesContainerValidationResult extends AbstractSignatureValidationResult implements
    ContainerValidationResult {

  /**
   * @param simpleReport simple report
   */
  public PadesContainerValidationResult(SimpleReport simpleReport) {
    this.simpleReports = Arrays.asList(simpleReport);
  }

  @Override
  public Indication getIndication(String signatureId) {
    if (StringUtils.isNotBlank(signatureId)) {
      return this.simpleReports.get(0).getIndication(signatureId);
    }
    throw new DigiDoc4JException("Signature ID is unset");
  }

  @Override
  public SubIndication getSubIndication(String signatureId) {
    if (StringUtils.isNotBlank(signatureId)) {
      return this.simpleReports.get(0).getSubIndication(signatureId);
    }
    throw new DigiDoc4JException("Signature ID is unset");
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected String getResultName() {
    return "PAdES container";
  }

  /*
   * ACCESSORS
   */

  @Override
  public List<DigiDoc4JException> getContainerErrors() {
    return Collections.emptyList();
  }

}
