package org.digidoc4j.impl.asic.cades;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.simplereport.SimpleReport;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.AbstractSignatureValidationResult;

import java.util.Collections;
import java.util.List;

public class AsicContainerWithCadesValidationResult extends AbstractSignatureValidationResult implements
    ContainerValidationResult {

  /**
   * @param simpleReport simple report
   */
  public AsicContainerWithCadesValidationResult(SimpleReport simpleReport) {
    this.simpleReports = Collections.singletonList(simpleReport);
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
    return "ASiC container with Cades";
  }

  /*
   * ACCESSORS
   */

  @Override
  public List<DigiDoc4JException> getContainerErrors() {
    return Collections.emptyList();
  }

}

