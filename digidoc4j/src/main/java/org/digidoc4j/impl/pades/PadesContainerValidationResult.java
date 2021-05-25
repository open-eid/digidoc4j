package org.digidoc4j.impl.pades;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.simplereport.SimpleReport;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.AbstractContainerValidationResult;

import java.util.Arrays;

/**
 * Created by Andrei on 20.11.2017.
 */
public class PadesContainerValidationResult extends AbstractContainerValidationResult implements ContainerValidationResult {

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

}
