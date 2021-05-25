package org.digidoc4j.impl;

import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;

import java.util.ArrayList;
import java.util.List;

public abstract class AbstractContainerValidationResult extends AbstractSignatureValidationResult implements ContainerValidationResult {

  protected List<DigiDoc4JException> containerErrors = new ArrayList<>();
  protected List<DigiDoc4JException> containerWarnings = new ArrayList<>();

  @Override
  public List<DigiDoc4JException> getContainerErrors() {
    return containerErrors;
  }

  public void addContainerErrors(List<DigiDoc4JException> containerErrors) {
    this.containerErrors = concatenate(this.containerErrors, containerErrors);
  }

  public void setContainerErrors(List<DigiDoc4JException> containerErrors) {
    this.containerErrors = containerErrors;
  }

  @Override
  public List<DigiDoc4JException> getContainerWarnings() {
    return containerWarnings;
  }

  public void addContainerWarnings(List<DigiDoc4JException> containerWarnings) {
    this.containerWarnings = concatenate(this.containerWarnings, containerWarnings);
  }

  public void setContainerWarnings(List<DigiDoc4JException> containerWarnings) {
    this.containerWarnings = containerWarnings;
  }

}
