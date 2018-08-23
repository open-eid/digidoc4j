package org.digidoc4j.impl.asic.xades.validation;

import java.util.ArrayList;
import java.util.List;

import org.digidoc4j.exceptions.DigiDoc4JException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlName;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.reports.DetailedReport;

/**
 * Created by Andrei on 1.03.2018.
 */
public class FullSimpleReportBuilder {

  private final Logger log = LoggerFactory.getLogger(FullSimpleReportBuilder.class);

  private static final int BUILDING_BLOCK_ID_LIMIT = 15;

  private DetailedReport detailedReport;
  private List<DigiDoc4JException> validationErrors = new ArrayList<>();
  private List<DigiDoc4JException> validationWarnings = new ArrayList<>();

  FullSimpleReportBuilder(DetailedReport detailedReport) {
    this.detailedReport = detailedReport;
  }

  /**
   * Add exceptions from DetailedReport to SimpleReport
   *
   * @param validationErrors
   * @param validationWarnings
   */
  public void addDetailedReportEexeptions(List<DigiDoc4JException> validationErrors, List<DigiDoc4JException> validationWarnings){
    this.validationErrors = validationErrors;
    this.validationWarnings = validationWarnings;
    errorsAndWarningsBuilder();
  }

  private void errorsAndWarningsBuilder(){
    log.debug("Errors and warnings parsing from DetailedReport");

    List<XmlBasicBuildingBlocks> basicBuildingBlocks = this.detailedReport.getJAXBModel().getBasicBuildingBlocks();
    List<XmlName> errors = new ArrayList<>();
    List<XmlName> warnings = new ArrayList<>();

    for (XmlBasicBuildingBlocks xmlBasicBuildingBlocks: basicBuildingBlocks){
      if (xmlBasicBuildingBlocks.getCV() != null) {
        errors.addAll(xmlBasicBuildingBlocks.getCV().getConclusion().getErrors());
        warnings.addAll(xmlBasicBuildingBlocks.getCV().getConclusion().getWarnings());
      }
      if (xmlBasicBuildingBlocks.getFC() != null) {
        errors.addAll(xmlBasicBuildingBlocks.getFC().getConclusion().getErrors());
        warnings.addAll(xmlBasicBuildingBlocks.getFC().getConclusion().getWarnings());
      }
      if (xmlBasicBuildingBlocks.getISC() != null) {
        errors.addAll(xmlBasicBuildingBlocks.getISC().getConclusion().getErrors());
        warnings.addAll(xmlBasicBuildingBlocks.getISC().getConclusion().getWarnings());
      }
      if (xmlBasicBuildingBlocks.getPCV() != null) {
        errors.addAll(xmlBasicBuildingBlocks.getPCV().getConclusion().getErrors());
        warnings.addAll(xmlBasicBuildingBlocks.getPCV().getConclusion().getWarnings());
      }
      if (xmlBasicBuildingBlocks.getSAV() != null) {
        errors.addAll(xmlBasicBuildingBlocks.getSAV().getConclusion().getErrors());
        warnings.addAll(xmlBasicBuildingBlocks.getCV().getConclusion().getWarnings());
      }
      if (xmlBasicBuildingBlocks.getPSV() != null) {
        errors.addAll(xmlBasicBuildingBlocks.getPSV().getConclusion().getErrors());
        warnings.addAll(xmlBasicBuildingBlocks.getPSV().getConclusion().getWarnings());
      }
      if (xmlBasicBuildingBlocks.getVCI() != null) {
        errors.addAll(xmlBasicBuildingBlocks.getVCI().getConclusion().getErrors());
        warnings.addAll(xmlBasicBuildingBlocks.getVCI().getConclusion().getWarnings());
      }
      if (xmlBasicBuildingBlocks.getVTS() != null) {
        errors.addAll(xmlBasicBuildingBlocks.getVTS().getConclusion().getErrors());
        warnings.addAll(xmlBasicBuildingBlocks.getVTS().getConclusion().getWarnings());
      }
      if (xmlBasicBuildingBlocks.getXCV() != null) {
        errors.addAll(xmlBasicBuildingBlocks.getXCV().getConclusion().getErrors());
        warnings.addAll(xmlBasicBuildingBlocks.getXCV().getConclusion().getWarnings());
        if (xmlBasicBuildingBlocks.getXCV().getSubXCV() != null) {
          List<XmlSubXCV> subXCV = xmlBasicBuildingBlocks.getXCV().getSubXCV();
          for (XmlSubXCV xmlSubXCV : subXCV){
            errors.addAll(xmlSubXCV.getConclusion().getErrors());
            warnings.addAll(xmlSubXCV.getConclusion().getWarnings());
          }
        }
      }
      validationErrors.addAll(getErrors(errors, xmlBasicBuildingBlocks.getId(), xmlBasicBuildingBlocks
          .getType()));

      validationWarnings.addAll(getWarnings(warnings, xmlBasicBuildingBlocks.getId(), xmlBasicBuildingBlocks.getType()));
    }
  }

  private List<DigiDoc4JException>  getWarnings(List<XmlName> warnings, String id, Context type) {
    List<DigiDoc4JException> warningsAsString = new ArrayList<>();
    String typeId = transformTypeId(id);
    for (XmlName xmlName : warnings){
      if (isNewException(xmlName.getValue(), this.validationWarnings)){
        warningsAsString.add(getExcetpions(xmlName, typeId, type));
      }
    }
    return warningsAsString;
  }

  private List<DigiDoc4JException> getErrors(List<XmlName> errors, String id, Context type) {
    List<DigiDoc4JException> errorsAsString = new ArrayList<>();
    String typeId = transformTypeId(id);
    for (XmlName xmlName : errors){
      if (isNewException(xmlName.getValue(), this.validationErrors)){
        errorsAsString.add(getExcetpions(xmlName, typeId, type));
      }
    }
    return errorsAsString;
  }

  private DigiDoc4JException getExcetpions(XmlName xmlName, String typeId, Context type) {
    String nameId = xmlName.getNameId();
    String value = xmlName.getValue();
    return new DigiDoc4JException("Block Id: " + typeId + ". Type = " +  type.name() + ". " + nameId + ": " +
        value);
  }

  private String transformTypeId(String id) {
    if (id.length() > BUILDING_BLOCK_ID_LIMIT){
      log.debug("BasicBuildingBlock Id is too big for report: {}", id);
      return id.substring(0, BUILDING_BLOCK_ID_LIMIT).concat("..");
    }
    return id;
  }

  private boolean isNewException(String exccceptionValue, List<DigiDoc4JException> exceptions) {
    for (DigiDoc4JException digiDoc4JException : exceptions){
      if (digiDoc4JException.getMessage().contains(exccceptionValue)){
        return false;
      }
    }
    return true;
  }
}
