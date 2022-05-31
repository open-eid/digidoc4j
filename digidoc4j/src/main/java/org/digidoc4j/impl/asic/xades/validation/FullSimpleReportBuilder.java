package org.digidoc4j.impl.asic.xades.validation;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.enumerations.Context;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Created by Andrei on 1.03.2018.
 */
public class FullSimpleReportBuilder {

  private static final Logger log = LoggerFactory.getLogger(FullSimpleReportBuilder.class);

  private static final int BUILDING_BLOCK_ID_LIMIT = 15;

  private final DetailedReport detailedReport;

  FullSimpleReportBuilder(DetailedReport detailedReport) {
    this.detailedReport = detailedReport;
  }

  /**
   * Add exceptions from DetailedReport to SimpleReport
   *
   * @param validationErrors
   * @param validationWarnings
   */
  public void addDetailedReportExceptions(List<DigiDoc4JException> validationErrors, List<DigiDoc4JException> validationWarnings){
    log.debug("Errors and warnings parsing from DetailedReport");

    List<XmlBasicBuildingBlocks> basicBuildingBlocks = this.detailedReport.getJAXBModel().getBasicBuildingBlocks();

    for (XmlBasicBuildingBlocks xmlBasicBuildingBlocks : basicBuildingBlocks) {
      String typeId = transformTypeId(xmlBasicBuildingBlocks.getId());
      Context type = xmlBasicBuildingBlocks.getType();

      if (xmlBasicBuildingBlocks.getCV() != null) {
        XmlConclusion xmlConclusion = xmlBasicBuildingBlocks.getCV().getConclusion();
        addExceptions(validationErrors, xmlConclusion.getErrors(), typeId, type);
        addExceptions(validationWarnings, xmlConclusion.getWarnings(), typeId, type);
      }
      if (xmlBasicBuildingBlocks.getFC() != null) {
        XmlConclusion xmlConclusion = xmlBasicBuildingBlocks.getFC().getConclusion();
        addExceptions(validationErrors, xmlConclusion.getErrors(), typeId, type);
        addExceptions(validationWarnings, xmlConclusion.getWarnings(), typeId, type);
      }
      if (xmlBasicBuildingBlocks.getISC() != null) {
        XmlConclusion xmlConclusion = xmlBasicBuildingBlocks.getISC().getConclusion();
        addExceptions(validationErrors, xmlConclusion.getErrors(), typeId, type);
        addExceptions(validationWarnings, xmlConclusion.getWarnings(), typeId, type);
      }
      if (xmlBasicBuildingBlocks.getPCV() != null) {
        XmlConclusion xmlConclusion = xmlBasicBuildingBlocks.getPCV().getConclusion();
        addExceptions(validationErrors, xmlConclusion.getErrors(), typeId, type);
        addExceptions(validationWarnings, xmlConclusion.getWarnings(), typeId, type);
      }
      if (xmlBasicBuildingBlocks.getSAV() != null) {
        XmlConclusion xmlConclusion = xmlBasicBuildingBlocks.getSAV().getConclusion();
        addExceptions(validationErrors, xmlConclusion.getErrors(), typeId, type);
        addExceptions(validationWarnings, xmlConclusion.getWarnings(), typeId, type);
      }
      if (xmlBasicBuildingBlocks.getPSV() != null) {
        XmlConclusion xmlConclusion = xmlBasicBuildingBlocks.getPSV().getConclusion();
        addExceptions(validationErrors, xmlConclusion.getErrors(), typeId, type);
        addExceptions(validationWarnings, xmlConclusion.getWarnings(), typeId, type);
      }
      if (xmlBasicBuildingBlocks.getVCI() != null) {
        XmlConclusion xmlConclusion = xmlBasicBuildingBlocks.getVCI().getConclusion();
        addExceptions(validationErrors, xmlConclusion.getErrors(), typeId, type);
        addExceptions(validationWarnings, xmlConclusion.getWarnings(), typeId, type);
      }
      if (xmlBasicBuildingBlocks.getVTS() != null) {
        XmlConclusion xmlConclusion = xmlBasicBuildingBlocks.getVTS().getConclusion();
        addExceptions(validationErrors, xmlConclusion.getErrors(), typeId, type);
        addExceptions(validationWarnings, xmlConclusion.getWarnings(), typeId, type);
      }
      if (xmlBasicBuildingBlocks.getXCV() != null) {
        XmlConclusion xmlConclusion = xmlBasicBuildingBlocks.getXCV().getConclusion();
        addExceptions(validationErrors, xmlConclusion.getErrors(), typeId, type);
        addExceptions(validationWarnings, xmlConclusion.getWarnings(), typeId, type);
        if (xmlBasicBuildingBlocks.getXCV().getSubXCV() != null) {
          List<XmlSubXCV> subXCV = xmlBasicBuildingBlocks.getXCV().getSubXCV();
          for (XmlSubXCV xmlSubXCV : subXCV){
            XmlConclusion xmlSubConclusion = xmlSubXCV.getConclusion();
            addExceptions(validationErrors, xmlSubConclusion.getErrors(), typeId, type);
            addExceptions(validationWarnings, xmlSubConclusion.getWarnings(), typeId, type);
          }
        }
      }
    }
  }

  private static void addExceptions(List<DigiDoc4JException> exceptions, List<XmlMessage> messages, String typeId, Context type) {
    for (XmlMessage xmlMessage : messages) {
      if (isNewException(xmlMessage.getValue(), exceptions)) {
        exceptions.add(getException(xmlMessage, typeId, type));
      }
    }
  }

  private static DigiDoc4JException getException(XmlMessage xmlMessage, String typeId, Context type) {
    String key = xmlMessage.getKey();
    String value = xmlMessage.getValue();
    return new DigiDoc4JException("Block Id: " + typeId + ". Type = " +  type.name() + ". " + key + ": " +
        value);
  }

  private static String transformTypeId(String id) {
    if (id.length() > BUILDING_BLOCK_ID_LIMIT){
      log.debug("BasicBuildingBlock Id is too big for report: {}", id);
      return id.substring(0, BUILDING_BLOCK_ID_LIMIT).concat("..");
    }
    return id;
  }

  private static boolean isNewException(String exceptionValue, List<DigiDoc4JException> exceptions) {
    for (DigiDoc4JException digiDoc4JException : exceptions){
      if (digiDoc4JException.getMessage().contains(exceptionValue)){
        return false;
      }
    }
    return true;
  }
}
