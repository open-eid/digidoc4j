/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.report;

import eu.europa.esig.dss.jaxb.parsers.DateParser;
import eu.europa.esig.dss.simplereport.jaxb.XmlDetails;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestampLevel;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlSchemaType;
import jakarta.xml.bind.annotation.XmlType;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
        "productionTime",
        "producedBy",
        "timestampLevel",
        "timestampScope"
})
public class TimestampValidationReport extends TokenValidationReport {

  private final static long serialVersionUID = 1L;

  @XmlElement(name = "ProductionTime", required = true, type = String.class)
  @XmlJavaTypeAdapter(DateParser.class)
  @XmlSchemaType(name = "dateTime")
  protected Date productionTime;
  @XmlElement(name = "ProducedBy")
  protected String producedBy;
  @XmlElement(name = "TimestampLevel")
  protected XmlTimestampLevel timestampLevel;
  @XmlElement(name = "TimestampScope")
  protected List<XmlSignatureScope> timestampScope;

  public static TimestampValidationReport create(XmlTimestamp xmlTimestamp) {
    TimestampValidationReport report = new TimestampValidationReport();
    report.setCertificateChain(getCertificateChain(xmlTimestamp));
    report.setIndication(xmlTimestamp.getIndication());
    report.setSubIndication(xmlTimestamp.getSubIndication());
    report.getErrors().addAll(getTokenMessages(xmlTimestamp, XmlDetails::getError));
    report.getWarnings().addAll(getTokenMessages(xmlTimestamp, XmlDetails::getWarning));
    report.getInfos().addAll(getTokenMessages(xmlTimestamp, XmlDetails::getInfo));
    report.setId(xmlTimestamp.getId());
    report.setProductionTime(xmlTimestamp.getProductionTime());
    report.setProducedBy(xmlTimestamp.getProducedBy());
    report.setTimestampLevel(xmlTimestamp.getTimestampLevel());
    report.getTimestampScope().addAll(xmlTimestamp.getTimestampScope());
    return report;
  }

  public Date getProductionTime() {
    return productionTime;
  }

  public void setProductionTime(Date value) {
    this.productionTime = value;
  }

  public String getProducedBy() {
    return producedBy;
  }

  public void setProducedBy(String value) {
    this.producedBy = value;
  }

  public XmlTimestampLevel getTimestampLevel() {
    return timestampLevel;
  }

  public void setTimestampLevel(XmlTimestampLevel value) {
    this.timestampLevel = value;
  }

  public List<XmlSignatureScope> getTimestampScope() {
    if (timestampScope == null) {
      timestampScope = new ArrayList<>();
    }
    return timestampScope;
  }

}
