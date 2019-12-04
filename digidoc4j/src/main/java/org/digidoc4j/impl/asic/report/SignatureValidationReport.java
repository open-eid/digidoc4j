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

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

import eu.europa.esig.dss.simplereport.jaxb.XmlSignature;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "")
public class SignatureValidationReport extends XmlSignature {

  @XmlElement(name = "DocumentName")
  protected String documentName;

  public static SignatureValidationReport create(XmlSignature xmlSignature) {
    SignatureValidationReport report = new SignatureValidationReport();
    report.setSigningTime(xmlSignature.getSigningTime());
    report.setSignedBy(xmlSignature.getSignedBy());
    report.setIndication(xmlSignature.getIndication());
    report.setSignatureLevel(xmlSignature.getSignatureLevel());
    report.setSubIndication(xmlSignature.getSubIndication());
    report.getErrors().addAll(xmlSignature.getErrors());
    report.getWarnings().addAll(xmlSignature.getWarnings());
    report.getInfos().addAll(xmlSignature.getInfos());
    report.getSignatureScope().addAll(xmlSignature.getSignatureScope());
    report.setId(xmlSignature.getId());
    //TODO not in use in DSS 5.2
    //report.setType(xmlSignature.getType());
    report.setParentId(xmlSignature.getParentId());
    report.setSignatureFormat(xmlSignature.getSignatureFormat());
    report.setCertificateChain(xmlSignature.getCertificateChain());
    return report;
  }

  public String getDocumentName() {
    return documentName;
  }

  public void setDocumentName(String documentName) {
    this.documentName = documentName;
  }
}
