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

import eu.europa.esig.dss.simplereport.jaxb.XmlCertificate;
import eu.europa.esig.dss.simplereport.jaxb.XmlCertificateChain;
import eu.europa.esig.dss.simplereport.jaxb.XmlDetails;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignature;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamps;
import eu.europa.esig.dss.simplereport.jaxb.XmlToken;
import org.apache.commons.collections4.CollectionUtils;

import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "")
public class SignatureValidationReport extends XmlSignature {

  @XmlElement(name = "DocumentName")
  protected String documentName;

  public static SignatureValidationReport create(XmlSignature xmlSignature) {
    SignatureValidationReport report = new SignatureValidationReport();
    copyXmlTokenProperties(xmlSignature, report);
    report.setSigningTime(xmlSignature.getSigningTime());
    report.setSignedBy(xmlSignature.getSignedBy());
    report.setSignatureLevel(xmlSignature.getSignatureLevel());
    report.getSignatureScope().addAll(xmlSignature.getSignatureScope());
    report.setTimestamps(createXmlTimestampsIfNeeded(xmlSignature.getTimestamps()));
    report.setParentId(xmlSignature.getParentId());
    report.setSignatureFormat(xmlSignature.getSignatureFormat());
    return report;
  }

  public String getDocumentName() {
    return documentName;
  }

  public void setDocumentName(String documentName) {
    this.documentName = documentName;
  }

  private static void copyXmlTokenProperties(XmlToken sourceXmlToken, XmlToken destXmlToken) {
    destXmlToken.setCertificateChain(createXmlCertificateChainIfNeeded(sourceXmlToken.getCertificateChain()));
    destXmlToken.setIndication(sourceXmlToken.getIndication());
    destXmlToken.setSubIndication(sourceXmlToken.getSubIndication());
    destXmlToken.setAdESValidationDetails(createXmlDetailsIfNeeded(sourceXmlToken.getAdESValidationDetails()));
    destXmlToken.setQualificationDetails(createXmlDetailsIfNeeded(sourceXmlToken.getQualificationDetails()));
    destXmlToken.setId(sourceXmlToken.getId());
  }

  private static XmlCertificateChain createXmlCertificateChainIfNeeded(XmlCertificateChain xmlCertificateChain) {
    XmlCertificateChain newXmlCertificateChain = null;
    if (xmlCertificateChain != null && CollectionUtils.isNotEmpty(xmlCertificateChain.getCertificate())) {
      for (XmlCertificate xmlCertificate : xmlCertificateChain.getCertificate()) {
        XmlCertificate newXmlCertificate = createXmlCertificateIfNeeded(xmlCertificate);
        if (newXmlCertificate == null) {
          continue;
        } else if (newXmlCertificateChain == null) {
          newXmlCertificateChain = new XmlCertificateChain();
        }
        newXmlCertificateChain.getCertificate().add(newXmlCertificate);
      }
    }
    return newXmlCertificateChain;
  }

  private static XmlCertificate createXmlCertificateIfNeeded(XmlCertificate xmlCertificate) {
    XmlCertificate newXmlCertificate = null;
    if (xmlCertificate != null) {
      newXmlCertificate = new XmlCertificate();
      newXmlCertificate.setId(xmlCertificate.getId());
      newXmlCertificate.setQualifiedName(xmlCertificate.getQualifiedName());
    }
    return newXmlCertificate;
  }

  private static XmlDetails createXmlDetailsIfNeeded(XmlDetails xmlDetails) {
    XmlDetails newXmlDetails = null;
    if (xmlDetails != null) {
      if (CollectionUtils.isNotEmpty(xmlDetails.getError())) {
        newXmlDetails = new XmlDetails();
        newXmlDetails.getError().addAll(xmlDetails.getError());
      }
      if (CollectionUtils.isNotEmpty(xmlDetails.getWarning())) {
        if (newXmlDetails == null) newXmlDetails = new XmlDetails();
        newXmlDetails.getWarning().addAll(xmlDetails.getWarning());
      }
      if (CollectionUtils.isNotEmpty(xmlDetails.getInfo())) {
        if (newXmlDetails == null) newXmlDetails = new XmlDetails();
        newXmlDetails.getInfo().addAll(xmlDetails.getInfo());
      }
    }
    return newXmlDetails;
  }

  private static XmlTimestamps createXmlTimestampsIfNeeded(XmlTimestamps xmlTimestamps) {
    XmlTimestamps newXmlTimestamps = null;
    if (xmlTimestamps != null) {
      List<XmlTimestamp> xmlTimestampList = xmlTimestamps.getTimestamp();
      if (CollectionUtils.isNotEmpty(xmlTimestampList)) {
        for (XmlTimestamp xmlTimestamp : xmlTimestampList) {
          XmlTimestamp newXmlTimestamp = createXmlTimestampIfNeeded(xmlTimestamp);
          if (newXmlTimestamp == null) {
            continue;
          } else if (newXmlTimestamps == null) {
            newXmlTimestamps = new XmlTimestamps();
          }
          newXmlTimestamps.getTimestamp().add(newXmlTimestamp);
        }
      }
    }
    return newXmlTimestamps;
  }

  private static XmlTimestamp createXmlTimestampIfNeeded(XmlTimestamp xmlTimestamp) {
    XmlTimestamp newXmlTimestamp = null;
    if (xmlTimestamp != null) {
      newXmlTimestamp = new XmlTimestamp();
      copyXmlTokenProperties(xmlTimestamp, newXmlTimestamp);
      newXmlTimestamp.setProductionTime(xmlTimestamp.getProductionTime());
      newXmlTimestamp.setProducedBy(xmlTimestamp.getProducedBy());
      newXmlTimestamp.setTimestampLevel(xmlTimestamp.getTimestampLevel());
    }
    return newXmlTimestamp;
  }

}
