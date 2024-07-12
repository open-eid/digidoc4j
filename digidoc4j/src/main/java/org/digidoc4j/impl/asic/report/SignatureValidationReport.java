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

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jaxb.parsers.DateParser;
import eu.europa.esig.dss.simplereport.jaxb.Adapter6;
import eu.europa.esig.dss.simplereport.jaxb.XmlDetails;
import eu.europa.esig.dss.simplereport.jaxb.XmlMessage;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignature;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignatureLevel;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamps;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlSchemaType;
import jakarta.xml.bind.annotation.XmlType;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Stream;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
    "signingTime",
    "bestSignatureTime",
    "signedBy",
    "signatureLevel",
    "signatureScope",
    "documentName"
})
public class SignatureValidationReport extends TokenValidationReport {

  private final static long serialVersionUID = 1L;

  @XmlElement(name = "SigningTime", type = String.class)
  @XmlJavaTypeAdapter(DateParser.class)
  @XmlSchemaType(name = "dateTime")
  protected Date signingTime;

  @XmlElement(name = "BestSignatureTime", required = true, type = String.class)
  @XmlJavaTypeAdapter(DateParser.class)
  @XmlSchemaType(name = "dateTime")
  protected Date bestSignatureTime;

  @XmlElement(name = "SignedBy")
  protected String signedBy;

  @XmlElement(name = "SignatureLevel")
  protected XmlSignatureLevel signatureLevel;

  @XmlElement(name = "SignatureScope")
  protected List<XmlSignatureScope> signatureScope;

  @XmlElement(name = "DocumentName")
  protected String documentName;

  @XmlAttribute(name = "SignatureFormat", required = true)
  @XmlJavaTypeAdapter(Adapter6.class)
  protected SignatureLevel signatureFormat;

  public static SignatureValidationReport create(XmlSignature xmlSignature) {
    SignatureValidationReport report = new SignatureValidationReport();
    report.setSigningTime(xmlSignature.getSigningTime());
    report.setBestSignatureTime(xmlSignature.getBestSignatureTime());
    report.setSignedBy(xmlSignature.getSignedBy());
    report.setIndication(xmlSignature.getIndication());
    report.setSignatureLevel(xmlSignature.getSignatureLevel());
    report.setSubIndication(xmlSignature.getSubIndication());
    report.getErrors().addAll(getSignatureMessages(xmlSignature, XmlDetails::getError));
    report.getWarnings().addAll(getSignatureMessages(xmlSignature, XmlDetails::getWarning));
    report.getInfos().addAll(getSignatureMessages(xmlSignature, XmlDetails::getInfo));
    report.getSignatureScope().addAll(xmlSignature.getSignatureScope());
    report.setId(xmlSignature.getId());
    report.setSignatureFormat(xmlSignature.getSignatureFormat());
    report.setCertificateChain(getCertificateChain(xmlSignature));
    return report;
  }

  static Collection<String> getSignatureMessages(XmlSignature xmlSignature, Function<XmlDetails, List<XmlMessage>> messageListExtractor) {
    final Collection<String> collectedMessages = getTokenMessages(xmlSignature, messageListExtractor);
    Optional.ofNullable(xmlSignature.getTimestamps())
            .map(XmlTimestamps::getTimestamp).map(List::stream).orElseGet(Stream::empty)
            .map(xmlTimestamp -> getTokenMessages(xmlTimestamp, messageListExtractor))
            .forEach(collectedMessages::addAll);
    return collectedMessages;
  }

  public Date getSigningTime() {
    return signingTime;
  }

  public void setSigningTime(Date value) {
    this.signingTime = value;
  }

  public Date getBestSignatureTime() {
    return bestSignatureTime;
  }

  public void setBestSignatureTime(Date value) {
    this.bestSignatureTime = value;
  }

  public String getSignedBy() {
    return signedBy;
  }

  public void setSignedBy(String value) {
    this.signedBy = value;
  }

  public XmlSignatureLevel getSignatureLevel() {
    return signatureLevel;
  }

  public void setSignatureLevel(XmlSignatureLevel value) {
    this.signatureLevel = value;
  }

  public List<XmlSignatureScope> getSignatureScope() {
    if (signatureScope == null) {
      signatureScope = new ArrayList<>();
    }
    return this.signatureScope;
  }

  public String getDocumentName() {
    return documentName;
  }

  public void setDocumentName(String documentName) {
    this.documentName = documentName;
  }

  public SignatureLevel getSignatureFormat() {
    return signatureFormat;
  }

  public void setSignatureFormat(SignatureLevel value) {
    this.signatureFormat = value;
  }

}
