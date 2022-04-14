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

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.simplereport.jaxb.Adapter1;
import eu.europa.esig.dss.simplereport.jaxb.Adapter3;
import eu.europa.esig.dss.simplereport.jaxb.Adapter4;
import eu.europa.esig.dss.simplereport.jaxb.Adapter6;
import eu.europa.esig.dss.simplereport.jaxb.XmlCertificateChain;
import eu.europa.esig.dss.simplereport.jaxb.XmlDetails;
import eu.europa.esig.dss.simplereport.jaxb.XmlMessage;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignature;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignatureLevel;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamps;
import eu.europa.esig.dss.simplereport.jaxb.XmlToken;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
    "certificateChain",
    "indication",
    "subIndication",
    "errors",
    "warnings",
    "infos",
    "signingTime",
    "bestSignatureTime",
    "signedBy",
    "signatureLevel",
    "signatureScope",
    "documentName"
})
public class SignatureValidationReport implements Serializable {

  private final static long serialVersionUID = 1L;

  @XmlElement(name = "CertificateChain")
  protected XmlCertificateChain certificateChain;

  @XmlElement(name = "Indication", required = true, type = String.class)
  @XmlJavaTypeAdapter(Adapter3.class)
  protected Indication indication;

  @XmlElement(name = "SubIndication", type = String.class)
  @XmlJavaTypeAdapter(Adapter4.class)
  protected SubIndication subIndication;

  @XmlElement(name = "Errors")
  protected List<String> errors;

  @XmlElement(name = "Warnings")
  protected List<String> warnings;

  @XmlElement(name = "Infos")
  protected List<String> infos;

  @XmlElement(name = "SigningTime", type = String.class)
  @XmlJavaTypeAdapter(Adapter1.class)
  @XmlSchemaType(name = "dateTime")
  protected Date signingTime;

  @XmlElement(name = "BestSignatureTime", required = true, type = String.class)
  @XmlJavaTypeAdapter(Adapter1 .class)
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

  @XmlAttribute(name = "Id", required = true)
  protected String id;

  public static SignatureValidationReport create(XmlSignature xmlSignature) {
    SignatureValidationReport report = new SignatureValidationReport();
    report.setSigningTime(xmlSignature.getSigningTime());
    report.setSignedBy(xmlSignature.getSignedBy());
    report.setIndication(xmlSignature.getIndication());
    report.setSignatureLevel(xmlSignature.getSignatureLevel());
    report.setSubIndication(xmlSignature.getSubIndication());
    report.getErrors().addAll(getAllMessages(xmlSignature, XmlDetails::getError));
    report.getWarnings().addAll(getAllMessages(xmlSignature, XmlDetails::getWarning));
    report.getInfos().addAll(getAllMessages(xmlSignature, XmlDetails::getInfo));
    report.getSignatureScope().addAll(xmlSignature.getSignatureScope());
    report.setId(xmlSignature.getId());
    report.setSignatureFormat(xmlSignature.getSignatureFormat());
    report.setCertificateChain(xmlSignature.getCertificateChain());
    return report;
  }

  static List<String> getAllMessages(XmlToken xmlToken, Function<XmlDetails, List<XmlMessage>> messageListExtractor) {
    final Set<String> allMessages = new LinkedHashSet<>();
    Stream.concat(
            Optional.ofNullable(xmlToken.getAdESValidationDetails()).map(Stream::of).orElseGet(Stream::empty),
            Optional.ofNullable(xmlToken.getQualificationDetails()).map(Stream::of).orElseGet(Stream::empty)
    ).flatMap(xmlDetails -> Optional
            .ofNullable(messageListExtractor.apply(xmlDetails)).map(List::stream).orElseGet(Stream::empty)
    ).forEach(xmlMessage -> allMessages.add(xmlMessage.getValue()));
    if (xmlToken instanceof XmlSignature) {
      Optional.ofNullable(((XmlSignature) xmlToken).getTimestamps())
              .map(XmlTimestamps::getTimestamp).map(List::stream).orElseGet(Stream::empty)
              .map(xmlTimestamp -> getAllMessages(xmlTimestamp, messageListExtractor))
              .forEach(allMessages::addAll);
    }
    return new ArrayList<>(allMessages);
  }

  public XmlCertificateChain getCertificateChain() {
    return certificateChain;
  }

  public void setCertificateChain(XmlCertificateChain value) {
    this.certificateChain = value;
  }

  public Indication getIndication() {
    return indication;
  }

  public void setIndication(Indication value) {
    this.indication = value;
  }

  public SubIndication getSubIndication() {
    return subIndication;
  }

  public void setSubIndication(SubIndication value) {
    this.subIndication = value;
  }

  public List<String> getErrors() {
    if (errors == null) {
      errors = new ArrayList<>();
    }
    return this.errors;
  }

  public List<String> getWarnings() {
    if (warnings == null) {
      warnings = new ArrayList<>();
    }
    return this.warnings;
  }

  public List<String> getInfos() {
    if (infos == null) {
      infos = new ArrayList<>();
    }
    return this.infos;
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

  public String getId() {
    return id;
  }

  public void setId(String value) {
    this.id = value;
  }

}
