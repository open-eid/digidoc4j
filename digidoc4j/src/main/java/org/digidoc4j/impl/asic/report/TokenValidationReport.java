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
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.simplereport.jaxb.Adapter3;
import eu.europa.esig.dss.simplereport.jaxb.Adapter4;
import eu.europa.esig.dss.simplereport.jaxb.XmlDetails;
import eu.europa.esig.dss.simplereport.jaxb.XmlMessage;
import eu.europa.esig.dss.simplereport.jaxb.XmlToken;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlType;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
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
    "infos"
})
class TokenValidationReport implements Serializable {

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

  @XmlAttribute(name = "Id", required = true)
  protected String id;

  protected static XmlCertificateChain getCertificateChain(XmlToken xmlToken) {
    return Optional
            .ofNullable(xmlToken.getCertificateChain())
            .map(XmlCertificateChain::create)
            .orElse(null);
  }

  protected static Collection<String> getTokenMessages(XmlToken xmlToken, Function<XmlDetails, List<XmlMessage>> messageListExtractor) {
    final Set<String> collectedMessages = new LinkedHashSet<>();
    Stream.concat(
            Optional.ofNullable(xmlToken.getAdESValidationDetails()).map(Stream::of).orElseGet(Stream::empty),
            Optional.ofNullable(xmlToken.getQualificationDetails()).map(Stream::of).orElseGet(Stream::empty)
    ).flatMap(xmlDetails -> Optional
            .ofNullable(messageListExtractor.apply(xmlDetails)).map(List::stream).orElseGet(Stream::empty)
    ).forEach(xmlMessage -> collectedMessages.add(xmlMessage.getValue()));
    return collectedMessages;
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
    return errors;
  }

  public List<String> getWarnings() {
    if (warnings == null) {
      warnings = new ArrayList<>();
    }
    return warnings;
  }

  public List<String> getInfos() {
    if (infos == null) {
      infos = new ArrayList<>();
    }
    return infos;
  }

  public String getId() {
    return id;
  }

  public void setId(String value) {
    this.id = value;
  }

}
