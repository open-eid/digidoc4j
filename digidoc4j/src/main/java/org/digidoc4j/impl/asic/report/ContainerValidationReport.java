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

import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlType;

import java.util.ArrayList;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "")
@XmlRootElement(name = "SimpleReport")
public class ContainerValidationReport extends XmlSimpleReport {

  @XmlElement(name = "Signature")
  protected List<SignatureValidationReport> signatures;
  @XmlElement(name = "TimestampToken")
  protected List<TimestampValidationReport> timestampTokens;
  @XmlElement(name = "ContainerError")
  protected List<String> containerErrors;

  public List<String> getContainerErrors() {
    return containerErrors;
  }

  public void setContainerErrors(List<String> containerErrors) {
    this.containerErrors = containerErrors;
  }

  public List<SignatureValidationReport> getSignatures() {
    if (signatures == null) {
      signatures = new ArrayList<>();
    }
    return signatures;
  }

  public void setSignatures(List<SignatureValidationReport> signatures) {
    this.signatures = signatures;
  }

  public List<TimestampValidationReport> getTimestampTokens() {
    if (timestampTokens == null) {
      timestampTokens = new ArrayList<>();
    }
    return timestampTokens;
  }

  public void setTimestampTokens(List<TimestampValidationReport> timestampTokens) {
    this.timestampTokens = timestampTokens;
  }

}
