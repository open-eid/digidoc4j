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

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "")
@XmlRootElement(name = "SimpleReport")
public class ContainerValidationReport extends XmlSimpleReport {

  @XmlElement(name = "Signature")
  protected List<SignatureValidationReport> signatures;
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
      signatures = new ArrayList<SignatureValidationReport>();
    }
    return this.signatures;
  }

  public void setSignatures(List<SignatureValidationReport> signatures) {
    this.signatures = signatures;
  }
}
