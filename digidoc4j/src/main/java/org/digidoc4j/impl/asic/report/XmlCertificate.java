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

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlType;

import java.io.Serializable;

/**
 * DD4J-967:
 * This class is a copy of {@link eu.europa.esig.dss.simplereport.jaxb.XmlCertificate} as it was in DSS 5.11.1
 * (except for the migration from {@code javax} to {@code jakarta} namespace and additional
 * {@link #create(eu.europa.esig.dss.simplereport.jaxb.XmlCertificate)} method).
 * It is a temporary solution for keeping the XML of the validation report temporarily unchanged.
 * This class may disappear in the future.
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
        "id",
        "qualifiedName"
})
public class XmlCertificate implements Serializable {

  private final static long serialVersionUID = 1L;

  @XmlElement(required = true)
  protected String id;

  @XmlElement(required = true)
  protected String qualifiedName;

  static XmlCertificate create(eu.europa.esig.dss.simplereport.jaxb.XmlCertificate dssCertificate) {
      XmlCertificate dd4jCertificate = new XmlCertificate();
      dd4jCertificate.setId(dssCertificate.getId());
      dd4jCertificate.setQualifiedName(dssCertificate.getQualifiedName());
      return dd4jCertificate;
  }

  public String getId() {
    return id;
  }

  public void setId(String value) {
    this.id = value;
  }

  public String getQualifiedName() {
    return qualifiedName;
  }

  public void setQualifiedName(String value) {
    this.qualifiedName = value;
  }

}
