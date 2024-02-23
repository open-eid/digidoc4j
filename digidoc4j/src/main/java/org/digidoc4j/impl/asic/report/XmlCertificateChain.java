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
import java.util.ArrayList;
import java.util.List;

/**
 * DD4J-967:
 * This class is a copy of {@link eu.europa.esig.dss.simplereport.jaxb.XmlCertificateChain} as it was in DSS 5.11.1
 * (except for the migration from {@code javax} to {@code jakarta} namespace and additional
 * {@link #create(eu.europa.esig.dss.simplereport.jaxb.XmlCertificateChain)} method).
 * It is a temporary solution for keeping the XML of the validation report temporarily unchanged.
 * This class may disappear in the future.
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
        "certificate"
})
public class XmlCertificateChain implements Serializable {

  private final static long serialVersionUID = 1L;

  @XmlElement(name = "Certificate")
  protected List<XmlCertificate> certificate;

  static XmlCertificateChain create(eu.europa.esig.dss.simplereport.jaxb.XmlCertificateChain dssCertificateChain) {
    final XmlCertificateChain dd4jCertificateChain = new XmlCertificateChain();
    dssCertificateChain.getCertificate().stream()
            .map(XmlCertificate::create)
            .forEach(dd4jCertificateChain.getCertificate()::add);
    return dd4jCertificateChain;
  }

  public List<XmlCertificate> getCertificate() {
    if (certificate == null) {
      certificate = new ArrayList<>();
    }
    return this.certificate;
  }

}
