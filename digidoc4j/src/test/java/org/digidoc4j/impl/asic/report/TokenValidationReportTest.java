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

import eu.europa.esig.dss.simplereport.jaxb.XmlCertificate;
import eu.europa.esig.dss.simplereport.jaxb.XmlMessage;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

abstract class TokenValidationReportTest {

  protected static XmlMessage createMessage(String message) {
    XmlMessage xmlMessage = new XmlMessage();
    xmlMessage.setValue(message);
    return xmlMessage;
  }

  protected static List<XmlMessage> createMessages(String... messages) {
    return Stream.of(messages)
            .map(SignatureValidationReportTest::createMessage)
            .collect(Collectors.toList());
  }

  protected static eu.europa.esig.dss.simplereport.jaxb.XmlCertificate createCertificate(String id, String qualifiedName) {
    eu.europa.esig.dss.simplereport.jaxb.XmlCertificate xmlCertificate = new XmlCertificate();
    xmlCertificate.setId(id);
    xmlCertificate.setQualifiedName(qualifiedName);
    return xmlCertificate;
  }

}
