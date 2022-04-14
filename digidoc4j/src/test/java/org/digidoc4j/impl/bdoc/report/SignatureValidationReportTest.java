/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.report;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.simplereport.jaxb.XmlDetails;
import eu.europa.esig.dss.simplereport.jaxb.XmlMessage;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignature;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignatureLevel;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope;
import org.digidoc4j.impl.asic.report.SignatureValidationReport;
import org.junit.Assert;
import org.junit.Test;

import java.util.Date;

import static java.util.Arrays.asList;
import static org.hamcrest.Matchers.containsInAnyOrder;

public class SignatureValidationReportTest {

  @Test
  public void copyXmlSignatureParameters() throws Exception {
    XmlSignature signature = new XmlSignature();
    Date today = new Date();
    signature.setSigningTime(today);
    signature.setSignedBy("SignedBy");
    signature.setIndication(Indication.TOTAL_PASSED);
    XmlSignatureLevel sigLevel = new XmlSignatureLevel();
    sigLevel.setValue(SignatureQualification.QES);
    sigLevel.setDescription(SignatureQualification.QES.getLabel());
    signature.setSignatureLevel(sigLevel);
    signature.setSubIndication(SubIndication.NO_POE);
    signature.setAdESValidationDetails(new XmlDetails());
    signature.getAdESValidationDetails().getError().addAll(asList(createMessage("AdESError1"), createMessage("AdESError2")));
    signature.getAdESValidationDetails().getWarning().addAll(asList(createMessage("AdESWarning1"), createMessage("AdESWarning2")));
    signature.getAdESValidationDetails().getInfo().addAll(asList(createMessage("AdESInfo1"), createMessage("AdESInfo2")));
    signature.setQualificationDetails(new XmlDetails());
    signature.getQualificationDetails().getError().addAll(asList(createMessage("QError1"), createMessage("QError2")));
    signature.getQualificationDetails().getWarning().addAll(asList(createMessage("QWarning1"), createMessage("QWarning2")));
    signature.getQualificationDetails().getInfo().addAll(asList(createMessage("QInfo1"), createMessage("QInfo2")));
    signature.getSignatureScope().addAll(asList(new XmlSignatureScope()));
    signature.setId("123abc");
    signature.setParentId("Parent ID");
    signature.setSignatureFormat(SignatureLevel.UNKNOWN);
    SignatureValidationReport report = SignatureValidationReport.create(signature);
    Assert.assertEquals(today, report.getSigningTime());
    Assert.assertEquals("SignedBy", report.getSignedBy());
    Assert.assertEquals(Indication.TOTAL_PASSED, report.getIndication());
    Assert.assertEquals("QES", report.getSignatureLevel().getValue().name());
    Assert.assertEquals("QES?", report.getSignatureLevel().getValue().getReadable());
    Assert.assertEquals(SubIndication.NO_POE, report.getSubIndication());
    Assert.assertThat(report.getErrors(), containsInAnyOrder("AdESError1", "AdESError2", "QError1", "QError2"));
    Assert.assertThat(report.getWarnings(), containsInAnyOrder("AdESWarning1", "AdESWarning2", "QWarning1", "QWarning2"));
    Assert.assertThat(report.getInfos(), containsInAnyOrder("AdESInfo1", "AdESInfo2", "QInfo1", "QInfo2"));
    Assert.assertEquals(1, report.getSignatureScope().size());
    Assert.assertEquals("123abc", report.getId());
    Assert.assertEquals(SignatureLevel.UNKNOWN, report.getSignatureFormat());
  }

  private static XmlMessage createMessage(String message) {
    XmlMessage xmlMessage = new XmlMessage();
    xmlMessage.setValue(message);
    return xmlMessage;
  }

}
