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
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.simplereport.jaxb.XmlCertificate;
import eu.europa.esig.dss.simplereport.jaxb.XmlCertificateChain;
import eu.europa.esig.dss.simplereport.jaxb.XmlDetails;
import eu.europa.esig.dss.simplereport.jaxb.XmlMessage;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignature;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignatureLevel;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestampLevel;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamps;
import org.digidoc4j.impl.asic.report.SignatureValidationReport;
import org.junit.Assert;
import org.junit.Test;

import java.util.Date;
import java.util.List;

import static java.util.Arrays.asList;

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
    XmlTimestamp timestamp = new XmlTimestamp();
    XmlCertificate timestampCertificate = new XmlCertificate();
    timestampCertificate.setId("TimestampCertificateId");
    timestampCertificate.setQualifiedName("Time-stamp certificate qualified name");
    XmlCertificateChain timestampCertificateChain = new XmlCertificateChain();
    timestampCertificateChain.getCertificate().add(timestampCertificate);
    timestamp.setCertificateChain(timestampCertificateChain);
    timestamp.setIndication(Indication.INDETERMINATE);
    timestamp.setSubIndication(SubIndication.TRY_LATER);
    timestamp.setAdESValidationDetails(new XmlDetails());
    timestamp.getAdESValidationDetails().getError().addAll(asList(createMessage("AdESErrorTs1"), createMessage("AdESErrorTs2")));
    timestamp.getAdESValidationDetails().getWarning().addAll(asList(createMessage("AdESWarningTs1"), createMessage("AdESWarningTs2")));
    timestamp.getAdESValidationDetails().getInfo().addAll(asList(createMessage("AdESInfoTs1"), createMessage("AdESInfoTs2")));
    timestamp.setQualificationDetails(new XmlDetails());
    timestamp.getQualificationDetails().getError().addAll(asList(createMessage("QErrorTs1"), createMessage("QErrorTs2")));
    timestamp.getQualificationDetails().getWarning().addAll(asList(createMessage("QWarningTs1"), createMessage("QWarningTs2")));
    timestamp.getQualificationDetails().getInfo().addAll(asList(createMessage("QInfoTs1"), createMessage("QInfoTs2")));
    timestamp.setId("456def");
    timestamp.setProductionTime(today);
    timestamp.setProducedBy("ProducedBy");
    XmlTimestampLevel timestampLevel = new XmlTimestampLevel();
    timestampLevel.setValue(TimestampQualification.NA);
    timestampLevel.setDescription("Some time-stamp level");
    timestamp.setTimestampLevel(timestampLevel);
    XmlTimestamps timestamps = new XmlTimestamps();
    timestamps.getTimestamp().add(timestamp);
    signature.setTimestamps(timestamps);

    SignatureValidationReport report = SignatureValidationReport.create(signature);

    Assert.assertEquals(today, report.getSigningTime());
    Assert.assertEquals("SignedBy", report.getSignedBy());
    Assert.assertEquals(Indication.TOTAL_PASSED, report.getIndication());
    Assert.assertEquals("QES", report.getSignatureLevel().getValue().name());
    Assert.assertEquals("QES?", report.getSignatureLevel().getValue().getReadable());
    Assert.assertEquals(SubIndication.NO_POE, report.getSubIndication());
    Assert.assertNotSame(signature.getAdESValidationDetails(), report.getAdESValidationDetails());
    assertMessages(report.getAdESValidationDetails().getError(), createMessage("AdESError1"), createMessage("AdESError2"));
    assertMessages(report.getAdESValidationDetails().getWarning(), createMessage("AdESWarning1"), createMessage("AdESWarning2"));
    assertMessages(report.getAdESValidationDetails().getInfo(), createMessage("AdESInfo1"), createMessage("AdESInfo2"));
    Assert.assertNotSame(signature.getQualificationDetails(), report.getQualificationDetails());
    assertMessages(report.getQualificationDetails().getError(), createMessage("QError1"), createMessage("QError2"));
    assertMessages(report.getQualificationDetails().getWarning(), createMessage("QWarning1"), createMessage("QWarning2"));
    assertMessages(report.getQualificationDetails().getInfo(), createMessage("QInfo1"), createMessage("QInfo2"));
    Assert.assertEquals(1, report.getSignatureScope().size());
    Assert.assertEquals("123abc", report.getId());
    Assert.assertEquals("Parent ID", report.getParentId());
    Assert.assertEquals(SignatureLevel.UNKNOWN, report.getSignatureFormat());
    Assert.assertNotNull(report.getTimestamps());
    Assert.assertNotNull(report.getTimestamps().getTimestamp());
    Assert.assertEquals(1, report.getTimestamps().getTimestamp().size());
    Assert.assertNotNull(report.getTimestamps().getTimestamp().get(0));
    Assert.assertNotNull(report.getTimestamps().getTimestamp().get(0).getCertificateChain());
    Assert.assertNotNull(report.getTimestamps().getTimestamp().get(0).getCertificateChain().getCertificate());
    Assert.assertEquals(1, report.getTimestamps().getTimestamp().get(0).getCertificateChain().getCertificate().size());
    Assert.assertNotNull(report.getTimestamps().getTimestamp().get(0).getCertificateChain().getCertificate().get(0));
    Assert.assertEquals("TimestampCertificateId", report.getTimestamps().getTimestamp().get(0).getCertificateChain().getCertificate().get(0).getId());
    Assert.assertEquals("Time-stamp certificate qualified name", report.getTimestamps().getTimestamp().get(0).getCertificateChain().getCertificate().get(0).getQualifiedName());
    Assert.assertEquals(Indication.INDETERMINATE, report.getTimestamps().getTimestamp().get(0).getIndication());
    Assert.assertEquals(SubIndication.TRY_LATER, report.getTimestamps().getTimestamp().get(0).getSubIndication());
    Assert.assertNotSame(signature.getTimestamps().getTimestamp().get(0).getAdESValidationDetails(), report.getTimestamps().getTimestamp().get(0).getAdESValidationDetails());
    assertMessages(report.getTimestamps().getTimestamp().get(0).getAdESValidationDetails().getError(), createMessage("AdESErrorTs1"), createMessage("AdESErrorTs2"));
    assertMessages(report.getTimestamps().getTimestamp().get(0).getAdESValidationDetails().getWarning(), createMessage("AdESWarningTs1"), createMessage("AdESWarningTs2"));
    assertMessages(report.getTimestamps().getTimestamp().get(0).getAdESValidationDetails().getInfo(), createMessage("AdESInfoTs1"), createMessage("AdESInfoTs2"));
    Assert.assertNotSame(signature.getTimestamps().getTimestamp().get(0).getQualificationDetails(), report.getTimestamps().getTimestamp().get(0).getQualificationDetails());
    assertMessages(report.getTimestamps().getTimestamp().get(0).getQualificationDetails().getError(), createMessage("QErrorTs1"), createMessage("QErrorTs2"));
    assertMessages(report.getTimestamps().getTimestamp().get(0).getQualificationDetails().getWarning(), createMessage("QWarningTs1"), createMessage("QWarningTs2"));
    assertMessages(report.getTimestamps().getTimestamp().get(0).getQualificationDetails().getInfo(), createMessage("QInfoTs1"), createMessage("QInfoTs2"));
    Assert.assertEquals("456def", report.getTimestamps().getTimestamp().get(0).getId());
    Assert.assertEquals(today, report.getTimestamps().getTimestamp().get(0).getProductionTime());
    Assert.assertEquals("ProducedBy", report.getTimestamps().getTimestamp().get(0).getProducedBy());
    Assert.assertNotNull(report.getTimestamps().getTimestamp().get(0).getTimestampLevel());
    Assert.assertEquals(TimestampQualification.NA, report.getTimestamps().getTimestamp().get(0).getTimestampLevel().getValue());
    Assert.assertEquals("Some time-stamp level", report.getTimestamps().getTimestamp().get(0).getTimestampLevel().getDescription());
  }

  private static XmlMessage createMessage(String prefix) {
    return createMessage(prefix + "Key", prefix + "Value");
  }

  private static XmlMessage createMessage(String key, String value) {
    XmlMessage xmlMessage = new XmlMessage();
    xmlMessage.setKey(key);
    xmlMessage.setValue(value);
    return xmlMessage;
  }

  private static void assertMessages(List<XmlMessage> actualMessages, XmlMessage... expectedMessages) {
    Assert.assertEquals(expectedMessages.length, actualMessages.size());
    for (int i = 0; i < expectedMessages.length; ++i) {
      if (expectedMessages[i] == null) {
        Assert.assertNull(actualMessages.get(i));
        continue;
      }
      Assert.assertNotNull(actualMessages.get(i));
      Assert.assertEquals(expectedMessages[i].getKey(), actualMessages.get(i).getKey());
      Assert.assertEquals(expectedMessages[i].getValue(), actualMessages.get(i).getValue());
    }
  }

}
