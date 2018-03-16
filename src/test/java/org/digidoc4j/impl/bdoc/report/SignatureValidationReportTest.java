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

import static java.util.Arrays.asList;
import static org.hamcrest.Matchers.containsInAnyOrder;

import java.util.Date;

import org.digidoc4j.impl.asic.report.SignatureValidationReport;
import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.jaxb.simplereport.XmlSignature;
import eu.europa.esig.dss.jaxb.simplereport.XmlSignatureLevel;
import eu.europa.esig.dss.jaxb.simplereport.XmlSignatureScope;
import eu.europa.esig.dss.validation.SignatureQualification;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;

public class SignatureValidationReportTest {

  @Test
  public void copyXmlSignatureParameters() throws Exception {
    XmlSignature signature = new XmlSignature();
    Date today = new Date();
    signature.setSigningTime(today);
    signature.setSignedBy("SignedBy");
    signature.setIndication(Indication.TOTAL_PASSED);
    // TODO: check and test XmlSignatureLevel usage
    XmlSignatureLevel sigLevel = new XmlSignatureLevel();
    sigLevel.setValue(SignatureQualification.QES);
    sigLevel.setDescription(SignatureQualification.QES.getLabel());
    signature.setSignatureLevel(sigLevel);
    signature.setSubIndication(SubIndication.NO_POE);
    signature.getErrors().addAll(asList("Error1", "Error2"));
    signature.getWarnings().addAll(asList("Warning1", "Warning2"));
    signature.getInfos().addAll(asList("Info1", "Info2"));
    signature.getSignatureScope().addAll(asList(new XmlSignatureScope()));
    signature.setId("123abc");
    //TODO not in use DSS 5.2
    //signature.setType("Type");
    signature.setParentId("Parent ID");
    signature.setSignatureFormat("Format");
    SignatureValidationReport report = SignatureValidationReport.create(signature);
    Assert.assertEquals(today, report.getSigningTime());
    Assert.assertEquals("SignedBy", report.getSignedBy());
    Assert.assertEquals(Indication.TOTAL_PASSED, report.getIndication());
    Assert.assertEquals("QES", report.getSignatureLevel().getValue().name());
    Assert.assertEquals("QES?", report.getSignatureLevel().getValue().getReadable());
    Assert.assertEquals(SubIndication.NO_POE, report.getSubIndication());
    Assert.assertThat(report.getErrors(), containsInAnyOrder("Error1", "Error2"));
    Assert.assertThat(report.getWarnings(), containsInAnyOrder("Warning1", "Warning2"));
    Assert.assertThat(report.getInfos(), containsInAnyOrder("Info1", "Info2"));
    Assert.assertEquals(1, report.getSignatureScope().size());
    Assert.assertEquals("123abc", report.getId());
    //TODO not in use DSS 5.2
    //Assert.assertEquals("Type", report.getType());
    Assert.assertEquals("Parent ID", report.getParentId());
    Assert.assertEquals("Format", report.getSignatureFormat());
  }

}
