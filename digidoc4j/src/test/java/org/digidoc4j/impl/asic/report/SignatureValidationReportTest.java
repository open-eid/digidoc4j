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
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.simplereport.jaxb.XmlCertificateChain;
import eu.europa.esig.dss.simplereport.jaxb.XmlDetails;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignature;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignatureLevel;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamps;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInRelativeOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

public class SignatureValidationReportTest extends TokenValidationReportTest {

  @Test
  public void create_WhenXmlSignatureParametersArePresent_SignatureValidationReportWithMatchingParametersIsCreated() {
    XmlSignature signature = new XmlSignature();
    Date today = new Date();
    signature.setSigningTime(today);
    signature.setBestSignatureTime(today);
    signature.setSignedBy("SignedBy");
    signature.setIndication(Indication.TOTAL_PASSED);
    XmlSignatureLevel sigLevel = new XmlSignatureLevel();
    sigLevel.setValue(SignatureQualification.QESIG);
    sigLevel.setDescription(SignatureQualification.QESIG.getLabel());
    signature.setSignatureLevel(sigLevel);
    signature.setSubIndication(SubIndication.NO_POE);
    signature.setAdESValidationDetails(new XmlDetails());
    signature.getAdESValidationDetails().getError().addAll(createMessages("AdESError1", "AdESError2"));
    signature.getAdESValidationDetails().getWarning().addAll(createMessages("AdESWarning1", "AdESWarning2"));
    signature.getAdESValidationDetails().getInfo().addAll(createMessages("AdESInfo1", "AdESInfo2"));
    signature.setQualificationDetails(new XmlDetails());
    signature.getQualificationDetails().getError().addAll(createMessages("QError1", "QError2"));
    signature.getQualificationDetails().getWarning().addAll(createMessages("QWarning1", "QWarning2"));
    signature.getQualificationDetails().getInfo().addAll(createMessages("QInfo1", "QInfo2"));
    signature.getSignatureScope().add(new XmlSignatureScope());
    signature.setId("123abc");
    signature.setParentId("Parent ID");
    signature.setTimestamps(new XmlTimestamps());
    signature.getTimestamps().getTimestamp().add(new XmlTimestamp());
    signature.getTimestamps().getTimestamp().get(0).setAdESValidationDetails(new XmlDetails());
    signature.getTimestamps().getTimestamp().get(0).getAdESValidationDetails().getError().add(createMessage("TsAdESError"));
    signature.getTimestamps().getTimestamp().get(0).getAdESValidationDetails().getWarning().add(createMessage("TsAdESWarning"));
    signature.getTimestamps().getTimestamp().get(0).getAdESValidationDetails().getInfo().add(createMessage("TsAdESInfo"));
    signature.getTimestamps().getTimestamp().get(0).setQualificationDetails(new XmlDetails());
    signature.getTimestamps().getTimestamp().get(0).getQualificationDetails().getError().add(createMessage("TsQError"));
    signature.getTimestamps().getTimestamp().get(0).getQualificationDetails().getWarning().add(createMessage("TsQWarning"));
    signature.getTimestamps().getTimestamp().get(0).getQualificationDetails().getInfo().add(createMessage("TsQInfo"));
    signature.setSignatureFormat(SignatureLevel.UNKNOWN);
    signature.setCertificateChain(new XmlCertificateChain());
    signature.getCertificateChain().getCertificate().addAll(asList(
            createCertificate("1234", "QName1"),
            createCertificate("5678", "QName2")
    ));

    SignatureValidationReport report = SignatureValidationReport.create(signature);

    assertThat(report.getSigningTime(), equalTo(today));
    assertThat(report.getBestSignatureTime(), equalTo(today));
    assertThat(report.getSignedBy(), equalTo("SignedBy"));
    assertThat(report.getIndication(), equalTo(Indication.TOTAL_PASSED));
    assertThat(report.getSignatureLevel(), notNullValue(XmlSignatureLevel.class));
    assertThat(report.getSignatureLevel().getValue(), equalTo(SignatureQualification.QESIG));
    assertThat(report.getSignatureLevel().getDescription(), equalTo(SignatureQualification.QESIG.getLabel()));
    assertThat(report.getSubIndication(), equalTo(SubIndication.NO_POE));
    assertThat(report.getErrors(), hasSize(6));
    assertThat(report.getErrors(), containsInRelativeOrder(
            "AdESError1", "AdESError2", "QError1", "QError2",
            "TsAdESError", "TsQError"
    ));
    assertThat(report.getWarnings(), hasSize(6));
    assertThat(report.getWarnings(), containsInRelativeOrder(
            "AdESWarning1", "AdESWarning2", "QWarning1", "QWarning2",
            "TsAdESWarning", "TsQWarning"
    ));
    assertThat(report.getInfos(), hasSize(6));
    assertThat(report.getInfos(), containsInRelativeOrder(
            "AdESInfo1", "AdESInfo2", "QInfo1", "QInfo2",
            "TsAdESInfo", "TsQInfo"
    ));
    assertThat(report.getSignatureScope(), hasSize(1));
    assertThat(report.getId(), equalTo("123abc"));
    assertThat(report.getSignatureFormat(), equalTo(SignatureLevel.UNKNOWN));
    assertThat(report.getCertificateChain(), notNullValue(org.digidoc4j.impl.asic.report.XmlCertificateChain.class));
    assertThat(report.getCertificateChain().getCertificate(), hasSize(2));
    assertThat(report.getCertificateChain().getCertificate().get(0), notNullValue(org.digidoc4j.impl.asic.report.XmlCertificate.class));
    assertThat(report.getCertificateChain().getCertificate().get(0).getId(), equalTo("1234"));
    assertThat(report.getCertificateChain().getCertificate().get(0).getQualifiedName(), equalTo("QName1"));
    assertThat(report.getCertificateChain().getCertificate().get(1), notNullValue(org.digidoc4j.impl.asic.report.XmlCertificate.class));
    assertThat(report.getCertificateChain().getCertificate().get(1).getId(), equalTo("5678"));
    assertThat(report.getCertificateChain().getCertificate().get(1).getQualifiedName(), equalTo("QName2"));
  }

  @Test
  public void create_WhenXmlSignatureParametersNotPresent_SignatureValidationReportWithMissingParametersIsCreated() {
    XmlSignature signature = new XmlSignature();

    SignatureValidationReport report = SignatureValidationReport.create(signature);

    assertThat(report.getSigningTime(), nullValue());
    assertThat(report.getBestSignatureTime(), nullValue());
    assertThat(report.getSignedBy(), nullValue());
    assertThat(report.getIndication(), nullValue());
    assertThat(report.getSignatureLevel(), nullValue());
    assertThat(report.getSubIndication(), nullValue());
    assertThat(report.getErrors(), empty());
    assertThat(report.getWarnings(), empty());
    assertThat(report.getInfos(), empty());
    assertThat(report.getSignatureScope(), empty());
    assertThat(report.getId(), nullValue());
    assertThat(report.getSignatureFormat(), nullValue());
    assertThat(report.getCertificateChain(), nullValue());
  }

}
