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
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.simplereport.jaxb.XmlDetails;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestampLevel;
import org.junit.Test;

import java.util.Date;

import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInRelativeOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;

public class TimestampValidationReportTest extends TokenValidationReportTest {

  @Test
  public void create_WhenXmlTimestampParametersArePresent_TimestampValidationReportWithMatchingParametersIsCreated() {
    XmlTimestamp timestamp = new XmlTimestamp();
    timestamp.setId("123abc");
    timestamp.setCertificateChain(new eu.europa.esig.dss.simplereport.jaxb.XmlCertificateChain());
    timestamp.getCertificateChain().getCertificate().addAll(asList(
            createCertificate("1234", "QName1"),
            createCertificate("5678", "QName2")
    ));
    timestamp.setIndication(Indication.FAILED);
    timestamp.setSubIndication(SubIndication.NO_CERTIFICATE_CHAIN_FOUND);
    timestamp.setAdESValidationDetails(new XmlDetails());
    timestamp.getAdESValidationDetails().getError().addAll(createMessages("AdESError1", "AdESError2"));
    timestamp.getAdESValidationDetails().getWarning().addAll(createMessages("AdESWarning1", "AdESWarning2"));
    timestamp.getAdESValidationDetails().getInfo().addAll(createMessages("AdESInfo1", "AdESInfo2"));
    timestamp.setQualificationDetails(new XmlDetails());
    timestamp.getQualificationDetails().getError().addAll(createMessages("QError1", "QError2"));
    timestamp.getQualificationDetails().getWarning().addAll(createMessages("QWarning1", "QWarning2"));
    timestamp.getQualificationDetails().getInfo().addAll(createMessages("QInfo1", "QInfo2"));
    Date productionTime = new Date();
    timestamp.setProductionTime(productionTime);
    timestamp.setProducedBy("ProducedBy");
    timestamp.setTimestampLevel(new XmlTimestampLevel());
    timestamp.getTimestampLevel().setValue(TimestampQualification.TSA);
    timestamp.getTimestampLevel().setDescription("Description");
    timestamp.getTimestampScope().add(new XmlSignatureScope());
    timestamp.getTimestampScope().get(0).setId("ScopeId");
    timestamp.getTimestampScope().get(0).setScope(SignatureScopeType.DIGEST);
    timestamp.getTimestampScope().get(0).setValue("ScopeValue");
    timestamp.getTimestampScope().get(0).setName("ScopeName");

    TimestampValidationReport report = TimestampValidationReport.create(timestamp);

    assertThat(report.getUniqueId(), equalTo("123abc"));
    assertThat(report.getCertificateChain(), notNullValue(XmlCertificateChain.class));
    assertThat(report.getCertificateChain().getCertificate(), hasSize(2));
    assertThat(report.getCertificateChain().getCertificate().get(0), notNullValue(XmlCertificate.class));
    assertThat(report.getCertificateChain().getCertificate().get(0).getId(), equalTo("1234"));
    assertThat(report.getCertificateChain().getCertificate().get(0).getQualifiedName(), equalTo("QName1"));
    assertThat(report.getCertificateChain().getCertificate().get(1), notNullValue(XmlCertificate.class));
    assertThat(report.getCertificateChain().getCertificate().get(1).getId(), equalTo("5678"));
    assertThat(report.getCertificateChain().getCertificate().get(1).getQualifiedName(), equalTo("QName2"));
    assertThat(report.getIndication(), sameInstance(Indication.FAILED));
    assertThat(report.getSubIndication(), sameInstance(SubIndication.NO_CERTIFICATE_CHAIN_FOUND));
    assertThat(report.getErrors(), hasSize(4));
    assertThat(report.getErrors(), containsInRelativeOrder(
            "AdESError1", "AdESError2", "QError1", "QError2"
    ));
    assertThat(report.getWarnings(), hasSize(4));
    assertThat(report.getWarnings(), containsInRelativeOrder(
            "AdESWarning1", "AdESWarning2", "QWarning1", "QWarning2"
    ));
    assertThat(report.getInfos(), hasSize(4));
    assertThat(report.getInfos(), containsInRelativeOrder(
            "AdESInfo1", "AdESInfo2", "QInfo1", "QInfo2"
    ));
    assertThat(report.getId(), equalTo("123abc"));
    assertThat(report.getProductionTime(), sameInstance(productionTime));
    assertThat(report.getProducedBy(), equalTo("ProducedBy"));
    assertThat(report.getTimestampLevel(), notNullValue(XmlTimestampLevel.class));
    assertThat(report.getTimestampLevel().getValue(), sameInstance(TimestampQualification.TSA));
    assertThat(report.getTimestampLevel().getDescription(), equalTo("Description"));
    assertThat(report.getTimestampScope(), hasSize(1));
    assertThat(report.getTimestampScope().get(0), notNullValue(XmlSignatureScope.class));
    assertThat(report.getTimestampScope().get(0).getId(), equalTo("ScopeId"));
    assertThat(report.getTimestampScope().get(0).getScope(), sameInstance(SignatureScopeType.DIGEST));
    assertThat(report.getTimestampScope().get(0).getValue(), equalTo("ScopeValue"));
    assertThat(report.getTimestampScope().get(0).getName(), equalTo("ScopeName"));
  }

  @Test
  public void create_WhenXmlTimestampParametersNotPresent_TimestampValidationReportWithMissingParametersIsCreated() {
    XmlTimestamp timestamp = new XmlTimestamp();

    TimestampValidationReport report = TimestampValidationReport.create(timestamp);

    assertThat(report.getUniqueId(), nullValue());
    assertThat(report.getCertificateChain(), nullValue());
    assertThat(report.getIndication(), nullValue());
    assertThat(report.getSubIndication(), nullValue());
    assertThat(report.getErrors(), empty());
    assertThat(report.getWarnings(), empty());
    assertThat(report.getInfos(), empty());
    assertThat(report.getId(), nullValue());
    assertThat(report.getProductionTime(), nullValue());
    assertThat(report.getProducedBy(), nullValue());
    assertThat(report.getTimestampLevel(), nullValue());
    assertThat(report.getTimestampScope(), empty());
  }

}
