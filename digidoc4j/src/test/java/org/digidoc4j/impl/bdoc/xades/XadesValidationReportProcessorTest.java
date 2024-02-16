/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.bdoc.xades;

import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.simplereport.jaxb.XmlDetails;
import eu.europa.esig.dss.simplereport.jaxb.XmlMessage;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignature;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamps;
import eu.europa.esig.dss.simplereport.jaxb.XmlToken;
import eu.europa.esig.dss.validation.reports.Reports;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.impl.asic.xades.XadesValidationReportProcessor;
import org.digidoc4j.test.matcher.IsSimpleReportXmlMessage;
import org.hamcrest.Matcher;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInRelativeOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.Mockito.doReturn;

public class XadesValidationReportProcessorTest {

  private static final I18nProvider i18nProvider = new I18nProvider();

  @Test
  public void process_WhenSignatureContainsOrganizationNameMissingWarnings_WarningsRemoved() {
    XmlSignature signature = new MockSignatureBuilder()
            .adesValidationDetails(b -> b.warnings(
                    MessageTag.BBB_XCV_ISSSC_ANS,
                    MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1
            ))
            .qualificationDetails(b -> b.warnings(
                    MessageTag.QUAL_HAS_CONSISTENT_BY_QC_ANS,
                    MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1
            ))
            .build();

    Reports validationReports = mockReports(signature);
    assertThat(signature.getAdESValidationDetails().getWarning(), hasSize(2));
    assertThat(signature.getAdESValidationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.BBB_XCV_ISSSC_ANS),
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1)
    ));
    assertThat(signature.getQualificationDetails().getWarning(), hasSize(2));
    assertThat(signature.getQualificationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_CONSISTENT_BY_QC_ANS),
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1)
    ));

    XadesValidationReportProcessor.process(validationReports);

    assertThat(signature.getAdESValidationDetails().getWarning(), hasSize(1));
    assertThat(signature.getAdESValidationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.BBB_XCV_ISSSC_ANS)
    ));
    assertThat(signature.getQualificationDetails().getWarning(), hasSize(1));
    assertThat(signature.getQualificationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_CONSISTENT_BY_QC_ANS)
    ));
  }

  @Test
  public void process_WhenTimestampContainsOrganizationNameMissingWarnings_WarningsRemoved() {
    XmlTimestamp timestamp = new MockTimestampBuilder()
            .adesValidationDetails(b -> b.warnings(
                    MessageTag.ADEST_IBSVPTC_ANS,
                    MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1
            ))
            .qualificationDetails(b -> b.warnings(
                    MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD_ANS,
                    MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1
            ))
            .build();
    XmlSignature signature = new MockSignatureBuilder()
            .adesValidationDetails(b -> b.warnings(MessageTag.BBB_XCV_ISNSSC_ANS))
            .qualificationDetails(b -> b.warnings(MessageTag.QUAL_HAS_VALID_CAQC_ANS))
            .timestamps(timestamp)
            .build();

    Reports validationReports = mockReports(signature);
    assertThat(signature.getAdESValidationDetails().getWarning(), hasSize(1));
    assertThat(signature.getAdESValidationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.BBB_XCV_ISNSSC_ANS)
    ));
    assertThat(signature.getQualificationDetails().getWarning(), hasSize(1));
    assertThat(signature.getQualificationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_VALID_CAQC_ANS)
    ));
    assertThat(timestamp.getAdESValidationDetails().getWarning(), hasSize(2));
    assertThat(timestamp.getAdESValidationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.ADEST_IBSVPTC_ANS),
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1)
    ));
    assertThat(timestamp.getQualificationDetails().getWarning(), hasSize(2));
    assertThat(timestamp.getQualificationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD_ANS),
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1)
    ));

    XadesValidationReportProcessor.process(validationReports);

    assertThat(signature.getAdESValidationDetails().getWarning(), hasSize(1));
    assertThat(signature.getAdESValidationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.BBB_XCV_ISNSSC_ANS)
    ));
    assertThat(signature.getQualificationDetails().getWarning(), hasSize(1));
    assertThat(signature.getQualificationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_VALID_CAQC_ANS)
    ));
    assertThat(timestamp.getAdESValidationDetails().getWarning(), hasSize(1));
    assertThat(timestamp.getAdESValidationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.ADEST_IBSVPTC_ANS)
    ));
    assertThat(timestamp.getQualificationDetails().getWarning(), hasSize(1));
    assertThat(timestamp.getQualificationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD_ANS)
    ));
  }

  @Test
  public void process_WhenSignatureContainsTrustedCertificateNotMatchingTrustedServiceWarnings_WarningsRemoved() {
    XmlSignature signature = new MockSignatureBuilder()
            .adesValidationDetails(b -> b.warnings(
                    MessageTag.BBB_XCV_IRDC_ANS,
                    MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2
            ))
            .qualificationDetails(b -> b.warnings(
                    MessageTag.QUAL_HAS_CERT_TYPE_COVERAGE_ANS,
                    MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2
            ))
            .build();

    Reports validationReports = mockReports(signature);
    assertThat(signature.getAdESValidationDetails().getWarning(), hasSize(2));
    assertThat(signature.getAdESValidationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.BBB_XCV_IRDC_ANS),
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2)
    ));
    assertThat(signature.getQualificationDetails().getWarning(), hasSize(2));
    assertThat(signature.getQualificationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_CERT_TYPE_COVERAGE_ANS),
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2)
    ));

    XadesValidationReportProcessor.process(validationReports);

    assertThat(signature.getAdESValidationDetails().getWarning(), hasSize(1));
    assertThat(signature.getAdESValidationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.BBB_XCV_IRDC_ANS)
    ));
    assertThat(signature.getQualificationDetails().getWarning(), hasSize(1));
    assertThat(signature.getQualificationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_CERT_TYPE_COVERAGE_ANS)
    ));
  }

  @Test
  public void process_WhenTimestampContainsTrustedCertificateNotMatchingTrustedServiceWarnings_WarningsRemoved() {
    XmlTimestamp timestamp = new MockTimestampBuilder()
            .adesValidationDetails(b -> b.warnings(
                    MessageTag.ADEST_IBSVPTADC_ANS,
                    MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2
            ))
            .qualificationDetails(b -> b.warnings(
                    MessageTag.QUAL_QC_AT_CC_ANS,
                    MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2
            ))
            .build();
    XmlSignature signature = new MockSignatureBuilder()
            .adesValidationDetails(b -> b.warnings(MessageTag.ADEST_IRTPTBST_ANS))
            .qualificationDetails(b -> b.warnings(MessageTag.QUAL_QC_AT_ST_ANS))
            .timestamps(timestamp)
            .build();

    Reports validationReports = mockReports(signature);
    assertThat(signature.getAdESValidationDetails().getWarning(), hasSize(1));
    assertThat(signature.getAdESValidationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.ADEST_IRTPTBST_ANS)
    ));
    assertThat(signature.getQualificationDetails().getWarning(), hasSize(1));
    assertThat(signature.getQualificationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_QC_AT_ST_ANS)
    ));
    assertThat(timestamp.getAdESValidationDetails().getWarning(), hasSize(2));
    assertThat(timestamp.getAdESValidationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.ADEST_IBSVPTADC_ANS),
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2)
    ));
    assertThat(timestamp.getQualificationDetails().getWarning(), hasSize(2));
    assertThat(timestamp.getQualificationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_QC_AT_CC_ANS),
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2)
    ));

    XadesValidationReportProcessor.process(validationReports);

    assertThat(signature.getAdESValidationDetails().getWarning(), hasSize(1));
    assertThat(signature.getAdESValidationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.ADEST_IRTPTBST_ANS)
    ));
    assertThat(signature.getQualificationDetails().getWarning(), hasSize(1));
    assertThat(signature.getQualificationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_QC_AT_ST_ANS)
    ));
    assertThat(timestamp.getAdESValidationDetails().getWarning(), hasSize(1));
    assertThat(timestamp.getAdESValidationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.ADEST_IBSVPTADC_ANS)
    ));
    assertThat(timestamp.getQualificationDetails().getWarning(), hasSize(1));
    assertThat(timestamp.getQualificationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_QC_AT_CC_ANS)
    ));
  }

  @Test
  public void process_WhenSignatureNorTimestampContainsNoFilterableWarnings_NoWarningsRemoved() {
    XmlTimestamp timestamp = new MockTimestampBuilder()
            .adesValidationDetails(b -> b.warnings(
                    MessageTag.BBB_ACCEPT_ANS
            ))
            .qualificationDetails(b -> b.warnings(
                    MessageTag.QUAL_HAS_QTST_ANS
            ))
            .build();
    XmlSignature signature = new MockSignatureBuilder()
            .adesValidationDetails(b -> b.warnings(
                    MessageTag.ADEST_VFDTAOCST_ANS
            ))
            .qualificationDetails(b -> b.warnings(
                    MessageTag.QUAL_CERT_TYPE_AT_CC_ANS
            ))
            .timestamps(timestamp)
            .build();

    Reports validationReports = mockReports(signature);
    assertThat(signature.getAdESValidationDetails().getWarning(), hasSize(1));
    assertThat(signature.getAdESValidationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.ADEST_VFDTAOCST_ANS)
    ));
    assertThat(signature.getQualificationDetails().getWarning(), hasSize(1));
    assertThat(signature.getQualificationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_CERT_TYPE_AT_CC_ANS)
    ));
    assertThat(timestamp.getAdESValidationDetails().getWarning(), hasSize(1));
    assertThat(timestamp.getAdESValidationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.BBB_ACCEPT_ANS)
    ));
    assertThat(timestamp.getQualificationDetails().getWarning(), hasSize(1));
    assertThat(timestamp.getQualificationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_QTST_ANS)
    ));

    XadesValidationReportProcessor.process(validationReports);

    assertThat(signature.getAdESValidationDetails().getWarning(), hasSize(1));
    assertThat(signature.getAdESValidationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.ADEST_VFDTAOCST_ANS)
    ));
    assertThat(signature.getQualificationDetails().getWarning(), hasSize(1));
    assertThat(signature.getQualificationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_CERT_TYPE_AT_CC_ANS)
    ));
    assertThat(timestamp.getAdESValidationDetails().getWarning(), hasSize(1));
    assertThat(timestamp.getAdESValidationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.BBB_ACCEPT_ANS)
    ));
    assertThat(timestamp.getQualificationDetails().getWarning(), hasSize(1));
    assertThat(timestamp.getQualificationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_QTST_ANS)
    ));
  }

  @Test
  public void process_WhenSignatureAndTimestampContainFilterableWarningsButAsErrorsAndInfo_NoErrorsNorInfoRemoved() {
    XmlTimestamp timestamp = new MockTimestampBuilder()
            .adesValidationDetails(b -> b
                    .errors(
                            MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1,
                            MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2
                    ).infos(
                            MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1,
                            MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2
                    )
            )
            .qualificationDetails(b -> b
                    .errors(
                            MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1,
                            MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2
                    ).infos(
                            MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1,
                            MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2
                    )
            )
            .build();
    XmlSignature signature = new MockSignatureBuilder()
            .adesValidationDetails(b -> b
                    .errors(
                            MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1,
                            MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2
                    ).infos(
                            MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1,
                            MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2
                    )
            )
            .qualificationDetails(b -> b
                    .errors(
                            MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1,
                            MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2
                    ).infos(
                            MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1,
                            MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2
                    )
            )
            .timestamps(timestamp)
            .build();

    Reports validationReports = mockReports(signature);
    assertThat(signature.getAdESValidationDetails().getWarning(), empty());
    assertThat(signature.getAdESValidationDetails().getError(), hasSize(2));
    assertThat(signature.getAdESValidationDetails().getError(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1),
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2)
    ));
    assertThat(signature.getAdESValidationDetails().getInfo(), hasSize(2));
    assertThat(signature.getAdESValidationDetails().getInfo(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1),
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2)
    ));
    assertThat(signature.getQualificationDetails().getWarning(), empty());
    assertThat(signature.getQualificationDetails().getError(), hasSize(2));
    assertThat(signature.getQualificationDetails().getError(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1),
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2)
    ));
    assertThat(signature.getQualificationDetails().getInfo(), hasSize(2));
    assertThat(signature.getQualificationDetails().getInfo(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1),
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2)
    ));
    assertThat(timestamp.getAdESValidationDetails().getWarning(), empty());
    assertThat(timestamp.getAdESValidationDetails().getError(), hasSize(2));
    assertThat(timestamp.getAdESValidationDetails().getError(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1),
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2)
    ));
    assertThat(timestamp.getAdESValidationDetails().getInfo(), hasSize(2));
    assertThat(timestamp.getAdESValidationDetails().getInfo(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1),
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2)
    ));
    assertThat(timestamp.getQualificationDetails().getWarning(), empty());
    assertThat(timestamp.getQualificationDetails().getError(), hasSize(2));
    assertThat(timestamp.getQualificationDetails().getError(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1),
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2)
    ));
    assertThat(timestamp.getQualificationDetails().getInfo(), hasSize(2));
    assertThat(timestamp.getQualificationDetails().getInfo(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1),
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2)
    ));

    XadesValidationReportProcessor.process(validationReports);

    assertThat(signature.getAdESValidationDetails().getWarning(), empty());
    assertThat(signature.getAdESValidationDetails().getError(), hasSize(2));
    assertThat(signature.getAdESValidationDetails().getError(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1),
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2)
    ));
    assertThat(signature.getAdESValidationDetails().getInfo(), hasSize(2));
    assertThat(signature.getAdESValidationDetails().getInfo(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1),
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2)
    ));
    assertThat(signature.getQualificationDetails().getWarning(), empty());
    assertThat(signature.getQualificationDetails().getError(), hasSize(2));
    assertThat(signature.getQualificationDetails().getError(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1),
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2)
    ));
    assertThat(signature.getQualificationDetails().getInfo(), hasSize(2));
    assertThat(signature.getQualificationDetails().getInfo(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1),
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2)
    ));
    assertThat(timestamp.getAdESValidationDetails().getWarning(), empty());
    assertThat(timestamp.getAdESValidationDetails().getError(), hasSize(2));
    assertThat(timestamp.getAdESValidationDetails().getError(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1),
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2)
    ));
    assertThat(timestamp.getAdESValidationDetails().getInfo(), hasSize(2));
    assertThat(timestamp.getAdESValidationDetails().getInfo(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1),
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2)
    ));
    assertThat(timestamp.getQualificationDetails().getWarning(), empty());
    assertThat(timestamp.getQualificationDetails().getError(), hasSize(2));
    assertThat(timestamp.getQualificationDetails().getError(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1),
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2)
    ));
    assertThat(timestamp.getQualificationDetails().getInfo(), hasSize(2));
    assertThat(timestamp.getQualificationDetails().getInfo(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1),
            messageOf(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2)
    ));
  }

  @Test
  public void process_WhenSignatureTimestampContainsTstPoeTimeStatusErrorInQualificationDetails_ErrorRemoved() {
    XmlTimestamp timestamp = new MockTimestampBuilder()
            .qualificationDetails(b -> b.errors(
                    toMessage(MessageTag.QUAL_HAS_QTST_ANS),
                    toMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
            ))
            .build();
    XmlSignature signature = new MockSignatureBuilder()
            .timestamps(timestamp)
            .build();

    Reports validationReports = mockReports(signature);
    assertThat(timestamp.getQualificationDetails().getError(), hasSize(2));
    assertThat(timestamp.getQualificationDetails().getError(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_QTST_ANS),
            messageOf(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    ));

    XadesValidationReportProcessor.process(validationReports);

    assertThat(timestamp.getQualificationDetails().getError(), hasSize(1));
    assertThat(timestamp.getQualificationDetails().getError(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_QTST_ANS)
    ));
  }

  @Test
  public void process_WhenSignatureTimestampContainsOtherStatusErrorsInQualificationDetails_NoErrorsRemoved() {
    List<Object> validationTimes = Stream.concat(
            Stream.of(MessageTag.values())
                    .filter(mt -> StringUtils.startsWith(mt.getId(), "VT_"))
                    .filter(mt -> !MessageTag.VT_TST_POE_TIME.equals(mt)),
            Stream.of("some custom validation time")
    ).collect(Collectors.toList());
    XmlTimestamp timestamp = new MockTimestampBuilder()
            .qualificationDetails(b -> b.errors(
                    validationTimes.stream()
                            .map(vt -> toMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, vt))
                            .collect(Collectors.toList())
            ))
            .build();
    XmlSignature signature = new MockSignatureBuilder()
            .timestamps(timestamp)
            .build();

    Reports validationReports = mockReports(signature);
    assertThat(timestamp.getQualificationDetails().getError(), hasSize(validationTimes.size()));
    assertThat(timestamp.getQualificationDetails().getError(), containsInRelativeOrder(
            validationTimes.stream()
                    .map(vt -> messageOf(MessageTag.QUAL_HAS_GRANTED_AT_ANS, vt))
                    .collect(Collectors.toList())
    ));

    XadesValidationReportProcessor.process(validationReports);

    assertThat(timestamp.getQualificationDetails().getError(), hasSize(validationTimes.size()));
    assertThat(timestamp.getQualificationDetails().getError(), containsInRelativeOrder(
            validationTimes.stream()
                    .map(vt -> messageOf(MessageTag.QUAL_HAS_GRANTED_AT_ANS, vt))
                    .collect(Collectors.toList())
    ));
  }

  @Test
  public void process_WhenSignatureOrTimestampContainsTstPoeTimeStatusErrorInAnywhereElseThanTimestampQualificationDetailsAsError_NothingRemoved() {
    XmlTimestamp timestamp = new MockTimestampBuilder()
            .adesValidationDetails(b -> b
                    .errors(toMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME))
                    .warnings(toMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME))
                    .infos(toMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME))
            )
            .qualificationDetails(b -> b
                    .warnings(toMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME))
                    .infos(toMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME))
            )
            .build();
    XmlSignature signature = new MockSignatureBuilder()
            .adesValidationDetails(b -> b
                    .errors(toMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME))
                    .warnings(toMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME))
                    .infos(toMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME))
            )
            .qualificationDetails(b -> b
                    .errors(toMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME))
                    .warnings(toMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME))
                    .infos(toMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME))
            )
            .timestamps(timestamp)
            .build();

    Reports validationReports = mockReports(signature);
    assertThat(signature.getAdESValidationDetails().getError(), hasSize(1));
    assertThat(signature.getAdESValidationDetails().getError(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    ));
    assertThat(signature.getAdESValidationDetails().getWarning(), hasSize(1));
    assertThat(signature.getAdESValidationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    ));
    assertThat(signature.getAdESValidationDetails().getInfo(), hasSize(1));
    assertThat(signature.getAdESValidationDetails().getInfo(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    ));
    assertThat(signature.getQualificationDetails().getError(), hasSize(1));
    assertThat(signature.getQualificationDetails().getError(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    ));
    assertThat(signature.getQualificationDetails().getWarning(), hasSize(1));
    assertThat(signature.getQualificationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    ));
    assertThat(signature.getQualificationDetails().getInfo(), hasSize(1));
    assertThat(signature.getQualificationDetails().getInfo(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    ));
    assertThat(timestamp.getAdESValidationDetails().getError(), hasSize(1));
    assertThat(timestamp.getAdESValidationDetails().getError(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    ));
    assertThat(timestamp.getAdESValidationDetails().getWarning(), hasSize(1));
    assertThat(timestamp.getAdESValidationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    ));
    assertThat(timestamp.getAdESValidationDetails().getInfo(), hasSize(1));
    assertThat(timestamp.getAdESValidationDetails().getInfo(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    ));
    assertThat(timestamp.getQualificationDetails().getError(), empty());
    assertThat(timestamp.getQualificationDetails().getWarning(), hasSize(1));
    assertThat(timestamp.getQualificationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    ));
    assertThat(timestamp.getQualificationDetails().getInfo(), hasSize(1));
    assertThat(timestamp.getQualificationDetails().getInfo(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    ));

    XadesValidationReportProcessor.process(validationReports);

    assertThat(signature.getAdESValidationDetails().getError(), hasSize(1));
    assertThat(signature.getAdESValidationDetails().getError(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    ));
    assertThat(signature.getAdESValidationDetails().getWarning(), hasSize(1));
    assertThat(signature.getAdESValidationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    ));
    assertThat(signature.getAdESValidationDetails().getInfo(), hasSize(1));
    assertThat(signature.getAdESValidationDetails().getInfo(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    ));
    assertThat(signature.getQualificationDetails().getError(), hasSize(1));
    assertThat(signature.getQualificationDetails().getError(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    ));
    assertThat(signature.getQualificationDetails().getWarning(), hasSize(1));
    assertThat(signature.getQualificationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    ));
    assertThat(signature.getQualificationDetails().getInfo(), hasSize(1));
    assertThat(signature.getQualificationDetails().getInfo(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    ));
    assertThat(timestamp.getAdESValidationDetails().getError(), hasSize(1));
    assertThat(timestamp.getAdESValidationDetails().getError(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    ));
    assertThat(timestamp.getAdESValidationDetails().getWarning(), hasSize(1));
    assertThat(timestamp.getAdESValidationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    ));
    assertThat(timestamp.getAdESValidationDetails().getInfo(), hasSize(1));
    assertThat(timestamp.getAdESValidationDetails().getInfo(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    ));
    assertThat(timestamp.getQualificationDetails().getError(), empty());
    assertThat(timestamp.getQualificationDetails().getWarning(), hasSize(1));
    assertThat(timestamp.getQualificationDetails().getWarning(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    ));
    assertThat(timestamp.getQualificationDetails().getInfo(), hasSize(1));
    assertThat(timestamp.getQualificationDetails().getInfo(), containsInRelativeOrder(
            messageOf(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    ));
  }

  private static Reports mockReports(XmlSignature... signatures) {
    XmlSimpleReport simpleReport = new XmlSimpleReport();
    Arrays.stream(signatures).forEach(simpleReport.getSignatureOrTimestampOrEvidenceRecord()::add);

    Reports validationReports = Mockito.mock(Reports.class);
    doReturn(simpleReport).when(validationReports).getSimpleReportJaxb();
    return validationReports;
  }

  private static Matcher<XmlMessage> messageOf(MessageTag messageTag, Object... args) {
    XmlMessage xmlMessage = toMessage(messageTag, args);
    return IsSimpleReportXmlMessage.messageWithKeyAndValue(xmlMessage.getKey(), xmlMessage.getValue());
  }

  private static XmlMessage toMessage(MessageTag messageTag, Object... args) {
    return new MessageBuilder().with(messageTag, args).build();
  }

  private static List<XmlMessage> toMessages(MessageTag... messageTags) {
    return Arrays.stream(messageTags)
            .map(XadesValidationReportProcessorTest::toMessage)
            .collect(ArrayList::new, ArrayList::add, ArrayList::addAll);
  }

  private static class DetailsBuilder {

    private List<XmlMessage> errors;
    private List<XmlMessage> warnings;
    private List<XmlMessage> infos;

    public DetailsBuilder errors(List<XmlMessage> errors) {
      this.errors = errors;
      return this;
    }

    public DetailsBuilder errors(XmlMessage... errors) {
      return errors(new ArrayList<>(Arrays.asList(errors)));
    }

    public DetailsBuilder errors(MessageTag... errors) {
      return errors(toMessages(errors));
    }

    public DetailsBuilder warnings(List<XmlMessage> warnings) {
      this.warnings = warnings;
      return this;
    }

    public DetailsBuilder warnings(XmlMessage... warnings) {
      return warnings(new ArrayList<>(Arrays.asList(warnings)));
    }

    public DetailsBuilder warnings(MessageTag... warnings) {
      return warnings(toMessages(warnings));
    }

    public DetailsBuilder infos(List<XmlMessage> infos) {
      this.infos = infos;
      return this;
    }

    public DetailsBuilder infos(XmlMessage... infos) {
      return infos(new ArrayList<>(Arrays.asList(infos)));
    }

    public DetailsBuilder infos(MessageTag... infos) {
      return infos(toMessages(infos));
    }

    public XmlDetails build() {
      XmlDetails details = new XmlDetails();
      Optional.ofNullable(errors).ifPresent(details.getError()::addAll);
      Optional.ofNullable(warnings).ifPresent(details.getWarning()::addAll);
      Optional.ofNullable(infos).ifPresent(details.getInfo()::addAll);
      return details;
    }

  }

  private static class MessageBuilder {

    private String key;
    private String value;

    public MessageBuilder key(String key) {
      this.key = key;
      return this;
    }

    public MessageBuilder key(MessageTag messageTag) {
      return key(messageTag.getId());
    }

    public MessageBuilder value(String value) {
      this.value = value;
      return this;
    }

    public MessageBuilder value(MessageTag messageTag, Object... args) {
      return value(i18nProvider.getMessage(messageTag, args));
    }

    public MessageBuilder with(MessageTag messageTag, Object... args) {
      return key(messageTag).value(messageTag, args);
    }

    public XmlMessage build() {
      XmlMessage message = new XmlMessage();
      Optional.ofNullable(key).ifPresent(message::setKey);
      Optional.ofNullable(value).ifPresent(message::setValue);
      return message;
    }

  }

  private abstract static class MockTokenBuilder<T extends XmlToken, B extends MockTokenBuilder<T, B>> {

    private final Class<T> tokenType;
    private XmlDetails adesValidationDetails;
    private XmlDetails qualificationDetails;

    protected MockTokenBuilder(Class<T> tokenType) {
      this.tokenType = Objects.requireNonNull(tokenType);
    }

    @SuppressWarnings("unchecked")
    public B adesValidationDetails(XmlDetails details) {
      adesValidationDetails = details;
      return (B) this;
    }

    public B adesValidationDetails(Consumer<DetailsBuilder> builderConsumer) {
      DetailsBuilder detailsBuilder = new DetailsBuilder();
      builderConsumer.accept(detailsBuilder);
      return adesValidationDetails(detailsBuilder.build());
    }

    @SuppressWarnings("unchecked")
    public B qualificationDetails(XmlDetails details) {
      qualificationDetails = details;
      return (B) this;
    }

    public B qualificationDetails(Consumer<DetailsBuilder> builderConsumer) {
      DetailsBuilder detailsBuilder = new DetailsBuilder();
      builderConsumer.accept(detailsBuilder);
      return qualificationDetails(detailsBuilder.build());
    }

    public T build() {
      T tokenMock = Mockito.mock(tokenType);
      if (adesValidationDetails != null) {
        doReturn(adesValidationDetails).when(tokenMock).getAdESValidationDetails();
      }
      if (qualificationDetails != null) {
        doReturn(qualificationDetails).when(tokenMock).getQualificationDetails();
      }
      return tokenMock;
    }

  }

  private static class MockSignatureBuilder extends MockTokenBuilder<XmlSignature, MockSignatureBuilder> {

    private XmlTimestamps timestamps;

    public MockSignatureBuilder() {
      super(XmlSignature.class);
    }

    public MockSignatureBuilder timestamps(XmlTimestamps timestamps) {
      this.timestamps = timestamps;
      return this;
    }

    public MockSignatureBuilder timestamps(XmlTimestamp... timestamps) {
      XmlTimestamps xmlTimestamps = new XmlTimestamps();
      xmlTimestamps.getTimestamp().addAll(Arrays.asList(timestamps));
      return timestamps(xmlTimestamps);
    }

    @Override
    public XmlSignature build() {
      XmlSignature signatureMock = super.build();
      if (timestamps != null) {
        doReturn(timestamps).when(signatureMock).getTimestamps();
      }
      return signatureMock;
    }

  }

  private static class MockTimestampBuilder extends MockTokenBuilder<XmlTimestamp, MockTimestampBuilder> {

    public MockTimestampBuilder() {
      super(XmlTimestamp.class);
    }

  }

}
