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
import org.digidoc4j.impl.asic.xades.XadesValidationReportProcessor;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.when;

public class XadesValidationReportProcessorTest {
    private static final I18nProvider i18nProvider = new I18nProvider();

    @Test
    public void organizationNameMissingWarningRemoved() {
        XmlSignature signature = mockSignatureWithWarnings(
                i18nProvider.getMessage(MessageTag.QUAL_IS_ADES),
                i18nProvider.getMessage(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1)
        );
        XmlSimpleReport simpleReport = new XmlSimpleReport();
        simpleReport.getSignatureOrTimestampOrEvidenceRecord().add(signature);

        Reports validationReports = Mockito.mock(Reports.class);
        when(validationReports.getSimpleReportJaxb()).thenReturn(simpleReport);

        assertSame(2, signature.getAdESValidationDetails().getWarning().size());
        assertSame(2, signature.getQualificationDetails().getWarning().size());
        XadesValidationReportProcessor.process(validationReports);
        assertSame(1, signature.getAdESValidationDetails().getWarning().size());
        assertSame(1, signature.getQualificationDetails().getWarning().size());
    }

    @Test
    public void organizationNameMissingWarningRemovedFromTimestamp() {
        XmlTimestamp timestamp = mockTimestampWithWarnings(
                i18nProvider.getMessage(MessageTag.QUAL_IS_ADES),
                i18nProvider.getMessage(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1)
        );
        XmlSignature signature = mockSignatureWithWarnings(
                i18nProvider.getMessage(MessageTag.QUAL_IS_ADES)
        );
        mockSignatureTimestamps(signature, timestamp);
        XmlSimpleReport simpleReport = new XmlSimpleReport();
        simpleReport.getSignatureOrTimestampOrEvidenceRecord().add(signature);

        Reports validationReports = Mockito.mock(Reports.class);
        when(validationReports.getSimpleReportJaxb()).thenReturn(simpleReport);

        assertSame(1, signature.getAdESValidationDetails().getWarning().size());
        assertSame(1, signature.getQualificationDetails().getWarning().size());
        assertSame(2, timestamp.getAdESValidationDetails().getWarning().size());
        assertSame(2, timestamp.getQualificationDetails().getWarning().size());
        XadesValidationReportProcessor.process(validationReports);
        assertSame(1, signature.getAdESValidationDetails().getWarning().size());
        assertSame(1, signature.getQualificationDetails().getWarning().size());
        assertSame(1, timestamp.getAdESValidationDetails().getWarning().size());
        assertSame(1, timestamp.getQualificationDetails().getWarning().size());
    }

    @Test
    public void trustedCertificateNotMatchingWithTrustedServiceWarningRemoved() {
        XmlSignature signature = mockSignatureWithWarnings(
                i18nProvider.getMessage(MessageTag.QUAL_IS_ADES),
                i18nProvider.getMessage(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2)
        );
        XmlSimpleReport simpleReport = new XmlSimpleReport();
        simpleReport.getSignatureOrTimestampOrEvidenceRecord().add(signature);

        Reports validationReports = Mockito.mock(Reports.class);
        when(validationReports.getSimpleReportJaxb()).thenReturn(simpleReport);

        assertSame(2, signature.getAdESValidationDetails().getWarning().size());
        assertSame(2, signature.getQualificationDetails().getWarning().size());
        XadesValidationReportProcessor.process(validationReports);
        assertSame(1, signature.getAdESValidationDetails().getWarning().size());
        assertSame(1, signature.getQualificationDetails().getWarning().size());
    }

    @Test
    public void trustedCertificateNotMatchingWithTrustedServiceWarningRemovedFromTimestamp() {
        XmlTimestamp timestamp = mockTimestampWithWarnings(
                i18nProvider.getMessage(MessageTag.QUAL_IS_ADES),
                i18nProvider.getMessage(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2)
        );
        XmlSignature signature = mockSignatureWithWarnings(
                i18nProvider.getMessage(MessageTag.QUAL_IS_ADES)
        );
        mockSignatureTimestamps(signature, timestamp);
        XmlSimpleReport simpleReport = new XmlSimpleReport();
        simpleReport.getSignatureOrTimestampOrEvidenceRecord().add(signature);

        Reports validationReports = Mockito.mock(Reports.class);
        when(validationReports.getSimpleReportJaxb()).thenReturn(simpleReport);

        assertSame(1, signature.getAdESValidationDetails().getWarning().size());
        assertSame(1, signature.getQualificationDetails().getWarning().size());
        assertSame(2, timestamp.getAdESValidationDetails().getWarning().size());
        assertSame(2, timestamp.getQualificationDetails().getWarning().size());
        XadesValidationReportProcessor.process(validationReports);
        assertSame(1, signature.getAdESValidationDetails().getWarning().size());
        assertSame(1, signature.getQualificationDetails().getWarning().size());
        assertSame(1, timestamp.getAdESValidationDetails().getWarning().size());
        assertSame(1, timestamp.getQualificationDetails().getWarning().size());
    }

    @Test
    public void noWarningRemoved() {
        XmlSignature signature = mockSignatureWithWarnings(
                i18nProvider.getMessage(MessageTag.QUAL_IS_ADES),
                i18nProvider.getMessage(MessageTag.QUAL_CERT_TYPE_AT_CC)
        );
        XmlSimpleReport simpleReport = new XmlSimpleReport();
        simpleReport.getSignatureOrTimestampOrEvidenceRecord().add(signature);

        Reports validationReports = Mockito.mock(Reports.class);
        when(validationReports.getSimpleReportJaxb()).thenReturn(simpleReport);

        assertSame(2, signature.getAdESValidationDetails().getWarning().size());
        assertSame(2, signature.getQualificationDetails().getWarning().size());
        XadesValidationReportProcessor.process(validationReports);
        assertSame(2, signature.getAdESValidationDetails().getWarning().size());
        assertSame(2, signature.getQualificationDetails().getWarning().size());
    }

    private static void mockSignatureTimestamps(XmlSignature signatureMock, XmlTimestamp... timestamps) {
        XmlTimestamps timestampsWrapper = Mockito.mock(XmlTimestamps.class);
        ArrayList<XmlTimestamp> timestampsList = Stream.of(timestamps)
                .collect(Collectors.toCollection(ArrayList::new));
        when(timestampsWrapper.getTimestamp()).thenReturn(timestampsList);
        when(signatureMock.getTimestamps()).thenReturn(timestampsWrapper);
    }

    private static void mockTokenWarnings(XmlToken tokenMock, String... warnings) {
        XmlDetails adESDetails = mockDetailsWithWarnings(warnings);
        when(tokenMock.getAdESValidationDetails()).thenReturn(adESDetails);
        XmlDetails qualificationDetails = mockDetailsWithWarnings(warnings);
        when(tokenMock.getQualificationDetails()).thenReturn(qualificationDetails);
    }

    private static XmlSignature mockSignatureWithWarnings(String... warnings) {
        XmlSignature signature = Mockito.mock(XmlSignature.class);
        mockTokenWarnings(signature, warnings);
        return signature;
    }

    private static XmlTimestamp mockTimestampWithWarnings(String... warnings) {
        XmlTimestamp timestamp = Mockito.mock(XmlTimestamp.class);
        mockTokenWarnings(timestamp, warnings);
        return timestamp;
    }

    private static XmlDetails mockDetailsWithWarnings(String... warnings) {
        XmlDetails details = Mockito.mock(XmlDetails.class);
        ArrayList<XmlMessage> warningsList = Stream.of(warnings).map(w -> {
            XmlMessage message = Mockito.mock(XmlMessage.class);
            when(message.getValue()).thenReturn(w);
            return message;
        }).collect(Collectors.toCollection(ArrayList::new));
        when(details.getWarning()).thenReturn(warningsList);
        return details;
    }

}
