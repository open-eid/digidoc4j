package org.digidoc4j.impl.bdoc.xades;

import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignature;
import eu.europa.esig.dss.validation.reports.Reports;
import org.digidoc4j.impl.asic.xades.XadesValidationReportProcessor;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.Arrays;

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
        simpleReport.getSignatureOrTimestamp().add(signature);

        Reports validationReports = Mockito.mock(Reports.class);
        when(validationReports.getSimpleReportJaxb()).thenReturn(simpleReport);

        assertSame(2, signature.getWarnings().size());
        XadesValidationReportProcessor.process(validationReports);
        assertSame(1, signature.getWarnings().size());
    }

    @Test
    public void trustedCertificateNotMatchingWithTrustedServiceWarningRemoved() {
        XmlSignature signature = mockSignatureWithWarnings(
                i18nProvider.getMessage(MessageTag.QUAL_IS_ADES),
                i18nProvider.getMessage(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2)
        );
        XmlSimpleReport simpleReport = new XmlSimpleReport();
        simpleReport.getSignatureOrTimestamp().add(signature);

        Reports validationReports = Mockito.mock(Reports.class);
        when(validationReports.getSimpleReportJaxb()).thenReturn(simpleReport);

        assertSame(2, signature.getWarnings().size());
        XadesValidationReportProcessor.process(validationReports);
        assertSame(1, signature.getWarnings().size());
    }

    @Test
    public void noWarningRemoved() {
        XmlSignature signature = mockSignatureWithWarnings(
                i18nProvider.getMessage(MessageTag.QUAL_IS_ADES),
                i18nProvider.getMessage(MessageTag.QUAL_FOR_SIGN_AT_CC)
        );
        XmlSimpleReport simpleReport = new XmlSimpleReport();
        simpleReport.getSignatureOrTimestamp().add(signature);

        Reports validationReports = Mockito.mock(Reports.class);
        when(validationReports.getSimpleReportJaxb()).thenReturn(simpleReport);

        assertSame(2, signature.getWarnings().size());
        XadesValidationReportProcessor.process(validationReports);
        assertSame(2, signature.getWarnings().size());
    }

    private XmlSignature mockSignatureWithWarnings(String... warnings) {
        XmlSignature signature = Mockito.mock(XmlSignature.class);
        when(signature.getWarnings()).thenReturn(new ArrayList<>(Arrays.asList(warnings)));
        return signature;
    }
}
