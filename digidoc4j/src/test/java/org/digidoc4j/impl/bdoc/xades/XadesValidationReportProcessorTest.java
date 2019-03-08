package org.digidoc4j.impl.bdoc.xades;

import eu.europa.esig.dss.jaxb.simplereport.SimpleReport;
import eu.europa.esig.dss.jaxb.simplereport.XmlSignature;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.Reports;
import org.digidoc4j.impl.asic.xades.XadesValidationReportProcessor;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.Arrays;

import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.when;

public class XadesValidationReportProcessorTest {

    @Test
    public void organizationNameMissingWarningRemoved() {
        XmlSignature signature = mockSignatureWithWarnings(
                MessageTag.QUAL_IS_ADES.getMessage(),
                MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1.getMessage()
        );
        SimpleReport simpleReport = new SimpleReport();
        simpleReport.getSignature().add(signature);

        Reports validationReports = Mockito.mock(Reports.class);
        when(validationReports.getSimpleReportJaxb()).thenReturn(simpleReport);

        assertSame(2, signature.getWarnings().size());
        XadesValidationReportProcessor.process(validationReports);
        assertSame(1, signature.getWarnings().size());
    }

    @Test
    public void trustedCertificateNotMatchingWithTrustedServiceWarningRemoved() {
        XmlSignature signature = mockSignatureWithWarnings(
                MessageTag.QUAL_IS_ADES.getMessage(),
                MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2.getMessage()
        );
        SimpleReport simpleReport = new SimpleReport();
        simpleReport.getSignature().add(signature);

        Reports validationReports = Mockito.mock(Reports.class);
        when(validationReports.getSimpleReportJaxb()).thenReturn(simpleReport);

        assertSame(2, signature.getWarnings().size());
        XadesValidationReportProcessor.process(validationReports);
        assertSame(1, signature.getWarnings().size());
    }

    @Test
    public void noWarningRemoved() {
        XmlSignature signature = mockSignatureWithWarnings(
                MessageTag.QUAL_IS_ADES.getMessage(),
                MessageTag.QUAL_FOR_SIGN_AT_CC.getMessage()
        );
        SimpleReport simpleReport = new SimpleReport();
        simpleReport.getSignature().add(signature);

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
