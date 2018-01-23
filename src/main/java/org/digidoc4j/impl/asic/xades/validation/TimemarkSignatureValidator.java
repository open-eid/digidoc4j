/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.asic.xades.validation;

import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.exceptions.InvalidTimemarkSignatureException;
import org.digidoc4j.exceptions.SignedWithExpiredCertificateException;
import org.digidoc4j.exceptions.UntrustedRevocationSourceException;
import org.digidoc4j.impl.asic.xades.XadesSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.xades.XPathQueryHolder;

public class TimemarkSignatureValidator extends XadesSignatureValidator {

    private final Logger log = LoggerFactory.getLogger(TimemarkSignatureValidator.class);

    public TimemarkSignatureValidator(XadesSignature signature) {
        super(signature);
    }

    @Override
    protected void populateValidationErrors() {
        super.populateValidationErrors();
        this.addCertificateExpirationError();
        this.addRevocationErrors();
    }

    @Override
    protected void addPolicyErrors() {
        this.log.debug("Extracting TM signature policy errors");
        XPathQueryHolder xPathQueryHolder = this.getDssSignature().getXPathQueryHolder();
        Element signaturePolicyImpliedElement = DomUtils.getElement(this.getDssSignature().getSignatureElement(),
            String.format("%s%s", xPathQueryHolder.XPATH_SIGNATURE_POLICY_IDENTIFIER,
                xPathQueryHolder.XPATH__SIGNATURE_POLICY_IMPLIED.replace(".", "")));
        if (signaturePolicyImpliedElement != null) {
            this.log.error("Signature contains forbidden element");
            this.addValidationError(new InvalidTimemarkSignatureException("Signature contains forbidden <SignaturePolicyImplied> element"));
        }
    }

    private void addCertificateExpirationError() {
        Date signingTime = this.signature.getTrustedSigningTime();
        if (signingTime == null) {
            return;
        }
        X509Certificate signerCert = this.signature.getSigningCertificate().getX509Certificate();
        boolean isCertValid = signingTime.compareTo(signerCert.getNotBefore()) >= 0 &&
            signingTime.compareTo(signerCert.getNotAfter()) <= 0;
        if (!isCertValid) {
            this.log.error("Signature has been created with expired certificate");
            this.addValidationError(new SignedWithExpiredCertificateException());
        }
    }

    private void addRevocationErrors() {
        DiagnosticData diagnosticData = this.signature.validate().getReport().getDiagnosticData();
        if (diagnosticData == null) {
            return;
        }
        String certificateRevocationSource = diagnosticData.getCertificateRevocationSource(diagnosticData.getSigningCertificateId());
        this.log.debug("Revocation source is <{}>", certificateRevocationSource);
        if (StringUtils.equalsIgnoreCase("CRLToken", certificateRevocationSource)) {
            this.log.error("Signing certificate revocation source is CRL instead of OCSP");
            this.addValidationError(new UntrustedRevocationSourceException());
        }
    }

}
