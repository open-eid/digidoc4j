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

import org.digidoc4j.Configuration;
import org.digidoc4j.exceptions.InvalidTimemarkSignatureException;
import org.digidoc4j.impl.asic.xades.XadesSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TimemarkSignatureValidator extends TimestampSignatureValidator {

    private final Logger log = LoggerFactory.getLogger(TimemarkSignatureValidator.class);

    public TimemarkSignatureValidator(XadesSignature signature) {
        super(signature);
    }

    public TimemarkSignatureValidator(XadesSignature signature, Configuration configuration) {
        super(signature, configuration);
    }

    @Override
    protected void addPolicyErrors() {
        this.log.debug("Extracting TM signature policy errors");
        if (isSignaturePolicyImpliedElementPresented()) {
            this.log.error("Signature contains forbidden element");
            this.addValidationError(new InvalidTimemarkSignatureException("Signature contains forbidden <SignaturePolicyImplied> element"));
        }
    }
}
