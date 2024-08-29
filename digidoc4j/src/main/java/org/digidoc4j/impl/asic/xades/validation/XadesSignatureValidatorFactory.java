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
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.impl.asic.xades.XadesSignature;

import java.util.Date;

/**
 * A factory for creating validators for XAdES signatures.
 */
public class XadesSignatureValidatorFactory {

  private Configuration configuration;
  private XadesSignature signature;
  private Date validationTime;

  public XadesSignatureValidator create() {
    SignatureProfile profile = signature.getProfile();
    XadesSignatureValidator xadesValidator;
    if (profile == SignatureProfile.B_BES) {
      xadesValidator = new XadesSignatureValidator(signature, configuration, validationTime);
    } else if (profile == SignatureProfile.LT_TM) {
      xadesValidator = new TimemarkSignatureValidator(signature, configuration, validationTime);
    } else {
      xadesValidator = new TimestampSignatureValidator(signature, configuration, validationTime);
    }
    return xadesValidator;
  }

  public void setConfiguration(Configuration configuration) {
    this.configuration = configuration;
  }

  public void setSignature(XadesSignature signature) {
    this.signature = signature;
  }

  public void setValidationTime(Date validationTime) {
    this.validationTime = validationTime;
  }
  
}
