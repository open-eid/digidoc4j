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

public class XadesSignatureValidatorFactory {

  private Configuration configuration;
  private XadesSignature signature;

  public XadesSignatureValidator create() {
    SignatureProfile profile = signature.getProfile();
    XadesSignatureValidator xadesValidator;
    if (profile == SignatureProfile.B_BES) {
      xadesValidator = new XadesSignatureValidator(signature, configuration);
    } else if (profile == SignatureProfile.LT_TM) {
      xadesValidator = new TimemarkSignatureValidator(signature, configuration);
    } else {
      xadesValidator = new TimestampSignatureValidator(signature, configuration);
    }
    return xadesValidator;
  }

  public void setConfiguration(Configuration configuration) {
    this.configuration = configuration;
  }

  public void setSignature(XadesSignature signature) {
    this.signature = signature;
  }
  
}
