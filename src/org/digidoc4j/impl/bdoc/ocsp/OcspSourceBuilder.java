/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.ocsp;

import org.digidoc4j.Configuration;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.impl.bdoc.SkDataLoader;

public class OcspSourceBuilder {

  private Configuration configuration;
  private byte[] signatureValue;
  private SignatureProfile signatureProfile;

  public static OcspSourceBuilder anOcspSource() {
    return new OcspSourceBuilder();
  }

  public SKOnlineOCSPSource build() {
    SKOnlineOCSPSource ocspSource;
    if (signatureProfile == SignatureProfile.LT_TM) {
      ocspSource = new BDocTMOcspSource(configuration, signatureValue);
    } else {
      ocspSource = new BDocTSOcspSource(configuration);
    }
    SkDataLoader dataLoader = SkDataLoader.createOcspDataLoader(configuration);
    dataLoader.setUserAgentSignatureProfile(signatureProfile);
    ocspSource.setDataLoader(dataLoader);
    return ocspSource;
  }

  public OcspSourceBuilder withConfiguration(Configuration configuration) {
    this.configuration = configuration;
    return this;
  }

  public OcspSourceBuilder withSignatureValue(byte[] signatureValue) {
    this.signatureValue = signatureValue;
    return this;
  }

  public OcspSourceBuilder withSignatureProfile(SignatureProfile signatureProfile) {
    this.signatureProfile = signatureProfile;
    return this;
  }
}
