/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j;

import org.digidoc4j.impl.DefaultOCSPSource;
import org.digidoc4j.impl.SKOnlineOCSPSource;
import org.digidoc4j.impl.asic.SkDataLoader;
import org.digidoc4j.impl.asic.ocsp.BDocTMOcspSource;
import org.digidoc4j.impl.asic.ocsp.BDocTSOcspSource;
import org.digidoc4j.utils.Helper;

import eu.europa.esig.dss.x509.ocsp.OCSPSource;

/**
 * OCSP source builder
 */
public class OCSPSourceBuilder {

  private Configuration configuration;
  private byte[] signatureValue;
  private SignatureProfile signatureProfile;

  /**
   * @return OCSPSourceBuilder
   */
  public static OCSPSourceBuilder anOcspSource() {
    return new OCSPSourceBuilder();
  }

  /**
   * @return OCSPSource
   */
  public OCSPSource build() {
    SkDataLoader loader = SkDataLoader.ocsp(this.configuration);
    SKOnlineOCSPSource source;
    if (this.signatureProfile != null) {
      switch (this.signatureProfile) {
        case LT_TM:
          source = new BDocTMOcspSource(this.configuration, this.signatureValue);
          break;
        default:
          source = new BDocTSOcspSource(this.configuration);
      }
      loader.setUserAgent(Helper.createBDocUserAgent(this.signatureProfile));
    } else {
      source = new DefaultOCSPSource(this.configuration);
      loader.setUserAgent(Helper.createUserAgent("None", null, null));
    }
    source.setDataLoader(loader);
    return source;
  }

  /**
   * @param configuration configuration context
   * @return OCSPSourceBuilder
   */
  public OCSPSourceBuilder withConfiguration(Configuration configuration) {
    this.configuration = configuration;
    return this;
  }

  /**
   * @param signatureValue signature bytes
   * @return OCSPSourceBuilder
   */
  public OCSPSourceBuilder withSignatureValue(byte[] signatureValue) {
    this.signatureValue = signatureValue;
    return this;
  }

  /**
   * @param signatureProfile signature profile
   * @return OCSPSourceBuilder
   */
  public OCSPSourceBuilder withSignatureProfile(SignatureProfile signatureProfile) {
    this.signatureProfile = signatureProfile;
    return this;
  }

}
