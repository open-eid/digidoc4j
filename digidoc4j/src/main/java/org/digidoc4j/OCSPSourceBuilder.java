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

import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import org.digidoc4j.impl.CommonOCSPSource;
import org.digidoc4j.impl.ConfigurationSingeltonHolder;
import org.digidoc4j.impl.SKOnlineOCSPSource;
import org.digidoc4j.impl.SkDataLoader;
import org.digidoc4j.impl.SkOCSPDataLoader;
import org.digidoc4j.impl.asic.ocsp.BDocTMOcspSource;
import org.digidoc4j.utils.Helper;

/**
 * OCSP source builder
 */
public class OCSPSourceBuilder {

  private final boolean defaultOCSPSource;
  private Configuration configuration;
  private SignatureProfile signatureProfile;
  private byte[] signatureValue;

  /**
   * @param defaultOCSPSource whether to use default OCSP source
   */
  protected OCSPSourceBuilder(boolean defaultOCSPSource) {
    this.defaultOCSPSource = defaultOCSPSource;
  }

  /**
   * Using default OCSP source and user agent token
   *
   * @return OCSPSourceBuilder
   */
  public static OCSPSourceBuilder defaultOCSPSource() {
    return new OCSPSourceBuilder(true);
  }

  /**
   * @return OCSPSourceBuilder
   */
  public static OCSPSourceBuilder anOcspSource() {
    return new OCSPSourceBuilder(false);
  }

  /**
   * @return OCSPSource
   */
  public OCSPSource build() {
    if (this.configuration == null) {
      this.configuration = ConfigurationSingeltonHolder.getInstance();
    }
    SkDataLoader loader = new SkOCSPDataLoader(this.configuration);
    SKOnlineOCSPSource source;
    if (this.defaultOCSPSource) {
      source = new CommonOCSPSource(this.configuration);
      loader.setUserAgent(Helper.createUserAgent());
    } else {
      if (SignatureProfile.LT_TM.equals(this.signatureProfile)) {
        source = new BDocTMOcspSource(this.configuration, this.signatureValue);
      } else {
        source = new CommonOCSPSource(this.configuration);
      }
      loader.setUserAgent(Helper.createBDocUserAgent(this.signatureProfile));
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
    if (this.defaultOCSPSource) {
      throw new IllegalStateException("Not applicable for default OCSP source");
    }
    this.signatureValue = signatureValue;
    return this;
  }

  /**
   * @param signatureProfile signature profile
   * @return OCSPSourceBuilder
   */
  public OCSPSourceBuilder withSignatureProfile(SignatureProfile signatureProfile) {
    if (this.defaultOCSPSource) {
      throw new IllegalStateException("Not applicable for default OCSP source");
    }
    this.signatureProfile = signatureProfile;
    return this;
  }

}
