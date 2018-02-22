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

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.OCSPSourceBuilder;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.impl.CommonOCSPSource;
import org.digidoc4j.impl.SKOnlineOCSPSource;
import org.digidoc4j.impl.asic.ocsp.BDocTMOcspSource;
import org.digidoc4j.test.TestAssert;
import org.junit.Assert;
import org.junit.Test;

public class OCSPSourceBuilderTest extends AbstractTest {

  @Test
  public void buildTimestampOCSPSource_whenProfileIsNotSet() throws Exception {
    SKOnlineOCSPSource source = (SKOnlineOCSPSource) OCSPSourceBuilder.anOcspSource().withConfiguration(
        this.configuration).build();
    Assert.assertEquals(CommonOCSPSource.class, source.getClass());
    TestAssert.assertOCSPSource(this.configuration, source, "XAdES_BASELINE_LT");
  }

  @Test
  public void buildTimestampOCSPSource() throws Exception {
    SKOnlineOCSPSource source = (SKOnlineOCSPSource) OCSPSourceBuilder.anOcspSource().withSignatureProfile(
        SignatureProfile.LT).withConfiguration(this.configuration).build();
    Assert.assertEquals(CommonOCSPSource.class, source.getClass());
    TestAssert.assertOCSPSource(this.configuration, source, "XAdES_BASELINE_LT");
  }

  @Test
  public void buildTimemarkOCSPSource() throws Exception {
    SKOnlineOCSPSource source = (SKOnlineOCSPSource) OCSPSourceBuilder.anOcspSource().withSignatureProfile(
        SignatureProfile.LT_TM).withSignatureValue(new byte[]{1, 2, 3}).withConfiguration(this.configuration).build();
    Assert.assertEquals(BDocTMOcspSource.class, source.getClass());
    TestAssert.assertOCSPSource(this.configuration, source, "ASiC_E_BASELINE_LT_TM");
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.configuration = new Configuration(Configuration.Mode.TEST);
  }

}
