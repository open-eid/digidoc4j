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
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.impl.asic.ocsp.BDocTMOcspSource;
import org.digidoc4j.impl.asic.ocsp.BDocTSOcspSource;
import org.digidoc4j.impl.asic.ocsp.OcspSourceBuilder;
import org.digidoc4j.impl.asic.ocsp.SKOnlineOCSPSource;
import org.digidoc4j.test.Refactored;
import org.digidoc4j.testutils.TestAssert;
import org.junit.Assert;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Refactored.class)
public class OcspSourceBuilderTest extends AbstractTest {

  @Test
  public void buildTimeStampOcspSource_whenProfileIsNotSet() throws Exception {
    SKOnlineOCSPSource ocspSource = OcspSourceBuilder.anOcspSource().withConfiguration(this.configuration).
        build();
    Assert.assertEquals(BDocTSOcspSource.class, ocspSource.getClass());
    TestAssert.assertOCSPSource(this.configuration, ocspSource, "XAdES_BASELINE_LT");
  }

  @Test
  public void buildTimeStampOcspSource() throws Exception {
    SKOnlineOCSPSource ocspSource = OcspSourceBuilder.anOcspSource().withSignatureProfile(SignatureProfile.LT)
        .withConfiguration(this.configuration).build();
    Assert.assertEquals(BDocTSOcspSource.class, ocspSource.getClass());
    TestAssert.assertOCSPSource(this.configuration, ocspSource, "XAdES_BASELINE_LT");
  }

  @Test
  public void buildTimeMarkOcspSource() throws Exception {
    SKOnlineOCSPSource ocspSource = OcspSourceBuilder.anOcspSource().withSignatureProfile(SignatureProfile.LT_TM).
        withSignatureValue(new byte[]{1, 2, 3}).withConfiguration(this.configuration).build();
    Assert.assertEquals(BDocTMOcspSource.class, ocspSource.getClass());
    TestAssert.assertOCSPSource(this.configuration, ocspSource, "ASiC_E_BASELINE_LT_TM");
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.configuration = new Configuration(Configuration.Mode.TEST);
  }

}
