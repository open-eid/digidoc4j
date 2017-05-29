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

import static org.digidoc4j.impl.bdoc.ocsp.OcspSourceBuilder.anOcspSource;
import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThat;

import org.digidoc4j.Configuration;
import org.digidoc4j.SignatureProfile;
import org.junit.Test;

public class OcspSourceBuilderTest {

  public static final Configuration CONFIGURATION = new Configuration(Configuration.Mode.TEST);

  @Test
  public void buildTimeStampOcspSource_whenProfileIsNotSet() throws Exception {
    SKOnlineOCSPSource ocspSource = anOcspSource().
        withConfiguration(CONFIGURATION).
        build();
    assertEquals(BDocTSOcspSource.class, ocspSource.getClass());
    assertOcspSource(ocspSource, "XAdES_BASELINE_LT");
  }

  @Test
  public void buildTimeStampOcspSource() throws Exception {
    SKOnlineOCSPSource ocspSource = anOcspSource().
        withSignatureProfile(SignatureProfile.LT).
        withConfiguration(CONFIGURATION).
        build();
    assertEquals(BDocTSOcspSource.class, ocspSource.getClass());
    assertOcspSource(ocspSource, "XAdES_BASELINE_LT");
  }

  @Test
  public void buildTimeMarkOcspSource() throws Exception {
    SKOnlineOCSPSource ocspSource = anOcspSource().
        withSignatureProfile(SignatureProfile.LT_TM).
        withSignatureValue(new byte[]{1, 2, 3}).
        withConfiguration(CONFIGURATION).
        build();
    assertEquals(BDocTMOcspSource.class, ocspSource.getClass());
    assertOcspSource(ocspSource, "ASiC_E_BASELINE_LT_TM");

  }

  private void assertOcspSource(SKOnlineOCSPSource ocspSource, String userAgentPart) {
    assertSame(CONFIGURATION, ocspSource.getConfiguration());
    assertNotNull(ocspSource.getDataLoader());
    assertThat(ocspSource.getDataLoader().getUserAgent(), containsString(userAgentPart));
  }
}
