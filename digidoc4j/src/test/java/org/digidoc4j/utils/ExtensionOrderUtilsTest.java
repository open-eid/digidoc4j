/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.utils;

import org.digidoc4j.SignatureProfile;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.digidoc4j.SignatureProfile.B_BES;
import static org.digidoc4j.SignatureProfile.B_EPES;
import static org.digidoc4j.SignatureProfile.LT_TM;
import static org.digidoc4j.SignatureProfile.T;
import static org.digidoc4j.SignatureProfile.LT;
import static org.digidoc4j.SignatureProfile.LTA;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;


public class ExtensionOrderUtilsTest {

  @Test
  public void getExtensionOrder_MinToMaxProfile_FullChainReturned() {
    List<SignatureProfile> order = ExtensionOrderUtils.getExtensionOrder(B_BES, LTA);

    assertEquals(Arrays.asList(B_BES, T, LT, LTA), order);
  }

  @Test
  public void getExtensionOrder_TToLT_PartialChainReturned() {
    List<SignatureProfile> order = ExtensionOrderUtils.getExtensionOrder(T, LT);

    assertEquals(Arrays.asList(T, LT), order);
  }

  @Test
  public void getExtensionOrder_LTAToLTA_ChainOfOneReturned() {
    List<SignatureProfile> order = ExtensionOrderUtils.getExtensionOrder(LTA, LTA);

    assertEquals(Collections.singletonList(LTA), order);
  }

  @Test
  public void getExtensionOrder_InvalidOrder_IllegalArgumentException() {
    IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> ExtensionOrderUtils.getExtensionOrder(LTA, B_BES));

    assertEquals("Not allowed to extend from LTA to B_BES", exception.getMessage());
  }

  @Test
  public void getExtensionOrder_UnsupportedSourceProfile_IllegalArgumentException() {
    IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> ExtensionOrderUtils.getExtensionOrder(LT_TM, LTA));

    assertEquals("Extension not applicable for profile LT_TM", exception.getMessage());
  }

  @Test
  public void getExtensionOrder_UnsupportedTargetProfile_IllegalArgumentException() {
    IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> ExtensionOrderUtils.getExtensionOrder(T, B_EPES));

    assertEquals("Extension not applicable for profile B_EPES", exception.getMessage());
  }

}
