/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ManifestEntryTest {

  @Test
  public void manifestEntryEquals() throws Exception {
    assertTrue(new ManifestEntry("fail.txt", "text/plain").equals(new ManifestEntry("fail.txt", "text/plain")));
  }

  @Test
  public void manifestEntryEqualsWhenMimeTypeIsWrong() throws Exception {
    assertFalse(new ManifestEntry("fail.txt", "text/plain").equals(new ManifestEntry("fail.txt", "text/xml")));
  }

  @Test
  public void manifestEntryEqualsWhenFileNameIsWrong() throws Exception {
    assertFalse(new ManifestEntry("fail.txt", "text/plain").equals(new ManifestEntry("fail1.txt", "text/plain")));
  }
}
