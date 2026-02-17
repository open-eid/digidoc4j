/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.asic.manifest;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class ManifestEntryTest {

  @Test
  void manifestEntryEquals() {
    assertEquals(new ManifestEntry("fail.txt", "text/plain"), new ManifestEntry("fail.txt", "text/plain"));
  }

  @Test
  void manifestEntryEqualsWhenMimeTypeIsWrong() {
    assertNotEquals(new ManifestEntry("fail.txt", "text/plain"), new ManifestEntry("fail.txt", "text/xml"));
  }

  @Test
  void manifestEntryEqualsWhenFileNameIsWrong() {
    assertNotEquals(new ManifestEntry("fail.txt", "text/plain"), new ManifestEntry("fail1.txt", "text/plain"));
  }

}
