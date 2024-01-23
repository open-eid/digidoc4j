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

import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import org.digidoc4j.AbstractTest;
import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertThrows;

public class MimeTypeUtilTest extends AbstractTest {

  @Test
  public void fromMimeTypeString_WhenInputIsNull_ThrowsException() {
    NullPointerException caughtException = assertThrows(
            NullPointerException.class,
            () -> MimeTypeUtil.fromMimeTypeString(null)
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("The mimeTypeString cannot be null!")
    );
  }

  @Test
  public void fromMimeTypeString_WhenInputCorrespondsToExistingMimeTypeEnumValue_ReturnsCorrespondingMimeTypeObject() {
    String mimeTypeString = MimeTypeEnum.TEXT.getMimeTypeString();

    MimeType result = MimeTypeUtil.fromMimeTypeString(mimeTypeString);

    assertThat(result, sameInstance(MimeTypeEnum.TEXT));
  }

  @Test
  public void fromMimeTypeString_WhenInputCorrespondsToNoMimeTypeEnumValue_ReturnsCustomMimeTypeObjectWithSpecifiedMimeTypeString() {
    String mimeTypeString = "foo/bar";

    MimeType result = MimeTypeUtil.fromMimeTypeString(mimeTypeString);

    assertThat(result, instanceOf(MimeTypeUtil.CustomMimeType.class));
    assertThat(result.getMimeTypeString(), equalTo(mimeTypeString));
    assertThat(result.getExtension(), nullValue());
  }

}
