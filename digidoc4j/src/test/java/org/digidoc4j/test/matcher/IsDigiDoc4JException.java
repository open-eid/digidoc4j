/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.test.matcher;

import org.digidoc4j.exceptions.DigiDoc4JException;
import org.hamcrest.Matcher;
import org.hamcrest.Matchers;

public class IsDigiDoc4JException<T extends DigiDoc4JException> extends ThrowableMatcher<T> {

  public IsDigiDoc4JException(
          Class<T> expectedType,
          Matcher<String> messageMatcher,
          Matcher<? extends Throwable> causeMatcher
  ) {
    super(expectedType, messageMatcher, causeMatcher);
  }

  public static <T extends DigiDoc4JException> Matcher<T> digiDoc4JExceptionOfTypeWithMessage(
          Class<T> expectedType,
          Matcher<String> messageMatcher
  ) {
    return new IsDigiDoc4JException<>(expectedType, messageMatcher, null);
  }

  public static Matcher<DigiDoc4JException> digiDoc4JExceptionWithMessage(Matcher<String> messageMatcher) {
    return digiDoc4JExceptionOfTypeWithMessage(DigiDoc4JException.class, messageMatcher);
  }

  public static Matcher<DigiDoc4JException> digiDoc4JExceptionWithMessage(String message) {
    return digiDoc4JExceptionWithMessage(Matchers.equalTo(message));
  }

  public static Matcher<DigiDoc4JException> digiDoc4JExceptionMessageContainsString(String messageSubstring) {
    return digiDoc4JExceptionWithMessage(Matchers.containsString(messageSubstring));
  }

}
