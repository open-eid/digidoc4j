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

import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import java.util.Objects;

public abstract class ThrowableMatcher<T extends Throwable> extends TypeSafeDiagnosingMatcher<T> {

  protected final Matcher<String> messageMatcher;
  protected final Matcher<? extends Throwable> causeMatcher;
  protected final String typeName;

  protected ThrowableMatcher(
          Class<T> expectedType,
          Matcher<String> messageMatcher,
          Matcher<? extends Throwable> causeMatcher
  ) {
    super(Objects.requireNonNull(expectedType));
    this.messageMatcher = Objects.requireNonNull(messageMatcher);
    this.causeMatcher = causeMatcher;
    this.typeName = expectedType.getSimpleName();
  }

  @Override
  protected boolean matchesSafely(T item, Description mismatchDescription) {
    if (!messageMatcher.matches(item.getMessage())) {
      mismatchDescription.appendText(typeName + " message ");
      messageMatcher.describeMismatch(item, mismatchDescription);
      return false;
    }
    if (causeMatcher != null && !causeMatcher.matches(item.getCause())) {
      mismatchDescription.appendText(typeName + " cause ");
      causeMatcher.describeMismatch(item, mismatchDescription);
      return false;
    }
    return true;
  }

  @Override
  public void describeTo(Description description) {
    description.appendText(typeName + " with message ").appendDescriptionOf(messageMatcher);
    if (causeMatcher != null) {
      description.appendText(" and with cause ").appendDescriptionOf(causeMatcher);
    }
  }

}
