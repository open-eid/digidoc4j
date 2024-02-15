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

import eu.europa.esig.dss.simplereport.jaxb.XmlMessage;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.Matchers;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import java.util.Objects;
import java.util.Optional;

public class IsSimpleReportXmlMessage extends TypeSafeDiagnosingMatcher<XmlMessage> {

  private static final String TYPE_NAME = XmlMessage.class.getSimpleName();

  private final Matcher<String> keyMatcher;
  private final Matcher<String> valueMatcher;

  public IsSimpleReportXmlMessage(Matcher<String> keyMatcher, Matcher<String> valueMatcher) {
    super(XmlMessage.class);
    this.keyMatcher = Objects.requireNonNull(keyMatcher);
    this.valueMatcher = Objects.requireNonNull(valueMatcher);
  }

  @Override
  protected boolean matchesSafely(XmlMessage item, Description mismatchDescription) {
    boolean result = true;
    if (!keyMatcher.matches(item.getKey())) {
      mismatchDescription.appendText(TYPE_NAME + " key ");
      keyMatcher.describeMismatch(item.getKey(), mismatchDescription);
      result = false;
    }
    if (!valueMatcher.matches(item.getValue())) {
      if (result) {
        mismatchDescription.appendText(TYPE_NAME + " value ");
      } else {
        mismatchDescription.appendText(" and value ");
      }
      valueMatcher.describeMismatch(item.getValue(), mismatchDescription);
      result = false;
    }
    return result;
  }

  @Override
  public void describeTo(Description description) {
    description.appendText(TYPE_NAME + " with key ").appendDescriptionOf(keyMatcher)
            .appendText(" and value ").appendDescriptionOf(valueMatcher);
  }

  public static Matcher<XmlMessage> messageWithKeyAndValue(Matcher<String> keyMatcher, Matcher<String> valueMatcher) {
    return new IsSimpleReportXmlMessage(keyMatcher, valueMatcher);
  }

  public static Matcher<XmlMessage> messageWithKeyAndValue(String key, String value) {
    return messageWithKeyAndValue(
            Optional.ofNullable(key).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class)),
            Optional.ofNullable(value).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class))
    );
  }

}
