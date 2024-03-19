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
import org.hamcrest.TypeSafeMatcher;

import java.util.regex.Pattern;

public class ContainsPattern extends TypeSafeMatcher<String> {

  private final Pattern pattern;

  public ContainsPattern(Pattern pattern) {
    this.pattern = pattern;
  }

  protected boolean matchesSafely(String item) {
    return this.pattern.matcher(item).find();
  }

  public void describeTo(Description description) {
    description.appendText("a string containing the pattern '" + this.pattern + "'");
  }

  public static Matcher<String> containsPattern(Pattern pattern) {
    return new ContainsPattern(pattern);
  }

  public static Matcher<String> containsPattern(String regex) {
    return new ContainsPattern(Pattern.compile(regex));
  }

}
