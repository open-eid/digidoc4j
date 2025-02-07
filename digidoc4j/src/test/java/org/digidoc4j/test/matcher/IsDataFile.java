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

import eu.europa.esig.dss.enumerations.MimeType;
import org.digidoc4j.DataFile;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.Matchers;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import java.util.Optional;

public class IsDataFile extends TypeSafeDiagnosingMatcher<DataFile> {

  private static final String TYPE_NAME = DataFile.class.getSimpleName();

  private final Matcher<String> nameMatcher;
  private final Matcher<String> mediaTypeMatcher;

  public IsDataFile(Matcher<String> name, Matcher<String> mediaType) {
    nameMatcher = name;
    mediaTypeMatcher = mediaType;
  }

  @Override
  protected boolean matchesSafely(DataFile item, Description mismatchDescription) {
    boolean result = true;
    if (nameMatcher != null && !nameMatcher.matches(item.getName())) {
      mismatchDescription.appendText(TYPE_NAME + " name ");
      nameMatcher.describeMismatch(item.getName(), mismatchDescription);
      result = false;
    }
    if (mediaTypeMatcher != null && !mediaTypeMatcher.matches(item.getMediaType())) {
      if (result) {
        mismatchDescription.appendText(TYPE_NAME + " media type ");
      } else {
        mismatchDescription.appendText(" and media type ");
      }
      mediaTypeMatcher.describeMismatch(item.getMediaType(), mismatchDescription);
      result = false;
    }
    return result;
  }

  @Override
  public void describeTo(Description description) {
    description.appendText(TYPE_NAME);
    boolean hasSubMatcher = false;
    if (nameMatcher != null) {
      description.appendText(" with name ").appendDescriptionOf(nameMatcher);
      hasSubMatcher = true;
    }
    if (mediaTypeMatcher != null) {
      (hasSubMatcher ? description.appendText(" and media type ") : description.appendText(" with media type "))
              .appendDescriptionOf(mediaTypeMatcher);
    }
  }

  public static Matcher<DataFile> isDataFileWithName(Matcher<String> nameMatcher) {
    return new IsDataFile(nameMatcher, null);
  }

  public static Matcher<DataFile> isDataFileWithName(String name) {
    return isDataFileWithName(Optional.ofNullable(name)
            .map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class)));
  }

  public static Matcher<DataFile> isDataFileWithMediaType(Matcher<String> mediaTypeMatcher) {
    return new IsDataFile(null, mediaTypeMatcher);
  }

  public static Matcher<DataFile> isDataFileWithMediaType(String mediaType) {
    return isDataFileWithMediaType(Optional.ofNullable(mediaType)
            .map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class)));
  }

  public static Matcher<DataFile> isDataFileWithMediaType(MimeType mediaType) {
    return isDataFileWithMediaType(Optional.ofNullable(mediaType)
            .map(MimeType::getMimeTypeString).orElse(null));
  }

  public static Matcher<DataFile> isDataFileWithNameAndMediaType(
          Matcher<String> nameMatcher,
          Matcher<String> mediaTypeMatcher
  ) {
    return new IsDataFile(nameMatcher, mediaTypeMatcher);
  }

  public static Matcher<DataFile> isDataFileWithNameAndMediaType(
          String name,
          String mediaType
  ) {
    return isDataFileWithNameAndMediaType(
            Optional.ofNullable(name).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class)),
            Optional.ofNullable(mediaType).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class))
    );
  }

  public static Matcher<DataFile> isDataFileWithNameAndMediaType(
          String name,
          MimeType mediaType
  ) {
    return isDataFileWithNameAndMediaType(name, Optional
            .ofNullable(mediaType).map(MimeType::getMimeTypeString).orElse(null));
  }

}
