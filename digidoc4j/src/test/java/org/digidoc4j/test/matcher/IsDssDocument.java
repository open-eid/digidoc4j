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
import eu.europa.esig.dss.model.DSSDocument;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.Matchers;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import java.util.Optional;

public class IsDssDocument extends TypeSafeDiagnosingMatcher<DSSDocument> {

  private static final String TYPE_NAME = DSSDocument.class.getSimpleName();

  private final Matcher<String> nameMatcher;
  private final Matcher<MimeType> mimeTypeMatcher;

  public IsDssDocument(Matcher<String> name, Matcher<MimeType> mimeType) {
    nameMatcher = name;
    mimeTypeMatcher = mimeType;
  }

  @Override
  protected boolean matchesSafely(DSSDocument item, Description mismatchDescription) {
    boolean result = true;
    if (nameMatcher != null && !nameMatcher.matches(item.getName())) {
      mismatchDescription.appendText(TYPE_NAME + " name ");
      nameMatcher.describeMismatch(item.getName(), mismatchDescription);
      result = false;
    }
    if (mimeTypeMatcher != null && !mimeTypeMatcher.matches(item.getMimeType())) {
      if (result) {
        mismatchDescription.appendText(TYPE_NAME + " mimetype ");
      } else {
        mismatchDescription.appendText(" and mimetype ");
      }
      mimeTypeMatcher.describeMismatch(item.getMimeType(), mismatchDescription);
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
    if (mimeTypeMatcher != null) {
      (hasSubMatcher ? description.appendText(" and mimetype ") : description.appendText(" with mimetype "))
              .appendDescriptionOf(mimeTypeMatcher);
    }
  }

  public static Matcher<DSSDocument> isDocumentWithName(Matcher<String> nameMatcher) {
    return new IsDssDocument(nameMatcher, null);
  }

  public static Matcher<DSSDocument> isDocumentWithName(String name) {
    return isDocumentWithName(Optional.ofNullable(name)
            .map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class)));
  }

  public static Matcher<DSSDocument> isDocumentWithMimeType(Matcher<MimeType> mimeTypeMatcher) {
    return new IsDssDocument(null, mimeTypeMatcher);
  }

  public static Matcher<DSSDocument> isDocumentWithMimeType(MimeType mimeType) {
    return isDocumentWithMimeType(Optional.ofNullable(mimeType)
            .map(Matchers::sameInstance).orElseGet(() -> Matchers.nullValue(MimeType.class)));
  }

  public static Matcher<DSSDocument> isDocumentWithNameAndMimeType(
          Matcher<String> nameMatcher,
          Matcher<MimeType> mimeTypeMatcher
  ) {
    return new IsDssDocument(nameMatcher, mimeTypeMatcher);
  }

  public static Matcher<DSSDocument> isDocumentWithNameAndMimeType(
          String name,
          MimeType mimeType
  ) {
    return isDocumentWithNameAndMimeType(
            Optional.ofNullable(name).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class)),
            Optional.ofNullable(mimeType).map(Matchers::sameInstance).orElseGet(() -> Matchers.nullValue(MimeType.class))
    );
  }

}
