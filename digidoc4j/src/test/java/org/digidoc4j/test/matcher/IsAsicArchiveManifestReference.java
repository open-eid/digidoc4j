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
import org.digidoc4j.impl.asic.cades.AsicArchiveManifest;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.Matchers;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import java.util.Objects;
import java.util.Optional;

public class IsAsicArchiveManifestReference<T extends AsicArchiveManifest.Reference> extends TypeSafeDiagnosingMatcher<T> {

  protected final Class<T> type;
  protected final Matcher<String> nameMatcher;
  protected final Matcher<String> mimeTypeMatcher;

  public IsAsicArchiveManifestReference(Class<T> type, Matcher<String> name, Matcher<String> mimeType) {
    this.type = Objects.requireNonNull(type);
    nameMatcher = name;
    mimeTypeMatcher = mimeType;
  }

  @Override
  protected boolean matchesSafely(T item, Description mismatchDescription) {
    boolean result = true;
    if (nameMatcher != null && !nameMatcher.matches(item.getName())) {
      mismatchDescription.appendText(type.getSimpleName() + " name ");
      nameMatcher.describeMismatch(item.getName(), mismatchDescription);
      result = false;
    }
    if (mimeTypeMatcher != null && !mimeTypeMatcher.matches(item.getMimeType())) {
      if (result) {
        mismatchDescription.appendText(type.getSimpleName() + " mimetype ");
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
    description.appendText(type.getSimpleName());
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

  public static Matcher<AsicArchiveManifest.Reference> isReferenceWithName(Matcher<String> nameMatcher) {
    return new IsAsicArchiveManifestReference<>(AsicArchiveManifest.Reference.class, nameMatcher, null);
  }

  public static Matcher<AsicArchiveManifest.Reference> isReferenceWithName(String name) {
    return isReferenceWithName(
            Optional.ofNullable(name).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class))
    );
  }

  public static Matcher<AsicArchiveManifest.Reference> isReferenceWithMimeType(Matcher<String> mimeTypeMatcher) {
    return new IsAsicArchiveManifestReference<>(AsicArchiveManifest.Reference.class, null, mimeTypeMatcher);
  }

  public static Matcher<AsicArchiveManifest.Reference> isReferenceWithMimeType(String mimeType) {
    return isReferenceWithMimeType(
            Optional.ofNullable(mimeType).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class))
    );
  }

  public static Matcher<AsicArchiveManifest.Reference> isReferenceWithMimeType(MimeType mimeType) {
    return isReferenceWithMimeType(Optional.ofNullable(mimeType).map(MimeType::getMimeTypeString).orElse(null));
  }

  public static Matcher<AsicArchiveManifest.Reference> isReferenceWithNameAndMimeType(
          Matcher<String> nameMatcher,
          Matcher<String> mimeTypeMatcher
  ) {
    return new IsAsicArchiveManifestReference<>(AsicArchiveManifest.Reference.class, nameMatcher, mimeTypeMatcher);
  }

  public static Matcher<AsicArchiveManifest.Reference> isReferenceWithNameAndMimeType(
          String name,
          String mimeType
  ) {
    return isReferenceWithNameAndMimeType(
            Optional.ofNullable(name).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class)),
            Optional.ofNullable(mimeType).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class))
    );
  }

  public static Matcher<AsicArchiveManifest.Reference> isReferenceWithNameAndMimeType(
          String name,
          MimeType mimeType
  ) {
    return isReferenceWithNameAndMimeType(name, Optional
            .ofNullable(mimeType).map(MimeType::getMimeTypeString).orElse(null));
  }

}
