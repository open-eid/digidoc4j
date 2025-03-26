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

  private static final Class<AsicArchiveManifest.Reference> TYPE = AsicArchiveManifest.Reference.class;

  protected final Class<T> type;
  protected final Matcher<String> uriMatcher;
  protected final Matcher<String> nameMatcher;
  protected final Matcher<String> mimeTypeMatcher;

  public IsAsicArchiveManifestReference(
          Class<T> type,
          Matcher<String> uri,
          Matcher<String> name,
          Matcher<String> mimeType
  ) {
    super(Objects.requireNonNull(type));
    this.type = type;
    uriMatcher = uri;
    nameMatcher = name;
    mimeTypeMatcher = mimeType;
  }

  @Override
  protected boolean matchesSafely(T item, Description mismatchDescription) {
    boolean result = true;
    if (uriMatcher != null && !uriMatcher.matches(item.getUri())) {
      mismatchDescription.appendText(type.getSimpleName() + " uri ");
      uriMatcher.describeMismatch(item.getUri(), mismatchDescription);
      result = false;
    }
    if (nameMatcher != null && !nameMatcher.matches(item.getName())) {
      if (result) {
        mismatchDescription.appendText(type.getSimpleName() + " name ");
      } else {
        mismatchDescription.appendText(" and name ");
      }
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
    if (uriMatcher != null) {
      description.appendText(" with uri ").appendDescriptionOf(uriMatcher);
      hasSubMatcher = true;
    }
    if (nameMatcher != null) {
      (hasSubMatcher ? description.appendText(" and name ") : description.appendText(" with name "))
              .appendDescriptionOf(nameMatcher);
      hasSubMatcher = true;
    }
    if (mimeTypeMatcher != null) {
      (hasSubMatcher ? description.appendText(" and mimetype ") : description.appendText(" with mimetype "))
              .appendDescriptionOf(mimeTypeMatcher);
    }
  }

  protected static <T extends AsicArchiveManifest.Reference> Matcher<T> isReferenceWithUri(
          Class<T> type,
          Matcher<String> uriMatcher
  ) {
    return new IsAsicArchiveManifestReference<>(type, uriMatcher, null, null);
  }

  public static Matcher<AsicArchiveManifest.Reference> isReferenceWithUri(Matcher<String> uriMatcher) {
    return isReferenceWithUri(TYPE, uriMatcher);
  }

  public static Matcher<AsicArchiveManifest.Reference> isReferenceWithUri(String uri) {
    return isReferenceWithUri(
            Optional.ofNullable(uri).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class))
    );
  }

  protected static <T extends AsicArchiveManifest.Reference> Matcher<T> isReferenceWithName(
          Class<T> type,
          Matcher<String> nameMatcher
  ) {
    return new IsAsicArchiveManifestReference<>(type, null, nameMatcher, null);
  }

  public static Matcher<AsicArchiveManifest.Reference> isReferenceWithName(Matcher<String> nameMatcher) {
    return isReferenceWithName(TYPE, nameMatcher);
  }

  public static Matcher<AsicArchiveManifest.Reference> isReferenceWithName(String name) {
    return isReferenceWithName(
            Optional.ofNullable(name).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class))
    );
  }

  protected static <T extends AsicArchiveManifest.Reference> Matcher<T> isReferenceWithMimeType(
          Class<T> type,
          Matcher<String> mimeTypeMatcher
  ) {
    return new IsAsicArchiveManifestReference<>(type, null, null, mimeTypeMatcher);
  }

  public static Matcher<AsicArchiveManifest.Reference> isReferenceWithMimeType(Matcher<String> mimeTypeMatcher) {
    return isReferenceWithMimeType(TYPE, mimeTypeMatcher);
  }

  public static Matcher<AsicArchiveManifest.Reference> isReferenceWithMimeType(String mimeType) {
    return isReferenceWithMimeType(
            Optional.ofNullable(mimeType).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class))
    );
  }

  public static Matcher<AsicArchiveManifest.Reference> isReferenceWithMimeType(MimeType mimeType) {
    return isReferenceWithMimeType(Optional.ofNullable(mimeType).map(MimeType::getMimeTypeString).orElse(null));
  }

  protected static <T extends AsicArchiveManifest.Reference> Matcher<T> isReferenceWithUriAndName(
          Class<T> type,
          Matcher<String> uriMatcher,
          Matcher<String> nameMatcher
  ) {
    return new IsAsicArchiveManifestReference<>(type, uriMatcher, nameMatcher, null);
  }

  public static Matcher<AsicArchiveManifest.Reference> isReferenceWithUriAndName(
          Matcher<String> uriMatcher,
          Matcher<String> nameMatcher
  ) {
    return isReferenceWithUriAndName(TYPE, uriMatcher, nameMatcher);
  }

  protected static <T extends AsicArchiveManifest.Reference> Matcher<T> isReferenceWithUriAndMimeType(
          Class<T> type,
          Matcher<String> uriMatcher,
          Matcher<String> mimeTypeMatcher
  ) {
    return new IsAsicArchiveManifestReference<>(type, uriMatcher, null, mimeTypeMatcher);
  }

  public static Matcher<AsicArchiveManifest.Reference> isReferenceWithUriAndMimeType(
          Matcher<String> uriMatcher,
          Matcher<String> mimeTypeMatcher
  ) {
    return isReferenceWithUriAndMimeType(TYPE, uriMatcher, mimeTypeMatcher);
  }

  public static Matcher<AsicArchiveManifest.Reference> isReferenceWithUriAndMimeType(
          String uri,
          String mimeType
  ) {
    return isReferenceWithUriAndMimeType(
            Optional.ofNullable(uri).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class)),
            Optional.ofNullable(mimeType).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class))
    );
  }

  public static Matcher<AsicArchiveManifest.Reference> isReferenceWithUriAndMimeType(
          String uri,
          MimeType mimeType
  ) {
    return isReferenceWithUriAndMimeType(uri, Optional
            .ofNullable(mimeType).map(MimeType::getMimeTypeString).orElse(null));
  }

  protected static <T extends AsicArchiveManifest.Reference> Matcher<T> isReferenceWithNameAndMimeType(
          Class<T> type,
          Matcher<String> nameMatcher,
          Matcher<String> mimeTypeMatcher
  ) {
    return new IsAsicArchiveManifestReference<>(type, null, nameMatcher, mimeTypeMatcher);
  }

  public static Matcher<AsicArchiveManifest.Reference> isReferenceWithNameAndMimeType(
          Matcher<String> nameMatcher,
          Matcher<String> mimeTypeMatcher
  ) {
    return isReferenceWithNameAndMimeType(TYPE, nameMatcher, mimeTypeMatcher);
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
