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
import org.apache.commons.codec.binary.Base64;
import org.digidoc4j.impl.asic.cades.AsicArchiveManifest;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.Matchers;

import java.util.Optional;

public class IsAsicArchiveManifestDataReference extends IsAsicArchiveManifestReference<AsicArchiveManifest.DataReference> {

  private static final Class<AsicArchiveManifest.DataReference> TYPE = AsicArchiveManifest.DataReference.class;

  private final Matcher<String> digestAlgorithmMatcher;
  private final Matcher<String> digestValueMatcher;

  public IsAsicArchiveManifestDataReference(
          Matcher<String> uri,
          Matcher<String> name,
          Matcher<String> mimeType,
          Matcher<String> digestAlgorithm,
          Matcher<String> digestValue
  ) {
    super(AsicArchiveManifest.DataReference.class, uri, name, mimeType);
    digestAlgorithmMatcher = digestAlgorithm;
    digestValueMatcher = digestValue;
  }

  @Override
  protected boolean matchesSafely(AsicArchiveManifest.DataReference item, Description mismatchDescription) {
    boolean result = super.matchesSafely(item, mismatchDescription);
    if (digestAlgorithmMatcher != null && !digestAlgorithmMatcher.matches(item.getDigestAlgorithm())) {
      if (result) {
        mismatchDescription.appendText(type.getSimpleName() + " digest algorithm ");
      } else {
        mismatchDescription.appendText(" and digest algorithm ");
      }
      digestAlgorithmMatcher.describeMismatch(item.getDigestAlgorithm(), mismatchDescription);
      result = false;
    }
    if (digestValueMatcher != null && !digestValueMatcher.matches(item.getDigestValue())) {
      if (result) {
        mismatchDescription.appendText(type.getSimpleName() + " digest value ");
      } else {
        mismatchDescription.appendText(" and digest value ");
      }
      digestValueMatcher.describeMismatch(item.getDigestValue(), mismatchDescription);
      result = false;
    }
    return result;
  }

  @Override
  public void describeTo(Description description) {
    super.describeTo(description);
    boolean hasSubMatcher = (uriMatcher != null) || (nameMatcher != null) || (mimeTypeMatcher != null);
    if (digestAlgorithmMatcher != null) {
      (hasSubMatcher ? description.appendText(" and digest algorithm ") : description.appendText(" with digest algorithm "))
              .appendDescriptionOf(digestAlgorithmMatcher);
      hasSubMatcher = true;
    }
    if (digestValueMatcher != null) {
      (hasSubMatcher ? description.appendText(" and digest value ") : description.appendText(" with digest value "))
              .appendDescriptionOf(digestValueMatcher);
    }
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithUri(Matcher<String> uriMatcher) {
    return isReferenceWithUri(TYPE, uriMatcher);
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithUri(String uri) {
    return isDataReferenceWithUri(
            Optional.ofNullable(uri).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class))
    );
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithName(Matcher<String> nameMatcher) {
    return isReferenceWithName(TYPE, nameMatcher);
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithName(String name) {
    return isDataReferenceWithName(
            Optional.ofNullable(name).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class))
    );
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithMimeType(Matcher<String> mimeTypeMatcher) {
    return isReferenceWithMimeType(TYPE, mimeTypeMatcher);
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithMimeType(String mimeType) {
    return isDataReferenceWithMimeType(
            Optional.ofNullable(mimeType).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class))
    );
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithMimeType(MimeType mimeType) {
    return isDataReferenceWithMimeType(
            Optional.ofNullable(mimeType).map(MimeType::getMimeTypeString).orElse(null)
    );
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithDigestAlgorithm(Matcher<String> digestAlgorithmMatcher) {
    return new IsAsicArchiveManifestDataReference(
            null,
            null,
            null,
            digestAlgorithmMatcher,
            null
    );
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithDigestAlgorithm(String digestAlgorithm) {
    return isDataReferenceWithDigestAlgorithm(
            Optional.ofNullable(digestAlgorithm).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class))
    );
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithDigestAlgorithm(
          eu.europa.esig.dss.enumerations.DigestAlgorithm digestAlgorithm
  ) {
    return isDataReferenceWithDigestAlgorithm(Optional.ofNullable(digestAlgorithm)
            .map(eu.europa.esig.dss.enumerations.DigestAlgorithm::getUri).orElse(null));
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithDigestAlgorithm(
          org.digidoc4j.DigestAlgorithm digestAlgorithm
  ) {
    return isDataReferenceWithDigestAlgorithm(Optional.ofNullable(digestAlgorithm)
            .map(org.digidoc4j.DigestAlgorithm::getDssDigestAlgorithm).orElse(null));
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithDigestValue(Matcher<String> digestValueMatcher) {
    return new IsAsicArchiveManifestDataReference(
            null,
            null,
            null,
            null,
            digestValueMatcher
    );
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithDigestValue(String digestValue) {
    return isDataReferenceWithDigestValue(
            Optional.ofNullable(digestValue).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class))
    );
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithDigestValue(byte[] digestValue) {
    return isDataReferenceWithDigestValue(
            Optional.ofNullable(digestValue).map(Base64::encodeBase64String).orElse(null)
    );
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithUriAndName(
          Matcher<String> uriMatcher,
          Matcher<String> nameMatcher
  ) {
    return isReferenceWithUriAndName(TYPE, uriMatcher, nameMatcher);
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithUriAndName(
          String uri,
          String name
  ) {
    return isDataReferenceWithUriAndName(
            Optional.ofNullable(uri).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class)),
            Optional.ofNullable(name).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class))
    );
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithUriAndMimeType(
          Matcher<String> uriMatcher,
          Matcher<String> mimeTypeMatcher
  ) {
    return isReferenceWithUriAndMimeType(TYPE, uriMatcher, mimeTypeMatcher);
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithUriAndMimeType(
          String uri,
          String mimeType
  ) {
    return isDataReferenceWithUriAndMimeType(
            Optional.ofNullable(uri).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class)),
            Optional.ofNullable(mimeType).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class))
    );
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithUriAndMimeType(
          String uri,
          MimeType mimeType
  ) {
    return isDataReferenceWithUriAndMimeType(uri, Optional
            .ofNullable(mimeType).map(MimeType::getMimeTypeString).orElse(null));
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithNameAndMimeType(
          Matcher<String> nameMatcher,
          Matcher<String> mimeTypeMatcher
  ) {
    return isReferenceWithNameAndMimeType(TYPE, nameMatcher, mimeTypeMatcher);
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithNameAndMimeType(
          String name,
          String mimeType
  ) {
    return isDataReferenceWithNameAndMimeType(
            Optional.ofNullable(name).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class)),
            Optional.ofNullable(mimeType).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class))
    );
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithNameAndMimeType(
          String name,
          MimeType mimeType
  ) {
    return isDataReferenceWithNameAndMimeType(name, Optional
            .ofNullable(mimeType).map(MimeType::getMimeTypeString).orElse(null));
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithNameAndDigestAlgorithm(
          Matcher<String> nameMatcher,
          Matcher<String> digestAlgorithmMatcher
  ) {
    return new IsAsicArchiveManifestDataReference(
            null,
            nameMatcher,
            null,
            digestAlgorithmMatcher,
            null
    );
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithNameAndDigestAlgorithm(
          String name,
          String digestAlgorithm
  ) {
    return isDataReferenceWithNameAndDigestAlgorithm(
            Optional.ofNullable(name).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class)),
            Optional.ofNullable(digestAlgorithm).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class))
    );
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithNameAndDigestAlgorithm(
          String name,
          eu.europa.esig.dss.enumerations.DigestAlgorithm digestAlgorithm
  ) {
    return isDataReferenceWithNameAndDigestAlgorithm(name, Optional.ofNullable(digestAlgorithm)
            .map(eu.europa.esig.dss.enumerations.DigestAlgorithm::getUri).orElse(null));
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithNameAndDigestAlgorithm(
          String name,
          org.digidoc4j.DigestAlgorithm digestAlgorithm
  ) {
    return isDataReferenceWithNameAndDigestAlgorithm(name, Optional.ofNullable(digestAlgorithm)
            .map(org.digidoc4j.DigestAlgorithm::getDssDigestAlgorithm).orElse(null));
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithNameAndMimeTypeAndDigestAlgorithm(
          Matcher<String> nameMatcher,
          Matcher<String> mimeTypeMatcher,
          Matcher<String> digestAlgorithmMatcher
  ) {
    return new IsAsicArchiveManifestDataReference(
            null,
            nameMatcher,
            mimeTypeMatcher,
            digestAlgorithmMatcher,
            null
    );
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithNameAndMimeTypeAndDigestAlgorithm(
          String name,
          String mimeType,
          String digestAlgorithm
  ) {
    return isDataReferenceWithNameAndMimeTypeAndDigestAlgorithm(
            Optional.ofNullable(name).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class)),
            Optional.ofNullable(mimeType).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class)),
            Optional.ofNullable(digestAlgorithm).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class))
    );
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithNameAndMimeTypeAndDigestAlgorithm(
          String name,
          MimeType mimeType,
          eu.europa.esig.dss.enumerations.DigestAlgorithm digestAlgorithm
  ) {
    return isDataReferenceWithNameAndMimeTypeAndDigestAlgorithm(name,
            Optional.ofNullable(mimeType).map(MimeType::getMimeTypeString).orElse(null),
            Optional.ofNullable(digestAlgorithm).map(eu.europa.esig.dss.enumerations.DigestAlgorithm::getUri).orElse(null)
    );
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithNameAndMimeTypeAndDigestAlgorithm(
          String name,
          MimeType mimeType,
          org.digidoc4j.DigestAlgorithm digestAlgorithm
  ) {
    return isDataReferenceWithNameAndMimeTypeAndDigestAlgorithm(name, mimeType, Optional
            .ofNullable(digestAlgorithm).map(org.digidoc4j.DigestAlgorithm::getDssDigestAlgorithm).orElse(null)
    );
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithDigestAlgorithmAndValue(
          Matcher<String> digestAlgorithmMatcher,
          Matcher<String> digestValueMatcher
  ) {
    return new IsAsicArchiveManifestDataReference(
            null,
            null,
            null,
            digestAlgorithmMatcher,
            digestValueMatcher
    );
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithDigestAlgorithmAndValue(
          String digestAlgorithm,
          String digestValue
  ) {
    return isDataReferenceWithDigestAlgorithmAndValue(
            Optional.ofNullable(digestAlgorithm).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class)),
            Optional.ofNullable(digestValue).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class))
    );
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithDigestAlgorithmAndValue(
          eu.europa.esig.dss.enumerations.DigestAlgorithm digestAlgorithm,
          String digestValue
  ) {
    return isDataReferenceWithDigestAlgorithmAndValue(Optional.ofNullable(digestAlgorithm)
            .map(eu.europa.esig.dss.enumerations.DigestAlgorithm::getUri).orElse(null), digestValue);
  }

  public static Matcher<AsicArchiveManifest.DataReference> isDataReferenceWithDigestAlgorithmAndValue(
          org.digidoc4j.DigestAlgorithm digestAlgorithm,
          String digestValue
  ) {
    return isDataReferenceWithDigestAlgorithmAndValue(Optional.ofNullable(digestAlgorithm)
            .map(org.digidoc4j.DigestAlgorithm::getDssDigestAlgorithm).orElse(null), digestValue);
  }

}
