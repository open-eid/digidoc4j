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

import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.Matchers;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import java.util.Objects;
import java.util.Optional;

public class IsSimpleReportXmlSignatureScope extends TypeSafeDiagnosingMatcher<XmlSignatureScope> {

  private static final String TYPE_NAME = XmlSignatureScope.class.getSimpleName();

  private final Matcher<String> idMatcher;
  private final Matcher<String> nameMatcher;
  private final Matcher<SignatureScopeType> scopeMatcher;
  private final Matcher<String> valueMatcher;

  public IsSimpleReportXmlSignatureScope(
          Matcher<String> idMatcher,
          Matcher<String> nameMatcher,
          Matcher<SignatureScopeType> scopeMatcher,
          Matcher<String> valueMatcher
  ) {
    super(XmlSignatureScope.class);
    this.idMatcher = Objects.requireNonNull(idMatcher);
    this.nameMatcher = Objects.requireNonNull(nameMatcher);
    this.scopeMatcher = Objects.requireNonNull(scopeMatcher);
    this.valueMatcher = valueMatcher;
  }

  @Override
  protected boolean matchesSafely(XmlSignatureScope item, Description mismatchDescription) {
    boolean result = true;
    if (!idMatcher.matches(item.getId())) {
      mismatchDescription.appendText(TYPE_NAME + " id ");
      idMatcher.describeMismatch(item.getId(), mismatchDescription);
      result = false;
    }
    if (!nameMatcher.matches(item.getName())) {
      if (result) {
        mismatchDescription.appendText(TYPE_NAME + " name ");
      } else {
        mismatchDescription.appendText(" and name ");
      }
      nameMatcher.describeMismatch(item.getName(), mismatchDescription);
      result = false;
    }
    if (!scopeMatcher.matches(item.getScope())) {
      if (result) {
        mismatchDescription.appendText(TYPE_NAME + " scope ");
      } else {
        mismatchDescription.appendText(" and scope ");
      }
      nameMatcher.describeMismatch(item.getScope(), mismatchDescription);
      result = false;
    }
    if (valueMatcher != null && !valueMatcher.matches(item.getValue())) {
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
    description.appendText(TYPE_NAME + " with id ").appendDescriptionOf(idMatcher)
            .appendText(" and name ").appendDescriptionOf(nameMatcher)
            .appendText(" and scope ").appendDescriptionOf(scopeMatcher);
    if (valueMatcher != null) {
      description.appendText(" and value ").appendDescriptionOf(valueMatcher);
    }
  }

  public static Matcher<XmlSignatureScope> scopeWithNameAndScope(
          Matcher<String> nameMatcher,
          Matcher<SignatureScopeType> scopeMatcher
  ) {
      return new IsSimpleReportXmlSignatureScope(
              Matchers.not(Matchers.blankOrNullString()),
              nameMatcher,
              scopeMatcher,
              null
      );
  }

  public static Matcher<XmlSignatureScope> scopeWithNameAndScope(String name, SignatureScopeType scope) {
    return scopeWithNameAndScope(
            Optional.ofNullable(name).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class)),
            Optional.ofNullable(scope).map(Matchers::sameInstance).orElseGet(() -> Matchers.nullValue(SignatureScopeType.class))
    );
  }

  public static Matcher<XmlSignatureScope> fullDocumentScopeWithName(Matcher<String> nameMatcher) {
    return new IsSimpleReportXmlSignatureScope(
            Matchers.not(Matchers.blankOrNullString()),
            nameMatcher,
            Matchers.sameInstance(SignatureScopeType.FULL),
            Matchers.equalTo("Full document")
    );
  }

  public static Matcher<XmlSignatureScope> fullDocumentScopeWithName(String name) {
    return fullDocumentScopeWithName(
            Optional.ofNullable(name).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class))
    );
  }

  public static Matcher<XmlSignatureScope> manifestDocumentScopeWithName(Matcher<String> nameMatcher) {
    return new IsSimpleReportXmlSignatureScope(
            Matchers.not(Matchers.blankOrNullString()),
            nameMatcher,
            Matchers.sameInstance(SignatureScopeType.FULL),
            Matchers.equalTo("Manifest document")
    );
  }

  public static Matcher<XmlSignatureScope> manifestDocumentScopeWithName(String name) {
    return manifestDocumentScopeWithName(
            Optional.ofNullable(name).map(Matchers::equalTo).orElseGet(() -> Matchers.nullValue(String.class))
    );
  }

}
