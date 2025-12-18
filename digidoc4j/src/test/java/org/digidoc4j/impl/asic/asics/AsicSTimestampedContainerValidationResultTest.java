/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.asics;

import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.test.MockValidationResult;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.mockito.Spy;
import org.mockito.junit.MockitoJUnitRunner;


import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@RunWith(MockitoJUnitRunner.class)
public class AsicSTimestampedContainerValidationResultTest {

  private static final String TEST_TOKEN_ID1 = "token-id-1";
  private static final String TEST_TOKEN_ID2 = "token-id-2";
  private static final String TEST_TOKEN_ID3 = "token-id-3";

  @Spy
  private AsicSTimestampedContainerValidationResult validationResult;

  @Test
  public void isValid_WhenResultContainsNoErrors_ReturnsTrueAndNoInteractionsWithTimestamps() {
    validationResult.setErrors(Collections.emptyList());

    boolean result = validationResult.isValid();

    assertThat(result, equalTo(true));
    verify(validationResult, never()).getTimestampIdList();
    verify(validationResult, never()).getValidationResult(anyString());
  }

  @Test
  public void isValid_WhenResultContainsErrorsButNoTimestamps_ReturnsFalse() {
    DigiDoc4JException digiDoc4JException = new DigiDoc4JException("Some error message");
    validationResult.setErrors(Collections.singletonList(digiDoc4JException));
    doReturn(Collections.emptyList()).when(validationResult).getTimestampIdList();

    boolean result = validationResult.isValid();

    assertThat(result, equalTo(false));
    verify(validationResult, atLeastOnce()).getTimestampIdList();
    verify(validationResult, never()).getValidationResult(anyString());
  }

  @Test
  public void isValid_WhenResultContainsErrorsAndOneValidTimestampWithoutErrors_ReturnsFalse() {
    DigiDoc4JException digiDoc4JException = new DigiDoc4JException("Some error message");
    validationResult.setErrors(Collections.singletonList(digiDoc4JException));
    doReturn(Collections.singletonList(TEST_TOKEN_ID1)).when(validationResult).getTimestampIdList();
    ValidationResult timestampValidationResult = createValidationResultWith(true);
    doReturn(timestampValidationResult).when(validationResult).getValidationResult(TEST_TOKEN_ID1);

    boolean result = validationResult.isValid();

    assertThat(result, equalTo(false));
    verify(validationResult, atLeastOnce()).getTimestampIdList();
    verify(validationResult, atLeastOnce()).getValidationResult(TEST_TOKEN_ID1);
  }

  @Test
  public void isValid_WhenResultContainsErrorsAndOneValidTimestampWithErrors_ReturnsFalse() {
    DigiDoc4JException digiDoc4JException = new DigiDoc4JException("Some error message");
    validationResult.setErrors(Collections.singletonList(digiDoc4JException));
    doReturn(Collections.singletonList(TEST_TOKEN_ID1)).when(validationResult).getTimestampIdList();
    ValidationResult timestampValidationResult = createValidationResultWith(true, digiDoc4JException);
    doReturn(timestampValidationResult).when(validationResult).getValidationResult(TEST_TOKEN_ID1);

    boolean result = validationResult.isValid();

    assertThat(result, equalTo(false));
    verify(validationResult, atLeastOnce()).getTimestampIdList();
    verify(validationResult, atLeastOnce()).getValidationResult(TEST_TOKEN_ID1);
  }

  @Test
  public void isValid_WhenResultContainsErrorsAndOneInvalidTimestampWithErrors_ReturnsFalse() {
    DigiDoc4JException digiDoc4JException = new DigiDoc4JException("Some error message");
    validationResult.setErrors(Collections.singletonList(digiDoc4JException));
    doReturn(Collections.singletonList(TEST_TOKEN_ID1)).when(validationResult).getTimestampIdList();
    ValidationResult timestampValidationResult = createValidationResultWith(false, digiDoc4JException);
    doReturn(timestampValidationResult).when(validationResult).getValidationResult(TEST_TOKEN_ID1);

    boolean result = validationResult.isValid();

    assertThat(result, equalTo(false));
    verify(validationResult, atLeastOnce()).getTimestampIdList();
    verify(validationResult, atLeastOnce()).getValidationResult(TEST_TOKEN_ID1);
  }

  @Test
  public void isValid_WhenResultContainsErrorsAndOneValidTimestampAndOneInvalidTimestampWithMatchingErrors_ReturnsTrue() {
    DigiDoc4JException digiDoc4JException = new DigiDoc4JException("Some error message");
    validationResult.setErrors(Collections.singletonList(digiDoc4JException));
    doReturn(Arrays.asList(TEST_TOKEN_ID1, TEST_TOKEN_ID2)).when(validationResult).getTimestampIdList();
    ValidationResult timestamp1ValidationResult = createValidationResultWith(true);
    doReturn(timestamp1ValidationResult).when(validationResult).getValidationResult(TEST_TOKEN_ID1);
    ValidationResult timestamp2ValidationResult = createValidationResultWith(false, digiDoc4JException);
    doReturn(timestamp2ValidationResult).when(validationResult).getValidationResult(TEST_TOKEN_ID2);

    boolean result = validationResult.isValid();

    assertThat(result, equalTo(true));
    verify(validationResult, atLeastOnce()).getTimestampIdList();
    verify(validationResult, atLeastOnce()).getValidationResult(anyString());
  }

  @Test
  public void isValid_WhenResultContainsErrorsAndMultipleValidTimestampsAndOneInvalidTimestampWithMatchingErrors_ReturnsTrue() {
    DigiDoc4JException digiDoc4JException = new DigiDoc4JException("Some error message");
    validationResult.setErrors(Collections.singletonList(digiDoc4JException));
    doReturn(Arrays.asList(TEST_TOKEN_ID1, TEST_TOKEN_ID2, TEST_TOKEN_ID3)).when(validationResult).getTimestampIdList();
    ValidationResult timestamp1ValidationResult = createValidationResultWith(true);
    doReturn(timestamp1ValidationResult).when(validationResult).getValidationResult(TEST_TOKEN_ID1);
    ValidationResult timestamp2ValidationResult = createValidationResultWith(false, digiDoc4JException);
    doReturn(timestamp2ValidationResult).when(validationResult).getValidationResult(TEST_TOKEN_ID2);
    ValidationResult timestamp3ValidationResult = createValidationResultWith(true);
    lenient().doReturn(timestamp3ValidationResult).when(validationResult).getValidationResult(TEST_TOKEN_ID3);

    boolean result = validationResult.isValid();

    assertThat(result, equalTo(true));
    verify(validationResult, atLeastOnce()).getTimestampIdList();
    verify(validationResult, atLeastOnce()).getValidationResult(anyString());
  }

  @Test
  public void isValid_WhenResultContainsErrorsAndOneValidTimestampAndMultipleInvalidTimestampsWithMatchingErrors_ReturnsTrue() {
    DigiDoc4JException digiDoc4JException1 = new DigiDoc4JException("Some error message 1");
    DigiDoc4JException digiDoc4JException2 = new DigiDoc4JException("Some error message 2");
    validationResult.setErrors(Arrays.asList(digiDoc4JException1, digiDoc4JException2));
    doReturn(Arrays.asList(TEST_TOKEN_ID1, TEST_TOKEN_ID2, TEST_TOKEN_ID3)).when(validationResult).getTimestampIdList();
    ValidationResult timestamp1ValidationResult = createValidationResultWith(false, digiDoc4JException1);
    doReturn(timestamp1ValidationResult).when(validationResult).getValidationResult(TEST_TOKEN_ID1);
    ValidationResult timestamp2ValidationResult = createValidationResultWith(true);
    doReturn(timestamp2ValidationResult).when(validationResult).getValidationResult(TEST_TOKEN_ID2);
    ValidationResult timestamp3ValidationResult = createValidationResultWith(false, digiDoc4JException2);
    doReturn(timestamp3ValidationResult).when(validationResult).getValidationResult(TEST_TOKEN_ID3);

    boolean result = validationResult.isValid();

    assertThat(result, equalTo(true));
    verify(validationResult, atLeastOnce()).getTimestampIdList();
    verify(validationResult, atLeastOnce()).getValidationResult(anyString());
  }

  @Test
  public void isValid_WhenResultContainsErrorsAndOneValidTimestampAndOneInvalidTimestampWithoutAllErrorsMatching_ReturnsFalse() {
    DigiDoc4JException digiDoc4JException1 = new DigiDoc4JException("Some error message 1");
    DigiDoc4JException digiDoc4JException2 = new DigiDoc4JException("Some error message 2");
    validationResult.setErrors(Arrays.asList(digiDoc4JException1, digiDoc4JException2));
    doReturn(Arrays.asList(TEST_TOKEN_ID1, TEST_TOKEN_ID2)).when(validationResult).getTimestampIdList();
    ValidationResult timestamp1ValidationResult = createValidationResultWith(true);
    doReturn(timestamp1ValidationResult).when(validationResult).getValidationResult(TEST_TOKEN_ID1);
    ValidationResult timestamp2ValidationResult = createValidationResultWith(false, digiDoc4JException1);
    doReturn(timestamp2ValidationResult).when(validationResult).getValidationResult(TEST_TOKEN_ID2);

    boolean result = validationResult.isValid();

    assertThat(result, equalTo(false));
    verify(validationResult, atLeastOnce()).getTimestampIdList();
    verify(validationResult, atLeastOnce()).getValidationResult(anyString());
  }

  private static ValidationResult createValidationResultWith(boolean validity, DigiDoc4JException... errors) {
    return createValidationResultWith(validity, Arrays.asList(errors));
  }

  private static ValidationResult createValidationResultWith(boolean validity, List<DigiDoc4JException> errors) {
    MockValidationResult mockValidationResult = new MockValidationResult();
    mockValidationResult.setValid(validity);
    mockValidationResult.setErrors(errors);
    return mockValidationResult;
  }

}
