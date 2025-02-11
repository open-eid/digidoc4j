/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.xades;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.exceptions.NonExtendableSignatureException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Collections;

import static org.digidoc4j.SignatureProfile.B_BES;
import static org.digidoc4j.SignatureProfile.B_EPES;
import static org.digidoc4j.SignatureProfile.LT;
import static org.digidoc4j.SignatureProfile.LTA;
import static org.digidoc4j.SignatureProfile.LT_TM;
import static org.digidoc4j.SignatureProfile.T;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class SignatureExtendingValidatorTest extends AbstractTest {

  private SignatureExtendingValidator validator;
  @Mock
  private XadesValidationDssFacade dssFacade;
  @Mock
  private SignedDocumentValidator signedDocumentValidator;

  @Before
  public void setUp() throws Exception {
    when(dssFacade.openXadesValidator(any(DSSDocument.class))).thenReturn(signedDocumentValidator);
    validator = new SignatureExtendingValidator(dssFacade);
  }

  @Test
  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  public void validateExtendability_ValidExtension_Succeeds() {
    runValidateProfileExtendability(B_BES, T);
    runValidateProfileExtendability(B_BES, LT);
    runValidateProfileExtendability(B_BES, LTA);
    runValidateProfileExtendability(LT, LTA);
    runValidateProfileExtendability(T, LT);
    runValidateProfileExtendability(T, LTA);
    runValidateProfileExtendability(LTA, LTA);
  }

  @Test
  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  public void validateExtendability_InvalidExtension_Throws() {
    assertProfileExtendabilityNotAllowed(B_BES, LT_TM);
    assertProfileExtendabilityNotAllowed(B_BES, B_EPES);
    assertProfileExtendabilityNotAllowed(LT, B_BES);
    assertProfileExtendabilityNotAllowed(LT, B_EPES);
    assertProfileExtendabilityNotAllowed(LT, T);
    assertProfileExtendabilityNotAllowed(LT, LT_TM);
    assertProfileExtendabilityNotAllowed(T, T);
    assertProfileExtendabilityNotAllowed(T, B_BES);
    assertProfileExtendabilityNotAllowed(T, B_EPES);
    assertProfileExtendabilityNotAllowed(T, LT_TM);
    assertProfileExtendabilityNotAllowed(LTA, B_BES);
    assertProfileExtendabilityNotAllowed(LTA, B_EPES);
    assertProfileExtendabilityNotAllowed(LTA, T);
    assertProfileExtendabilityNotAllowed(LTA, LT);
    assertProfileExtendabilityNotAllowed(LTA, LT_TM);
  }

  @Test
  public void validateExtendability_ProfileValidationFails_Throws() {
    NotSupportedException caughtException = assertThrows(
        NotSupportedException.class,
        () -> runValidateExtendability(LTA, LT)
    );

    assertEquals("Not supported: It is not possible to extend LTA signature to LT.", caughtException.getMessage());
  }

  @Test
  public void validateExtendability_DssValidationFailsWithAlertException_Throws() {
    when(signedDocumentValidator.getValidationData(anyList())).thenThrow(new AlertException("Error"));

    NonExtendableSignatureException caughtException = assertThrows(
        NonExtendableSignatureException.class,
        () -> runValidateExtendability(LT, LTA)
    );

    assertEquals("Validating the signature with DSS failed", caughtException.getMessage());
    assertEquals(AlertException.class, caughtException.getCause().getClass());
    assertEquals("Error", caughtException.getCause().getMessage());
  }

  @Test
  public void validateExtendability_SignatureDoesNotCoverDatafile_Throws() {
    Container container = ContainerOpener.open(ASICE_INVALID_SIGNATURE_DOES_NOT_COVER_DATAFILE, Configuration.of(Configuration.Mode.TEST));
    Signature signature = container.getSignatures().get(0);

    NonExtendableSignatureException caughtException = assertThrows(
        NonExtendableSignatureException.class,
        () -> validator.validateExtendability(signature, LTA)
    );

    assertEquals("Validating the signature with DSS failed", caughtException.getMessage());
    assertEquals(DSSException.class, caughtException.getCause().getClass());
    assertEquals("Cryptographic signature verification has failed / Signature verification failed against the best candidate.", caughtException.getCause().getMessage());
  }

  private void runValidateExtendability(SignatureProfile originalProfile, SignatureProfile targetProfile) {
    Container container = createNonEmptyContainer();
    Signature signature = createSignatureBy(container, originalProfile, pkcs12SignatureToken);
    validator.validateExtendability(signature, targetProfile);
  }

  private void runValidateProfileExtendability(SignatureProfile originalProfile, SignatureProfile targetProfile) {
    Container container = createNonEmptyContainer();
    Signature signature = createSignatureBy(container, originalProfile, pkcs12SignatureToken);
    SignatureExtendingValidator.validateProfileExtendability(Collections.singletonList(signature), targetProfile);
  }

    private void assertProfileExtendabilityNotAllowed(SignatureProfile originalProfile, SignatureProfile targetProfile) {
      NotSupportedException caughtException = assertThrows(
          NotSupportedException.class,
          () -> runValidateProfileExtendability(originalProfile, targetProfile)
      );
      String expectedMessage = "Not supported: It is not possible to extend " + originalProfile + " signature to " + targetProfile + ".";
      assertEquals(expectedMessage, caughtException.getMessage());
    }
}