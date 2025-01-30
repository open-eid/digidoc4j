/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.bdoc.asic;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Container.DocumentType;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.impl.asic.AsicContainer;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class AsicEContainerTest extends AbstractTest {

  @Test
  public void getExtensionValidationErrors_NoSignaturesInContainer_NoErrors() {
    AsicContainer container = (AsicContainer) createNonEmptyContainerBy(DocumentType.ASICE);

    Map<String, DigiDoc4JException> validationErrors = container.getExtensionValidationErrors(SignatureProfile.LT_TM);

    assertEquals(0, validationErrors.size());
  }

  @Test
  public void getExtensionValidationErrors_ExtendFromLtToLta_NoErrors() {
    String containerPath = createSignedContainerBy(DocumentType.ASICE, "asice");
    AsicContainer container = (AsicContainer) ContainerBuilder.aContainer().fromExistingFile(containerPath).build();

    Map<String, DigiDoc4JException> validationErrors = container.getExtensionValidationErrors(SignatureProfile.LTA);

    assertEquals(0, validationErrors.size());
  }

  @Test
  public void getExtensionValidationErrors_ExtendFromLtToLtaWithExpiredSignerCertificate_NotAllowed() {
    AsicContainer container = (AsicContainer) ContainerBuilder.aContainer(DocumentType.ASICE)
            .fromExistingFile("src/test/resources/testFiles/invalid-containers/two_signatures_one_invalid.bdoc").build();

    Map<String, DigiDoc4JException> validationErrors = container.getExtensionValidationErrors(SignatureProfile.LTA);

    assertEquals(2, validationErrors.size());
    DigiDoc4JException signature1Exception = validationErrors.get("S-DCF05D27954FB8CFED30883EDD83362FDD3F3F4AE90BF2068104A367EED786E7");
    assertEquals("Validating the signature with DSS failed", signature1Exception.getMessage());
    assertThat(signature1Exception.getCause().getMessage(), containsString("The signing certificate has expired and there is no POE during its validity range"));
    DigiDoc4JException signature2Exception = validationErrors.get("S-B9A1B36DD3CC9FE690F95042D80B6E6EE984D61097F36D5F37A95FF5936B3568");
    assertEquals("Validating the signature with DSS failed", signature2Exception.getMessage());
    assertThat(signature2Exception.getCause().getMessage(), containsString("The signing certificate has expired and there is no POE during its validity range"));
  }

  @Test
  public void getExtensionValidationErrors_ExtendFromLtToLt_NotAllowed() {
    String containerPath = createSignedContainerBy(DocumentType.ASICE, "asice");
    AsicContainer container = (AsicContainer) ContainerBuilder.aContainer().fromExistingFile(containerPath).build();
    String signatureUniqueId = container.getSignatures().get(0).getUniqueId();

    Map<String, DigiDoc4JException> validationErrors = container.getExtensionValidationErrors(SignatureProfile.LT);

    assertEquals(1, validationErrors.size());
    DigiDoc4JException exception = validationErrors.get(signatureUniqueId);
    assertEquals(NotSupportedException.class, exception.getClass());
    assertEquals("Not supported: It is not possible to extend LT signature to LT.", exception.getMessage());
  }

  @Test
  public void getExtensionValidationErrors_ExtendFromLtToLtTm_NotAllowed() {
    String containerPath = createSignedContainerBy(DocumentType.ASICE, "asice");
    AsicContainer container = (AsicContainer) ContainerBuilder.aContainer().fromExistingFile(containerPath).build();
    String signatureUniqueId = container.getSignatures().get(0).getUniqueId();
    Map<String, DigiDoc4JException> validationErrors = container.getExtensionValidationErrors(SignatureProfile.LT_TM);
    assertEquals(1, validationErrors.size());
    DigiDoc4JException exception = validationErrors.get(signatureUniqueId);
    assertEquals(NotSupportedException.class, exception.getClass());
    assertEquals("Not supported: It is not possible to extend LT signature to LT_TM.", exception.getMessage());
  }

  @Test
  public void getExtensionValidationErrors_InvalidProfileTransitionAndInvalidDssResult_OnlyInvalidProfileTransitionErrorIsPresent() {
    AsicContainer container = (AsicContainer) ContainerBuilder.aContainer(DocumentType.ASICE)
            .fromExistingFile(BDOC_WITH_TM_SIG).build();

    Map<String, DigiDoc4JException> validationErrors = container.getExtensionValidationErrors(SignatureProfile.LTA);

    assertEquals(1, validationErrors.size());
    DigiDoc4JException exception = validationErrors.get("S-A2C9571C4C2D5292B5D21A8CB2C0981AC5B895418CC95963E35492ED5B6419E5");
    assertEquals(NotSupportedException.class, exception.getClass());
    assertEquals("Not supported: It is not possible to extend LT_TM signature to LTA.", exception.getMessage());
  }

  @Test
  public void getExtensionValidationErrors_ValidationFromBepesToLta_NotAllowed() {
    AsicContainer container = (AsicContainer) ContainerBuilder.aContainer(DocumentType.ASICE)
            .fromExistingFile(BDOC_WITH_B_EPES_SIG).build();

    Map<String, DigiDoc4JException> validationErrors = container.getExtensionValidationErrors(SignatureProfile.LTA);

    assertEquals(1, validationErrors.size());
    DigiDoc4JException exception = validationErrors.get("S-9D235BC6FADAF0D57BD6B4DEC923F7DB6D4D7E9C2B67BBA0514DCD409769A6DB");
    assertEquals(NotSupportedException.class, exception.getClass());
    assertEquals("Not supported: It is not possible to extend B_EPES signature to LTA.", exception.getMessage());
  }

  @Test
  public void getExtensionValidationErrors_OnlyExtendableSignaturesAreSelectedOfMultipleSignatures_Success() {
    AsicContainer container = (AsicContainer) ContainerBuilder.aContainer(DocumentType.ASICE)
            .fromExistingFile(BDOC_WITH_TM_SIG).build();
    List<Signature> extendableSignatures = new ArrayList<>();
    extendableSignatures.add(createSignatureBy(container, SignatureProfile.LT, pkcs12EccSignatureToken));
    extendableSignatures.add(createSignatureBy(container, SignatureProfile.LTA, pkcs12EccSignatureToken));

    Map<String, DigiDoc4JException> validationErrors = container.getExtensionValidationErrors(
            SignatureProfile.LTA, extendableSignatures);

    assertEquals(0, validationErrors.size());
  }

  @Test
  public void getExtensionValidationErrors_SelectedSignatureNotInContainer_Throws() {
    AsicContainer container = (AsicContainer) createNonEmptyContainerBy(DocumentType.ASICE);
    Signature signature = createSignatureBy(DocumentType.ASICE, SignatureProfile.LT, pkcs12EccSignatureToken);

    DigiDoc4JException caughtException = assertThrows(
            DigiDoc4JException.class,
            () -> container.getExtensionValidationErrors(SignatureProfile.LTA, Collections.singletonList(signature))
    );

    assertThat(caughtException.getMessage(), containsString(
            "Signature not found in container: " + signature.getId()
    ));
  }

}
