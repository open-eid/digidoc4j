/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.bdoc;

import eu.europa.esig.dss.model.DSSDocument;
import org.apache.commons.io.FileUtils;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.DataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.exceptions.SignatureNotFoundException;
import org.digidoc4j.impl.asic.AsicContainer;
import org.digidoc4j.impl.asic.AsicEntry;
import org.digidoc4j.impl.asic.AsicParseResult;
import org.digidoc4j.impl.asic.AsicSignature;
import org.digidoc4j.impl.asic.asice.AsicEContainer;
import org.digidoc4j.impl.asic.asice.AsicESignature;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainer;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainerBuilder;
import org.digidoc4j.impl.asic.xades.XadesSignatureWrapper;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import static org.digidoc4j.Container.DocumentType.ASICE;
import static org.digidoc4j.Container.DocumentType.BDOC;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class ContainerParticlesRemovalTest extends AbstractTest {

  @Test
  public void signatureRemovalFromBDocContainerThroughoutContainerSavingAndOpening_shouldResultWithCompletelyRemovedSignature() {
    BDocContainer initialContainer = createEmptyContainerBy(BDOC);
    initialContainer.addDataFile(mockDataFile());

    Signature signature = createSignatureBy(initialContainer, SignatureProfile.LT, pkcs12SignatureToken);
    assertSame(1, initialContainer.getSignatures().size());
    assertTrue(initialContainer.getSignatures().contains(signature));
    assertNull(initialContainer.getContainerParseResult());
    assertTrue(initialContainer.validate().isValid());

    InputStream containerStream = initialContainer.saveAsStream();

    AsicContainer deserializedContainer = (AsicContainer) ContainerBuilder.aContainer(BDOC).fromStream(containerStream).build();
    assertEquals(1, deserializedContainer.getSignatures().size());
    AsicSignature containerSignature = (AsicSignature) deserializedContainer.getSignatures().get(0);
    assertEquals(containerSignature.getId(), signature.getId());
    containerParseResultContainsSignature(deserializedContainer.getContainerParseResult(), containerSignature.getSignatureDocument().getName());
    ContainerValidationResult validationResult = deserializedContainer.validate();
    assertTrue(validationResult.isValid());
    containerValidationResultContainsSignature(validationResult, containerSignature);

    deserializedContainer.removeSignature(containerSignature);
    assertTrue(deserializedContainer.getSignatures().isEmpty());
    containerParseResultDoesNotContainSignature(deserializedContainer.getContainerParseResult(), containerSignature.getSignatureDocument().getName());
    validationResult = deserializedContainer.validate();
    assertTrue(validationResult.isValid());
    containerValidationResultDoesNotContainSignature(validationResult, containerSignature);

    containerStream = deserializedContainer.saveAsStream();

    deserializedContainer = (AsicContainer) ContainerBuilder.aContainer(BDOC).fromStream(containerStream).build();
    assertTrue(deserializedContainer.getSignatures().isEmpty());
    containerParseResultDoesNotContainSignature(deserializedContainer.getContainerParseResult(), containerSignature.getSignatureDocument().getName());
    validationResult = deserializedContainer.validate();
    assertTrue(validationResult.isValid());
    containerValidationResultDoesNotContainSignature(validationResult, containerSignature);
  }

  @Test
  public void signatureRemovalFromASiCEContainerThroughoutContainerSavingAndOpening_shouldResultWithCompletelyRemovedSignature() {
    AsicEContainer container = createEmptyContainerBy(ASICE);
    container.addDataFile(mockDataFile());

    Signature signature = createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken);
    assertSame(1, container.getSignatures().size());
    assertTrue(container.getSignatures().contains(signature));
    assertNull(container.getContainerParseResult());
    assertTrue(container.validate().isValid());

    InputStream containerStream = container.saveAsStream();

    container = (AsicEContainer) ContainerBuilder.aContainer(ASICE).fromStream(containerStream).build();
    assertEquals(1, container.getSignatures().size());
    AsicESignature containerSignature = (AsicESignature) container.getSignatures().get(0);
    assertEquals(containerSignature.getId(), signature.getId());
    containerParseResultContainsSignature(container.getContainerParseResult(), containerSignature.getSignatureDocument().getName());
    ContainerValidationResult validationResult = container.validate();
    assertTrue(validationResult.isValid());
    containerValidationResultContainsSignature(validationResult, containerSignature);

    container.removeSignature(containerSignature);
    assertTrue(container.getSignatures().isEmpty());
    containerParseResultDoesNotContainSignature(container.getContainerParseResult(), containerSignature.getSignatureDocument().getName());
    validationResult = container.validate();
    assertTrue(validationResult.isValid());
    containerValidationResultDoesNotContainSignature(validationResult, containerSignature);

    containerStream = container.saveAsStream();

    container = (AsicEContainer) ContainerBuilder.aContainer(ASICE).fromStream(containerStream).build();
    assertTrue(container.getSignatures().isEmpty());
    containerParseResultDoesNotContainSignature(container.getContainerParseResult(), containerSignature.getSignatureDocument().getName());
    validationResult = container.validate();
    assertTrue(validationResult.isValid());
    containerValidationResultDoesNotContainSignature(validationResult, containerSignature);
  }

  @Test
  public void addAndRemoveSignatureToNewContainerBeforeSaving_resultsWithCompletelyRemovedSignature() {
    BDocContainer container = createEmptyContainerBy(BDOC);
    container.addDataFile(mockDataFile());

    AsicSignature signature = createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken);
    container.removeSignature(signature);
    assertTrue(container.getSignatures().isEmpty());
    assertNull(container.getContainerParseResult());

    InputStream containerStream = container.saveAsStream();
    container = (BDocContainer) ContainerBuilder.aContainer(BDOC).fromStream(containerStream).build();
    assertTrue(container.getSignatures().isEmpty());
    assertTrue(container.getContainerParseResult().getSignatures().isEmpty());
  }

  @Test
  public void addAndRemoveSignatureToAlreadySignedContainerBeforeSaving_resultsWithCompletelyRemovedSignature() {
    BDocContainer container = (BDocContainer) openContainer(BDOC_WITH_TM_SIG);
    assertSame(1, container.getSignatures().size());

    container.removeSignature(container.getSignatures().get(0));
    assertSame(0, container.getSignatures().size());
    assertSame(0, container.getContainerParseResult().getSignatures().size());

    InputStream containerStream = container.saveAsStream();
    container = (BDocContainer) ContainerBuilder.aContainer(BDOC).fromStream(containerStream).build();
    assertSame(0, container.getSignatures().size());
    assertSame(0, container.getContainerParseResult().getSignatures().size());
  }

  @Test
  public void tryingToRemoveNonExistingSignatureFromBDocContainer_shouldThrowAnException() {
    BDocContainer container = createEmptyContainerBy(BDOC);
    container.addDataFile(mockDataFile());

    Signature containerSignature = createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken);
    Signature unrelatedSignature = createSignatureBy(BDOC, SignatureProfile.LT, pkcs12SignatureToken);

    assertEquals(1, container.getSignatures().size());
    assertTrue(container.getSignatures().contains(containerSignature));

    SignatureNotFoundException caughtException = assertThrows(
            SignatureNotFoundException.class,
            () -> container.removeSignature(unrelatedSignature)
    );

    assertEquals("Signature not found: " + unrelatedSignature.getId(), caughtException.getMessage());
    assertEquals(1, container.getSignatures().size());
    assertTrue(container.getSignatures().contains(containerSignature));
  }

  @Test
  public void tryingToRemoveNonExistingSignatureFromASiCEContainer_shouldThrowAnException() {
    AsicEContainer container = createEmptyContainerBy(ASICE);
    container.addDataFile(mockDataFile());

    Signature containerSignature = createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken);
    Signature unrelatedSignature = createSignatureBy(ASICE, SignatureProfile.LT, pkcs12SignatureToken);

    assertEquals(1, container.getSignatures().size());
    assertTrue(container.getSignatures().contains(containerSignature));

    SignatureNotFoundException caughtException = assertThrows(
            SignatureNotFoundException.class,
            () -> container.removeSignature(unrelatedSignature)
    );

    assertEquals("Signature not found: " + unrelatedSignature.getId(), caughtException.getMessage());
    assertEquals(1, container.getSignatures().size());
    assertTrue(container.getSignatures().contains(containerSignature));
  }

  @Test
  public void tryingToRemoveNonExistingSignatureByIndexFromBDocContainer_shouldThrowAnException() {
    BDocContainer container = createEmptyContainerBy(BDOC);
    container.addDataFile(mockDataFile());

    Signature signature = createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken);
    Signature nonExistingSignature = SignatureBuilder.aSignature(container)
            .withSignatureProfile(SignatureProfile.LT)
            .withSignatureToken(pkcs12SignatureToken)
            .withSignatureId("id-non-existing")
            .invokeSigning();

    assertEquals(1, container.getSignatures().size());
    assertTrue(container.getSignatures().contains(signature));

    SignatureNotFoundException caughtException = assertThrows(
            SignatureNotFoundException.class,
            () -> container.removeSignature(nonExistingSignature)
    );

    assertEquals("Signature not found: id-non-existing", caughtException.getMessage());
    assertEquals(1, container.getSignatures().size());
    assertTrue(container.getSignatures().contains(signature));
  }

  @Test
  public void tryingToRemoveNonExistingSignatureByIndexFromASiCEContainer_shouldThrowAnException() {
    AsicEContainer container = createEmptyContainerBy(ASICE);
    container.addDataFile(mockDataFile());

    Signature signature = createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken);
    Signature nonExistingSignature = SignatureBuilder.aSignature(container)
            .withSignatureProfile(SignatureProfile.LT)
            .withSignatureToken(pkcs12SignatureToken)
            .withSignatureId("id-non-existing")
            .invokeSigning();

    assertEquals(1, container.getSignatures().size());
    assertTrue(container.getSignatures().contains(signature));

    SignatureNotFoundException caughtException = assertThrows(
            SignatureNotFoundException.class,
            () -> container.removeSignature(nonExistingSignature)
    );

    assertEquals("Signature not found: id-non-existing", caughtException.getMessage());
    assertEquals(1, container.getSignatures().size());
    assertTrue(container.getSignatures().contains(signature));
  }

  @Test
  public void dataFileRemovalFromBDocContainerThroughoutContainerSavingAndOpening_shouldResultWithCompletelyRemovedData() {
    DataFile dataFile = mockDataFile();

    BDocContainer container = createEmptyContainerBy(BDOC);
    container.addDataFile(dataFile);
    assertTrue(container.getDataFiles().contains(dataFile));
    assertNull(container.getContainerParseResult());

    InputStream containerStream = container.saveAsStream();

    container = (BDocContainer) ContainerBuilder.aContainer(BDOC).fromStream(containerStream).build();
    assertEquals(1, container.getDataFiles().size());
    assertEquals(dataFile.getName(), container.getDataFiles().get(0).getName());
    containerParseResultContainsDataFile(container.getContainerParseResult(), dataFile.getName());
    assertTrue(container.validate().isValid());

    container.removeDataFile(container.getDataFiles().get(0));
    assertTrue(container.getDataFiles().isEmpty());
    containerParseResultDoesNotContainDataFile(container.getContainerParseResult(), dataFile.getName());
    assertTrue(container.validate().isValid());

    containerStream = container.saveAsStream();

    container = (BDocContainer) ContainerBuilder.aContainer(BDOC).fromStream(containerStream).build();
    assertTrue(container.getDataFiles().isEmpty());
    containerParseResultDoesNotContainDataFile(container.getContainerParseResult(), dataFile.getName());
    assertTrue(container.validate().isValid());
  }

  @Test
  public void dataFileRemovalFromASiCEContainerThroughoutContainerSavingAndOpening_shouldResultWithCompletelyRemovedData() {
    DataFile dataFile = mockDataFile();

    AsicEContainer container = createEmptyContainerBy(ASICE);
    container.addDataFile(dataFile);
    assertTrue(container.getDataFiles().contains(dataFile));
    assertNull(container.getContainerParseResult());

    InputStream containerStream = container.saveAsStream();

    container = (AsicEContainer) ContainerBuilder.aContainer(ASICE).fromStream(containerStream).build();
    assertEquals(1, container.getDataFiles().size());
    assertEquals(dataFile.getName(), container.getDataFiles().get(0).getName());
    containerParseResultContainsDataFile(container.getContainerParseResult(), dataFile.getName());
    assertTrue(container.validate().isValid());

    container.removeDataFile(container.getDataFiles().get(0));
    assertTrue(container.getDataFiles().isEmpty());
    containerParseResultDoesNotContainDataFile(container.getContainerParseResult(), dataFile.getName());
    assertTrue(container.validate().isValid());

    containerStream = container.saveAsStream();

    container = (AsicEContainer) ContainerBuilder.aContainer(ASICE).fromStream(containerStream).build();
    assertTrue(container.getDataFiles().isEmpty());
    containerParseResultDoesNotContainDataFile(container.getContainerParseResult(), dataFile.getName());
    assertTrue(container.validate().isValid());
  }

  private DataFile mockDataFile() {
    return new DataFile(new ByteArrayInputStream(new byte[]{0, 1, 2, 3}), "test-file.txt", "text/plain");
  }

  private void containerParseResultContainsSignature(AsicParseResult containerParseResult, final String signatureName) {
    boolean signatureInAsicEntries = false;
    for (AsicEntry asicEntry : containerParseResult.getAsicEntries()) {
      signatureInAsicEntries = signatureName.equals(asicEntry.getContent().getName());
      if (signatureInAsicEntries) {
        break;
      }
    }
    assertTrue(signatureInAsicEntries);

    boolean signaturePresent = false;
    for (XadesSignatureWrapper signatureWrapper : containerParseResult.getSignatures()) {
      signaturePresent = signatureWrapper.getSignatureDocument().getName().equals(signatureName);
      if (signaturePresent) {
        break;
      }
    }
    assertTrue(signaturePresent);
  }


  private void containerParseResultDoesNotContainSignature(AsicParseResult containerParseResult, String signatureName) {
    for (AsicEntry asicEntry : containerParseResult.getAsicEntries()) {
      assertNotEquals(signatureName, asicEntry.getContent().getName());
    }

    for (XadesSignatureWrapper signatureWrapper : containerParseResult.getSignatures()) {
      assertNotEquals(signatureWrapper.getSignatureDocument().getName(), signatureName);
    }
  }

  private void containerParseResultContainsDataFile(AsicParseResult containerParseResult, final String dataFileName) {
    boolean dataFileInAsicEntries = false;
    for (AsicEntry asicEntry : containerParseResult.getAsicEntries()) {
      dataFileInAsicEntries = dataFileName.equals(asicEntry.getContent().getName());
      if (dataFileInAsicEntries) {
        break;
      }
    }
    assertTrue(dataFileInAsicEntries);

    boolean dataFileInDataFiles = false;
    for (DataFile dataFile : containerParseResult.getDataFiles()) {
      dataFileInDataFiles = dataFile.getName().equals(dataFileName);
      if (dataFileInDataFiles) {
        break;
      }
    }
    assertTrue(dataFileInDataFiles);

    boolean dataFileInDetachedContents = false;
    for (DSSDocument detachedContent : containerParseResult.getDetachedContents()) {
      dataFileInDetachedContents = detachedContent.getName().equals(dataFileName);
      if (dataFileInDetachedContents) {
        break;
      }
    }
    assertTrue(dataFileInDetachedContents);
  }

  private void containerParseResultDoesNotContainDataFile(AsicParseResult containerParseResult, String dataFileName) {
    for (AsicEntry asicEntry : containerParseResult.getAsicEntries()) {
      assertNotEquals(dataFileName, asicEntry.getContent().getName());
    }

    for (DataFile dataFile : containerParseResult.getDataFiles()) {
      assertNotEquals(dataFile.getName(), dataFileName);
    }

    for (DSSDocument detachedContent : containerParseResult.getDetachedContents()) {
      assertNotEquals(detachedContent.getName(), dataFileName);
    }
  }

  private static void containerValidationResultContainsSignature(final ContainerValidationResult validationResult, final Signature signature) {
    assertTrue(
            "Validation result should contain signature: " + signature.getId(),
            validationResultContainsSignatureById(validationResult, signature.getId())
    );
  }

  private static void containerValidationResultDoesNotContainSignature(final ContainerValidationResult validationResult, final Signature signature) {
    assertFalse(
            "Validation result should not contain signature: " + signature.getId(),
            validationResultContainsSignatureById(validationResult, signature.getId())
    );
  }

  private static boolean validationResultContainsSignatureById(final ContainerValidationResult validationResult, final String signatureId) {
    return validationResult.getReports().stream().anyMatch(r -> signatureId.equals(r.getId()));
  }

  private Container openContainer(String path) {
    try (InputStream stream = FileUtils.openInputStream(new File(path))) {
      return BDocContainerBuilder
              .aContainer(Container.DocumentType.BDOC)
              .fromStream(stream)
              .build();
    } catch (IOException e) {
      fail("Failed to read container from stream");
      throw new IllegalStateException(e);
    }
  }
}
