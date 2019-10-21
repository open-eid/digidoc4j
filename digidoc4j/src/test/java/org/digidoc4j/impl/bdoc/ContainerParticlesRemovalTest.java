package org.digidoc4j.impl.bdoc;

import eu.europa.esig.dss.model.DSSDocument;
import org.apache.commons.io.FileUtils;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.DataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.impl.asic.AsicEntry;
import org.digidoc4j.impl.asic.AsicParseResult;
import org.digidoc4j.impl.asic.asice.AsicEContainer;
import org.digidoc4j.impl.asic.asice.AsicESignature;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainer;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainerBuilder;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignature;
import org.digidoc4j.impl.asic.xades.XadesSignatureWrapper;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import static org.digidoc4j.Container.DocumentType.ASICE;
import static org.digidoc4j.Container.DocumentType.BDOC;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class ContainerParticlesRemovalTest extends AbstractTest {

  @Test
  public void signatureRemovalFromBDocContainerThroughoutContainerSavingAndOpening_shouldResultWithCompletelyRemovedSignature() {
    BDocContainer container = this.createEmptyContainerBy(BDOC);
    container.addDataFile(mockDataFile());

    Signature signature = this.createSignatureBy(container, SignatureProfile.LT_TM, pkcs12SignatureToken);
    assertSame(1, container.getSignatures().size());
    assertTrue(container.getSignatures().contains(signature));
    assertNull(container.getContainerParseResult());
    assertTrue(container.validate().isValid());

    InputStream containerStream = container.saveAsStream();

    container = (BDocContainer) ContainerBuilder.aContainer(BDOC).fromStream(containerStream).build();
    assertEquals(1, container.getSignatures().size());
    BDocSignature containerSignature = (BDocSignature) container.getSignatures().get(0);
    assertEquals(containerSignature.getId(), signature.getId());
    containerParseResultContainsSignature(container.getContainerParseResult(), containerSignature.getSignatureDocument().getName());
    assertTrue(container.validate().isValid());

    container.removeSignature(containerSignature);
    assertTrue(container.getSignatures().isEmpty());
    containerParseResultDoesNotContainSignature(container.getContainerParseResult(), containerSignature.getSignatureDocument().getName());
    assertTrue(container.validate().isValid());

    containerStream = container.saveAsStream();

    container = (BDocContainer) ContainerBuilder.aContainer(BDOC).fromStream(containerStream).build();
    assertTrue(container.getSignatures().isEmpty());
    containerParseResultDoesNotContainSignature(container.getContainerParseResult(), containerSignature.getSignatureDocument().getName());
    assertTrue(container.validate().isValid());
  }

  @Test
  public void signatureRemovalFromASiCEContainerThroughoutContainerSavingAndOpening_shouldResultWithCompletelyRemovedSignature() {
    AsicEContainer container = this.createEmptyContainerBy(ASICE);
    container.addDataFile(mockDataFile());

    Signature signature = this.createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken);
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
    assertTrue(container.validate().isValid());

    container.removeSignature(containerSignature);
    assertTrue(container.getSignatures().isEmpty());
    containerParseResultDoesNotContainSignature(container.getContainerParseResult(), containerSignature.getSignatureDocument().getName());
    assertTrue(container.validate().isValid());

    containerStream = container.saveAsStream();

    container = (AsicEContainer) ContainerBuilder.aContainer(ASICE).fromStream(containerStream).build();
    assertTrue(container.getSignatures().isEmpty());
    containerParseResultDoesNotContainSignature(container.getContainerParseResult(), containerSignature.getSignatureDocument().getName());
    assertTrue(container.validate().isValid());
  }

  @Test
  public void addAndRemoveSignatureToNewContainerBeforeSaving_resultsWithCompletelyRemovedSignature() {
    BDocContainer container = this.createEmptyContainerBy(BDOC);
    container.addDataFile(mockDataFile());

    BDocSignature signature = this.createSignatureBy(container, SignatureProfile.LT_TM, pkcs12SignatureToken);
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
  public void dataFileRemovalFromBDocContainerThroughoutContainerSavingAndOpening_shouldResultWithCompletelyRemovedData() {
    DataFile dataFile = mockDataFile();

    BDocContainer container = this.createEmptyContainerBy(BDOC);
    container.addDataFile(dataFile);
    assertTrue(container.getDataFiles().contains(dataFile));
    assertNull(container.getContainerParseResult());

    InputStream containerStream = container.saveAsStream();

    container = (BDocContainer) ContainerBuilder.aContainer(BDOC).fromStream(containerStream).build();
    assertEquals(1, container.getDataFiles().size());
    assertEquals(dataFile.getName(), container.getDataFiles().get(0).getName());
    containerParseResultContainsDataFile(container.getContainerParseResult(), dataFile.getName());
    assertTrue(container.validate().isValid());

    container.removeDataFile(dataFile.getName());
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

    AsicEContainer container = this.createEmptyContainerBy(ASICE);
    container.addDataFile(dataFile);
    assertTrue(container.getDataFiles().contains(dataFile));
    assertNull(container.getContainerParseResult());

    InputStream containerStream = container.saveAsStream();

    container = (AsicEContainer) ContainerBuilder.aContainer(ASICE).fromStream(containerStream).build();
    assertEquals(1, container.getDataFiles().size());
    assertEquals(dataFile.getName(), container.getDataFiles().get(0).getName());
    containerParseResultContainsDataFile(container.getContainerParseResult(), dataFile.getName());
    assertTrue(container.validate().isValid());

    container.removeDataFile(dataFile.getName());
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
