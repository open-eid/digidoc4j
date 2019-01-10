package org.digidoc4j.impl.bdoc.asic;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.digidoc4j.*;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.asic.manifest.ManifestValidator;
import org.digidoc4j.test.util.TestDigiDoc4JUtil;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import eu.europa.esig.dss.MimeType;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Created by Andrei on 15.11.2017.
 */

public class AsicSContainerTest extends AbstractTest {

  @Test(expected = DigiDoc4JException.class)
  public void testAddSignatureToAsicSContainer() throws IOException {
    this.createSignatureBy(this.createNonEmptyContainer(Container.DocumentType.ASICS, 1), this.pkcs12SignatureToken);
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAsicSContainerWithTwoDataFiles() throws IOException {
    this.createNonEmptyContainer(Container.DocumentType.ASICS, 2);
  }

  @Test(expected = DigiDoc4JException.class)
  public void testExistingAsicSContainerFromPath() throws IOException {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS)
        .fromExistingFile("src/test/resources/testFiles/valid-containers/testasics.asics").build();
    //cannot add second file to existing container
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testExistingAsicSContainerFromZIPPath() throws IOException {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS).
        fromExistingFile("src/test/resources/testFiles/valid-containers/testasics.zip").build();
    //cannot add second file to existing container
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testExistingAsicSContainerFromStream() throws IOException {
    try (InputStream stream = new FileInputStream(new File("src/test/resources/testFiles/valid-containers/testasics.asics"))) {
      Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS).fromStream(stream).build();
      //cannot add second file to existing container
      container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    }
  }

  @Test
  public void testExistingAsicSContainerWithSingleSingature() {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS)
            .fromExistingFile("src/test/resources/testFiles/valid-containers/asics-1-signature.asics").build();
    assertTrue(container.validate().isValid());
  }

  @Test
  public void testExistingAsicSContainerWithTwoSingaturesInDifferentFiles() {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS)
            .fromExistingFile("src/test/resources/testFiles/invalid-containers/asics-2-signatures-in-different-files.asics").build();
    ValidationResult result = container.validate();
    assertFalse(result.isValid());
    assertEquals("ASICS container can only contain single signature file", result.getErrors().get(0).getMessage());
  }

  @Test
  public void testExistingAsicSContainerWithTwoSingaturesInDifferentFiles2_withoutGivingContainerType() {
    Container container = ContainerBuilder.aContainer()
            .fromExistingFile("src/test/resources/testFiles/invalid-containers/asics-2-signatures-in-different-files.asics").build();
    ValidationResult result = container.validate();
    assertFalse(result.isValid());
    assertEquals("ASICS container can only contain single signature file", result.getErrors().get(0).getMessage());
  }

}
