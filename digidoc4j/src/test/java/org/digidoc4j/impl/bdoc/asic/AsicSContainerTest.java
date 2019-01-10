package org.digidoc4j.impl.bdoc.asic;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.asic.manifest.ManifestValidator;
import org.digidoc4j.test.util.TestDigiDoc4JUtil;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import eu.europa.esig.dss.MimeType;

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

}
