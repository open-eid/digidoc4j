package org.digidoc4j.impl.bdoc;

import org.junit.Assert;
import org.junit.Test;

import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.signature.MimeType;

public class AsicContainerParserTest {

  @Test
  public void findingNextSignatureFileIndex_onEmptyContainer_shouldReturn_null() throws Exception {
    AsicContainerParser containerParser = createParser("testFiles/asics_without_signatures.bdoc");
    Assert.assertEquals(null, containerParser.findCurrentSignatureFileIndex());
  }

  @Test
  public void findingNextSignatureFileIndex_onContainerWithOneSignature_withoutIndex_shouldReturn_null() throws Exception {
    AsicContainerParser containerParser = createParser("testFiles/asics_for_testing.bdoc");
    Assert.assertEquals(null, containerParser.findCurrentSignatureFileIndex());
  }

  @Test
  public void findingNextSignatureFileIndex_onContainerWithOneSignature_withIndex0_shouldReturn_0() throws Exception {
    AsicContainerParser containerParser = createParser("testFiles/asics_with_one_signature.bdoc");
    Assert.assertEquals(Integer.valueOf(0), containerParser.findCurrentSignatureFileIndex());
  }

  @Test
  public void findingNextSignatureFileIndex_onContainerWithTwoSignature_shouldReturn_1() throws Exception {
    AsicContainerParser containerParser = createParser("testFiles/asics_testing_two_signatures.bdoc");
    Assert.assertEquals(Integer.valueOf(1), containerParser.findCurrentSignatureFileIndex());
  }

  private AsicContainerParser createParser(String path) {
    DSSDocument container = new FileDocument(path);
    container.setMimeType(MimeType.ASICE);
    return new AsicContainerParser(container);
  }
}
