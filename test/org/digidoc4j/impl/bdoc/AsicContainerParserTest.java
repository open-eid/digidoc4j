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

import org.digidoc4j.testutils.TestDataBuilder;
import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;

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
    DSSDocument container = TestDataBuilder.createAsicContainer(path);
    return new AsicContainerParser(container);
  }
}
