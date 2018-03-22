/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.manifest;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignature;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignatureOpener;
import org.digidoc4j.impl.asic.manifest.AsicManifest;
import org.digidoc4j.impl.asic.manifest.ManifestEntry;
import org.digidoc4j.impl.asic.manifest.ManifestErrorMessage;
import org.digidoc4j.impl.asic.manifest.ManifestParser;
import org.digidoc4j.impl.asic.manifest.ManifestValidator;
import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;

public class ManifestValidatorTest {

  @Test
  public void validateEntries() throws Exception {
    Map<String, ManifestEntry> entriesFromManifest = new HashMap<String, ManifestEntry>() {{
      put("1", new ManifestEntry("1", "a"));
      put("2", new ManifestEntry("2", "b"));
    }};
    Set<ManifestEntry> entriesFromSignature = new HashSet<ManifestEntry>() {{
      add(new ManifestEntry("1", "a"));
      add(new ManifestEntry("2", "b"));
    }};
    Assert.assertEquals(0, ManifestValidator.validateEntries(entriesFromManifest, entriesFromSignature, "").size());
  }

  @Test
  public void validateEntriesUnOrdered() throws Exception {
    Map<String, ManifestEntry> entriesFromManifest = new HashMap<String, ManifestEntry>() {{
      put("1", new ManifestEntry("1", "a"));
      put("2", new ManifestEntry("2", "b"));
    }};

    Set<ManifestEntry> entriesFromSignature = new HashSet<ManifestEntry>() {{
      add(new ManifestEntry("2", "b"));
      add(new ManifestEntry("1", "a"));
    }};
    Assert.assertEquals(0, ManifestValidator.validateEntries(entriesFromManifest, entriesFromSignature, "").size());
  }

  @Test
  public void validateEntriesNotEqual() throws Exception {
    Map<String, ManifestEntry> entriesFromManifest = new HashMap<String, ManifestEntry>() {{
      put("1", new ManifestEntry("1", "a"));
      put("2", new ManifestEntry("2", "b"));
      put("2", new ManifestEntry("2", "f"));
    }};
    Set<ManifestEntry> entriesFromSignature = new HashSet<ManifestEntry>() {{
      add(new ManifestEntry("1", "a"));
      add(new ManifestEntry("2", "b"));
    }};
    List<ManifestErrorMessage> manifestErrorMessageList = ManifestValidator.validateEntries(entriesFromManifest, entriesFromSignature, "S0");
    Assert.assertEquals(1, manifestErrorMessageList.size());
    ManifestErrorMessage manifestErrorMessage = manifestErrorMessageList.get(0);
    Assert.assertEquals("Manifest file has an entry for file <2> with mimetype <f> but the signature file for "
        + "signature S0 indicates the mimetype is <b>", manifestErrorMessage.getErrorMessage());
    Assert.assertEquals("S0", manifestErrorMessage.getSignatureId());
  }

  @Test
  public void validateEntriesNotEqualValueSwapped() throws Exception {
    Map<String, ManifestEntry> entriesFromManifest = new HashMap<String, ManifestEntry>() {{
      put("1", new ManifestEntry("1", "a"));
      put("2", new ManifestEntry("2", "b"));
    }};
    Set<ManifestEntry> entriesFromSignature = new HashSet<ManifestEntry>() {{
      add(new ManifestEntry("1", "b"));
      add(new ManifestEntry("2", "a"));
    }};
    List<ManifestErrorMessage> manifestErrorMessageList = ManifestValidator
        .validateEntries(entriesFromManifest, entriesFromSignature, "S0");
    Assert.assertEquals(2, manifestErrorMessageList.size());
    ManifestErrorMessage file1ManifestErrorMessage = manifestErrorMessageList.get(0);
    Assert.assertEquals("Manifest file has an entry for file <1> with mimetype <a> but the signature file for "
        + "signature S0 indicates the mimetype is <b>", file1ManifestErrorMessage.getErrorMessage());
    Assert.assertEquals("S0", file1ManifestErrorMessage.getSignatureId());

    ManifestErrorMessage file2ManifestErrorMessage = manifestErrorMessageList.get(1);
    Assert.assertEquals("Manifest file has an entry for file <2> with mimetype <b> but the signature file for "
        + "signature S0 indicates the mimetype is <a>", file2ManifestErrorMessage.getErrorMessage());
    Assert.assertEquals("S0", file2ManifestErrorMessage.getSignatureId());
  }

  @Test
  public void validateEntriesMissingEntryInSignature() throws Exception {
    Map<String, ManifestEntry> entriesFromManifest = new HashMap<String, ManifestEntry>() {{
      put("1", new ManifestEntry("1", "a"));
      put("2", new ManifestEntry("2", "b"));
      put("3", new ManifestEntry("3", "c"));
    }};
    Set<ManifestEntry> entriesFromSignature = new HashSet<ManifestEntry>() {{
      add(new ManifestEntry("1", "a"));
      add(new ManifestEntry("3", "c"));
    }};
    List<ManifestErrorMessage> manifestErrorMessageList = ManifestValidator.validateEntries(entriesFromManifest, entriesFromSignature, "S0");
    Assert.assertEquals(1, manifestErrorMessageList.size());
    ManifestErrorMessage manifestErrorMessage = manifestErrorMessageList.get(0);
    Assert.assertEquals("Manifest file has an entry for file <2> with mimetype <b> but the signature file for "
        + "signature S0 does not have an entry for this file", manifestErrorMessage.getErrorMessage());
    Assert.assertEquals("S0", manifestErrorMessage.getSignatureId());
  }

  @Test
  public void validateEntriesMissingEntryInManifest() throws Exception {
    Map<String, ManifestEntry> entriesFromManifest = new HashMap<String, ManifestEntry>() {{
      put("1", new ManifestEntry("1", "a"));
      put("3", new ManifestEntry("3", "c"));
    }};
    Set<ManifestEntry> entriesFromSignature = new HashSet<ManifestEntry>() {{
      add(new ManifestEntry("1", "a"));
      add(new ManifestEntry("2", "b"));
      add(new ManifestEntry("3", "c"));
    }};
    List<ManifestErrorMessage> manifestErrorMessageList = ManifestValidator
        .validateEntries(entriesFromManifest, entriesFromSignature, "S1");
    Assert.assertEquals(1, manifestErrorMessageList.size());
    ManifestErrorMessage manifestErrorMessage = manifestErrorMessageList.get(0);
    Assert.assertEquals("The signature file for signature S1 has an entry for file <2> with mimetype <b> but the "
        + "manifest file does not have an entry for this file", manifestErrorMessage.getErrorMessage());
    Assert.assertEquals("S1", manifestErrorMessage.getSignatureId());
  }

  @Test
  public void validateHealthyContainer() throws Exception {
    ManifestParser manifestParser = this.createManifest(dataFile("test.txt", "text/plain"));
    List<DSSDocument> detachedContents = Arrays.asList(detachedContent("test.txt", "text/plain"));
    List<Signature> signatures = this.openSignature("src/test/resources/testFiles/xades/test-bdoc-ts.xml", detachedContents);
    List<ManifestErrorMessage> errors = new ManifestValidator(manifestParser, detachedContents, signatures).validateDocument();
    Assert.assertTrue(errors.isEmpty());
  }

  @Test
  public void container_withDifferentDataFileName_shouldBeInvalid() throws Exception {
    ManifestParser manifestParser = this.createManifest(dataFile("test.txt", "text/plain"));
    List<DSSDocument> detachedContents = Arrays.asList(detachedContent("other.txt", "text/plain"), detachedContent("test.txt", "text/plain"));
    List<Signature> signatures = this.openSignature("src/test/resources/testFiles/xades/test-bdoc-ts.xml", detachedContents);
    List<ManifestErrorMessage> errors = new ManifestValidator(manifestParser, detachedContents, signatures).validateDocument();
    Assert.assertFalse(errors.isEmpty());
    ManifestErrorMessage manifestErrorMessage = errors.get(0);
    Assert.assertEquals("Container contains a file named <other.txt> which is not found in the signature file",
        manifestErrorMessage.getErrorMessage());
    Assert.assertEquals("", manifestErrorMessage.getSignatureId());
  }


  @Test
  public void container_withSpecialDataFileCharacters_shouldBeValid() throws Exception {
    ManifestParser manifestParser = this.createManifest(dataFile("dds_JÜRIÖÖ € žŠ päev.txt", "application/octet-stream"));
    List<DSSDocument> detachedContents = Arrays.asList(detachedContent("dds_JÜRIÖÖ € žŠ päev.txt", "application/octet-stream"));
    List<Signature> signatures = this.openSignature("src/test/resources/testFiles/xades/test-bdoc-specia-chars-data-file.xml", detachedContents);
    List<ManifestErrorMessage> errors = new ManifestValidator(manifestParser, detachedContents, signatures).validateDocument();
    Assert.assertTrue(errors.isEmpty());
  }

  /*
   * RESTRICTED METHODS
   */

  private List<Signature> openSignature(String signaturePath, List<DSSDocument> detachedContents) {
    BDocSignatureOpener signatureOpener = new BDocSignatureOpener(detachedContents, new Configuration(Configuration.Mode.TEST));
    BDocSignature signature = signatureOpener.parse(new FileDocument(signaturePath)).get(0);
    signature.getOrigin().getDssSignature().checkSignatureIntegrity();
    List<Signature> signatureList = new ArrayList<>(1);
    signatureList.add(signature);
    return signatureList;
  }

  private DataFile dataFile(String fileName, String mimeType) {
    return new DataFile(new byte[]{1, 2, 3}, fileName, mimeType);
  }

  private ManifestParser createManifest(DataFile... dataFile) {
    AsicManifest asicManifest = new AsicManifest();
    asicManifest.addFileEntry(Arrays.asList(dataFile));
    DSSDocument manifestFile = new InMemoryDocument(asicManifest.getBytes());
    return new ManifestParser(manifestFile);
  }

  private DSSDocument detachedContent(String name, String mimeType) {
    return new InMemoryDocument(new byte[]{1, 2, 3}, name, MimeType.fromMimeTypeString(mimeType));
  }

}
