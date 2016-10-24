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

import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.impl.bdoc.BDocSignature;
import org.digidoc4j.impl.bdoc.BDocSignatureOpener;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

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

    assertEquals(0, ManifestValidator.validateEntries(entriesFromManifest, entriesFromSignature, "").size());
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
    List<String> errorMessages = ManifestValidator.validateEntries(entriesFromManifest, entriesFromSignature, "S0");

    assertEquals(1, errorMessages.size());
    assertEquals("Manifest file has an entry for file 2 with mimetype f but the signature file for signature S0 " +
        "indicates the mimetype is b", errorMessages.get(0));
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
    List<String> errorMessages = ManifestValidator.validateEntries(entriesFromManifest, entriesFromSignature, "S0");

    assertEquals(2, errorMessages.size());
    assertEquals("Manifest file has an entry for file 1 with mimetype a but the signature file for signature S0 " +
        "indicates the mimetype is b", errorMessages.get(0));
    assertEquals("Manifest file has an entry for file 2 with mimetype b but the signature file for signature S0 " +
        "indicates the mimetype is a", errorMessages.get(1));
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
    List<String> errorMessages = ManifestValidator.validateEntries(entriesFromManifest, entriesFromSignature, "S0");

    assertEquals(1, errorMessages.size());
    assertEquals("Manifest file has an entry for file 2 with mimetype b but the signature file for signature S0 does" +
        " not have an entry for this file", errorMessages.get(0));
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
    List<String> errorMessages = ManifestValidator.validateEntries(entriesFromManifest, entriesFromSignature, "S1");

    assertEquals(1, errorMessages.size());
    assertEquals("The signature file for signature S1 has an entry for file 2 with mimetype b but the manifest file" +
        " does not have an entry for this file", errorMessages.get(0));
  }

  @Test
  public void validateHealthyContainer() throws Exception {
    ManifestParser manifestParser = createManifest(dataFile("test.txt", "text/plain"));
    List<DSSDocument> detachedContents = Arrays.asList(detachedContent("test.txt", "text/plain"));
    List<Signature> signatures = openSignature("testFiles/xades/test-bdoc-ts.xml", detachedContents);
    List<String> errors = new ManifestValidator(manifestParser, detachedContents, signatures).validateDocument();
    assertTrue(errors.isEmpty());
  }

  @Test
  public void container_withDifferentDataFileName_shouldBeInvalid() throws Exception {
    ManifestParser manifestParser = createManifest(dataFile("test.txt", "text/plain"));
    List<DSSDocument> detachedContents = Arrays.asList(detachedContent("other.txt", "text/plain"), detachedContent("test.txt", "text/plain"));
    List<Signature> signatures = openSignature("testFiles/xades/test-bdoc-ts.xml", detachedContents);
    List<String> errors = new ManifestValidator(manifestParser, detachedContents, signatures).validateDocument();
    assertFalse(errors.isEmpty());
    assertEquals("Container contains a file named other.txt which is not found in the signature file", errors.get(0));
  }

  @Test
  @Ignore("https://www.pivotaltracker.com/story/show/125469911")
  public void container_withSpecialDataFileCharacters_shouldBeValid() throws Exception {
    ManifestParser manifestParser = createManifest(dataFile("dds_JÜRIÖÖ € žŠ päev.txt", "application/octet-stream"));
    List<DSSDocument> detachedContents = Arrays.asList(detachedContent("dds_JÜRIÖÖ € žŠ päev.txt", "application/octet-stream"));
    List<Signature> signatures = openSignature("testFiles/xades/test-bdoc-specia-chars-data-file.xml", detachedContents);
    List<String> errors = new ManifestValidator(manifestParser, detachedContents, signatures).validateDocument();
    assertTrue(errors.isEmpty());
  }

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
