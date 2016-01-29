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

import org.junit.Assert;
import org.junit.Test;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;

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
}
