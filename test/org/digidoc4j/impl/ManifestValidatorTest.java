package org.digidoc4j.impl;

import org.junit.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;

public class ManifestValidatorTest {

  @Test
  public void validateEntries() throws Exception {
    Set<ManifestEntry> entriesFromManifest = new HashSet<ManifestEntry>() {{
      add(new ManifestEntry("1", "a"));
      add(new ManifestEntry("2", "b"));
    }};

    Set<ManifestEntry> entriesFromSignature = new HashSet<ManifestEntry>() {{
      add(new ManifestEntry("1", "a"));
      add(new ManifestEntry("2", "b"));
    }};

    assertEquals(0, ManifestValidator.validateEntries(entriesFromManifest, entriesFromSignature, "").size());
  }

  @Test
  public void validateEntriesUnOrdered() throws Exception {
    Set<ManifestEntry> entriesFromManifest = new HashSet<ManifestEntry>() {{
      add(new ManifestEntry("1", "a"));
      add(new ManifestEntry("2", "b"));
    }};

    Set<ManifestEntry> entriesFromSignature = new HashSet<ManifestEntry>() {{
      add(new ManifestEntry("2", "b"));
      add(new ManifestEntry("1", "a"));
    }};

    assertEquals(0, ManifestValidator.validateEntries(entriesFromManifest, entriesFromSignature, "").size());
  }

  @Test
  public void validateEntriesNotEqual() throws Exception {
    Set<ManifestEntry> entriesFromManifest = new HashSet<ManifestEntry>() {{
      add(new ManifestEntry("1", "a"));
      add(new ManifestEntry("2", "b"));
      add(new ManifestEntry("2", "f"));
    }};

    Set<ManifestEntry> entriesFromSignature = new HashSet<ManifestEntry>() {{
      add(new ManifestEntry("1", "a"));
      add(new ManifestEntry("2", "b"));
    }};
    List<String> errorMessages = ManifestValidator.validateEntries(entriesFromManifest, entriesFromSignature, "S0");

    assertEquals(1, errorMessages.size());
    assertEquals("Manifest file has an entry for file 2 with mimetype f but the signature file for signature S0 does" +
        " not.", errorMessages.get(0));
  }

  @Test
  public void validateEntriesNotEqualValueSwapped() throws Exception {
    Set<ManifestEntry> entriesFromManifest = new HashSet<ManifestEntry>() {{
      add(new ManifestEntry("1", "a"));
      add(new ManifestEntry("2", "b"));
    }};

    Set<ManifestEntry> entriesFromSignature = new HashSet<ManifestEntry>() {{
      add(new ManifestEntry("1", "b"));
      add(new ManifestEntry("2", "a"));
    }};
    List<String> errorMessages = ManifestValidator.validateEntries(entriesFromManifest, entriesFromSignature, "S0");

    assertEquals(4, errorMessages.size());
    assertEquals("Manifest file has an entry for file 1 with mimetype a but the signature file for signature S0 does" +
        " not.", errorMessages.get(0));
    assertEquals("Manifest file has an entry for file 2 with mimetype b but the signature file for signature S0 does" +
        " not.", errorMessages.get(1));
    assertEquals("The signature file for signature S0 has an entry for file 1 with mimetype b but the manifest file" +
        " does not.", errorMessages.get(2));
    assertEquals("The signature file for signature S0 has an entry for file 2 with mimetype a but the manifest file" +
        " does not.", errorMessages.get(3));
  }

  @Test
  public void validateEntriesMissingEntryInSignature() throws Exception {
    Set<ManifestEntry> entriesFromManifest = new HashSet<ManifestEntry>() {{
      add(new ManifestEntry("1", "a"));
      add(new ManifestEntry("2", "b"));
      add(new ManifestEntry("3", "c"));
    }};

    Set<ManifestEntry> entriesFromSignature = new HashSet<ManifestEntry>() {{
      add(new ManifestEntry("1", "a"));
      add(new ManifestEntry("3", "c"));
    }};
    List<String> errorMessages = ManifestValidator.validateEntries(entriesFromManifest, entriesFromSignature, "S0");

    assertEquals(1, errorMessages.size());
    assertEquals("Manifest file has an entry for file 2 with mimetype b but the signature file for signature S0 does" +
        " not.", errorMessages.get(0));
  }

  @Test
  public void validateEntriesMissingEntryInManifest() throws Exception {
    Set<ManifestEntry> entriesFromManifest = new HashSet<ManifestEntry>() {{
      add(new ManifestEntry("1", "a"));
      add(new ManifestEntry("3", "c"));
    }};

    Set<ManifestEntry> entriesFromSignature = new HashSet<ManifestEntry>() {{
      add(new ManifestEntry("1", "a"));
      add(new ManifestEntry("2", "b"));
      add(new ManifestEntry("3", "c"));
    }};
    List<String> errorMessages = ManifestValidator.validateEntries(entriesFromManifest, entriesFromSignature, "S1");

    assertEquals(1, errorMessages.size());
    assertEquals("The signature file for signature S1 has an entry for file 2 with mimetype b but the manifest file" +
        " does not.", errorMessages.get(0));
  }
}