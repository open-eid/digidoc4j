package org.digidoc4j.impl;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ManifestEntryTest {

  @Test
  public void manifestEntryEquals() throws Exception {
    assertTrue(new ManifestEntry("fail.txt", "text/plain").equals(new ManifestEntry("fail.txt", "text/plain")));
  }

  @Test
  public void manifestEntryEqualsWhenMimeTypeIsWrong() throws Exception {
    assertFalse(new ManifestEntry("fail.txt", "text/plain").equals(new ManifestEntry("fail.txt", "text/xml")));
  }

  @Test
  public void manifestEntryEqualsWhenFileNameIsWrong() throws Exception {
    assertFalse(new ManifestEntry("fail.txt", "text/plain").equals(new ManifestEntry("fail1.txt", "text/plain")));
  }
}