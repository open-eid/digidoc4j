package org.digidoc4j.utils;

import java.io.File;

import org.junit.Test;

import static org.junit.Assert.assertFalse;

public class HelperTest {

  @Test
  public void testIsXMLFileWhenFileIsNotXMLFile() throws Exception {
    assertFalse(Helper.isXMLFile(new File("test.txt")));
  }
}