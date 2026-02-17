/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.utils;

import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResourceUtilsTest {

  @Test
  void isResourceAccessibleShouldReturnTrueIfResourceExistsOnClasspath() {
    assertTrue(ResourceUtils.isResourceAccessible("digidoc4j.yaml"));
  }

  @Test
  void isResourceAccessibleShouldReturnFalseIfResourceDoesNotExist() {
    assertFalse(ResourceUtils.isResourceAccessible("non_existing_resource"));
  }

  @Test
  void isFileReadableShouldReturnTrueIfPathRefersToExistingFile() {
    Path path = Paths.get("pom.xml");
    assertTrue(Files.isRegularFile(path) && Files.isReadable(path));
    assertTrue(ResourceUtils.isFileReadable(path.toString()));
  }

  @Test
  void isFileReadableShouldReturnFalseIfPathRefersToExistingDirectory() {
    Path path = Paths.get("target");
    assertTrue(Files.isDirectory(path));
    assertFalse(ResourceUtils.isFileReadable(path.toString()));
  }

  @Test
  void isFileReadableShouldReturnFalseIfNoSuchFileExists() {
    Path path = Paths.get("non_existing_file");
    assertFalse(ResourceUtils.isFileReadable(path.toString()));
  }

  @Test
  void getResourceWithClasspathPrefix() {
    InputStream inputStream = ResourceUtils.getResource("classpath:testFiles/keystores/truststore.jks");
    assertNotNull(inputStream);
  }

  @Test
  void getClasspathResourceWithoutPrefix() {
    InputStream inputStream = ResourceUtils.getResource("testFiles/keystores/truststore.jks");
    assertNotNull(inputStream);
  }

  @Test
  void getNonExistingResourceWithClasspathPrefixPath() {
    IllegalArgumentException caughtException = assertThrows(
            IllegalArgumentException.class,
            () -> ResourceUtils.getResource("classpath:test.xml")
    );
    assertEquals("Classpath resource not found: test.xml", caughtException.getMessage());
  }

  @Test
  void getResourceWithFilePrefix() {
    Path path = Paths.get("target/test-classes/testFiles/keystores/truststore.jks");
    InputStream inputStream = ResourceUtils.getResource("file:" + path.toAbsolutePath());
    assertNotNull(inputStream);
  }

  @Test
  void getFileResourceWithoutPrefix() {
    Path path = Paths.get("target/test-classes/testFiles/keystores/truststore.jks");
    InputStream inputStream = ResourceUtils.getResource(path.toAbsolutePath().toString());
    assertNotNull(inputStream);
  }

  @Test
  void getNonExistingResourceWithFilePrefix() {
    IllegalArgumentException caughtException = assertThrows(
            IllegalArgumentException.class,
            () -> ResourceUtils.getResource("file:test.xml")
    );
    assertEquals("File resource not found: test.xml", caughtException.getMessage());
  }

  @Test
  void getNonExistingResource() {
    IllegalArgumentException caughtException = assertThrows(
            IllegalArgumentException.class,
            () -> ResourceUtils.getResource("test.xml")
    );
    assertEquals("Resource not found: test.xml", caughtException.getMessage());
  }

}
