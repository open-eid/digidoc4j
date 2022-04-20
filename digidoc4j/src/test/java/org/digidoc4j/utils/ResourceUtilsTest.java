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

import org.junit.Assert;
import org.junit.Test;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class ResourceUtilsTest {

  @Test
  public void isResourceAccessibleShouldReturnTrueIfResourceExistsOnClasspath() {
    Assert.assertTrue(ResourceUtils.isResourceAccessible("digidoc4j.yaml"));
  }

  @Test
  public void isResourceAccessibleShouldReturnFalseIfResourceDoesNotExist() {
    Assert.assertFalse(ResourceUtils.isResourceAccessible("non_existing_resource"));
  }

  @Test
  public void isFileReadableShouldReturnTrueIfPathRefersToExistingFile() {
    Path path = Paths.get("pom.xml");
    Assert.assertTrue(Files.isRegularFile(path) && Files.isReadable(path));
    Assert.assertTrue(ResourceUtils.isFileReadable(path.toString()));
  }

  @Test
  public void isFileReadableShouldReturnFalseIfPathRefersToExistingDirectory() {
    Path path = Paths.get("target");
    Assert.assertTrue(Files.isDirectory(path));
    Assert.assertFalse(ResourceUtils.isFileReadable(path.toString()));
  }

  @Test
  public void isFileReadableShouldReturnFalseIfNoSuchFileExists() {
    Path path = Paths.get("non_existing_file");
    Assert.assertFalse(ResourceUtils.isFileReadable(path.toString()));
  }

  @Test
  public void getResourceWithClasspathPrefix() {
    InputStream inputStream = ResourceUtils.getResource("classpath:testFiles/keystores/truststore.jks");
    Assert.assertNotNull(inputStream);
  }

  @Test
  public void getClasspathResourceWithoutPrefix() {
    InputStream inputStream = ResourceUtils.getResource("testFiles/keystores/truststore.jks");
    Assert.assertNotNull(inputStream);
  }

  @Test
  public void getNonExistingResourceWithClasspathPrefixPath() {
    IllegalArgumentException caughtException = Assert.assertThrows(
            IllegalArgumentException.class,
            () -> ResourceUtils.getResource("classpath:test.xml")
    );
    Assert.assertEquals("Classpath resource not found: test.xml", caughtException.getMessage());
  }

  @Test
  public void getResourceWithFilePrefix() {
    Path path = Paths.get("target/test-classes/testFiles/keystores/truststore.jks");
    InputStream inputStream = ResourceUtils.getResource("file:" + path.toAbsolutePath());
    Assert.assertNotNull(inputStream);
  }

  @Test
  public void getFileResourceWithoutPrefix() {
    Path path = Paths.get("target/test-classes/testFiles/keystores/truststore.jks");
    InputStream inputStream = ResourceUtils.getResource(path.toAbsolutePath().toString());
    Assert.assertNotNull(inputStream);
  }

  @Test
  public void getNonExistingResourceWithFilePrefix() {
    IllegalArgumentException caughtException = Assert.assertThrows(
            IllegalArgumentException.class,
            () -> ResourceUtils.getResource("file:test.xml")
    );
    Assert.assertEquals("File resource not found: test.xml", caughtException.getMessage());
  }

  @Test
  public void getNonExistingResource() {
    IllegalArgumentException caughtException = Assert.assertThrows(
            IllegalArgumentException.class,
            () -> ResourceUtils.getResource("test.xml")
    );
    Assert.assertEquals("Resource not found: test.xml", caughtException.getMessage());
  }

}