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

  @Test(expected = IllegalArgumentException.class)
  public void getResourceWithInvalidClasspathPrefixPath() {
    ResourceUtils.getResource("classpath:test.xml");
  }

  @Test
  public void getResourceWithFilePrefix() {
    Path path = Paths.get("target/test-classes/testFiles/keystores/truststore.jks");
    InputStream inputStream = ResourceUtils.getResource("file:" + path.toAbsolutePath().toString());
    Assert.assertNotNull(inputStream);
  }

  @Test(expected = IllegalArgumentException.class)
  public void getResourceWithInvalidFilePrefix() {
    ResourceUtils.getResource("file:test.xml");
  }

  @Test
  public void getResourceWithoutPrefix() {
    Path path = Paths.get("target/test-classes/testFiles/keystores/truststore.jks");
    InputStream inputStream = ResourceUtils.getResource(path.toAbsolutePath().toString());
    Assert.assertNotNull(inputStream);
  }

  @Test(expected = IllegalArgumentException.class)
  public void getResourceWithInvalidPath() {
    ResourceUtils.getResource("test.xml");
  }

}