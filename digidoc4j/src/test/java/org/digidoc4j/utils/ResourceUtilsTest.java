package org.digidoc4j.utils;

import org.junit.Assert;
import org.junit.Test;

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

}