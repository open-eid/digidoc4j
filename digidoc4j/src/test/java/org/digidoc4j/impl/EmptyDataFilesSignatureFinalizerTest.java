package org.digidoc4j.impl;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.DataFile;
import org.digidoc4j.exceptions.InvalidDataFileException;
import org.digidoc4j.test.TestAssert;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

public abstract class EmptyDataFilesSignatureFinalizerTest extends AbstractTest {

    protected abstract SignatureFinalizer createSignatureFinalizerWithDataFiles(List<DataFile> dataFiles);

    @Test
    public void testCreateSignatureFinalizerWithSingleEmptyDataFile() {
        List<DataFile> dataFiles = Arrays.asList(
                new DataFile(new byte[0], "empty-file.txt", "text/plain")
        );

        InvalidDataFileException caughtException = assertThrows(
                InvalidDataFileException.class,
                () -> createSignatureFinalizerWithDataFiles(dataFiles)
        );

        Assert.assertEquals("Cannot sign empty datafile: empty-file.txt", caughtException.getMessage());
        TestAssert.assertSuppressed(caughtException, InvalidDataFileException.class);
    }

    @Test
    public void testCreateSignatureFinalizerWithMultipleEmptyDataFiles() {
        List<DataFile> dataFiles = Arrays.asList(
                new DataFile(new byte[1], "data-file-1.txt", "text/plain"),
                new DataFile(new byte[0], "empty-file-2.txt", "text/plain"),
                new DataFile(new byte[1], "data-file-3.txt", "text/plain"),
                new DataFile(new byte[1], "data-file-4.txt", "text/plain"),
                new DataFile(new byte[0], "empty-file-5.txt", "text/plain"),
                new DataFile(new byte[1], "data-file-6.txt", "text/plain"),
                new DataFile(new byte[0], "empty-file-7.txt", "text/plain"),
                new DataFile(new byte[0], "empty-file-8.txt", "text/plain")
        );

        InvalidDataFileException caughtException = assertThrows(
                InvalidDataFileException.class,
                () -> createSignatureFinalizerWithDataFiles(dataFiles)
        );

        Assert.assertEquals("Cannot sign empty datafile: empty-file-2.txt", caughtException.getMessage());
        TestAssert.assertSuppressed(caughtException, InvalidDataFileException.class,
                "Cannot sign empty datafile: empty-file-5.txt",
                "Cannot sign empty datafile: empty-file-7.txt",
                "Cannot sign empty datafile: empty-file-8.txt"
        );
    }

}