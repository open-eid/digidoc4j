/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Container;
import org.digidoc4j.DataFile;
import org.digidoc4j.exceptions.InvalidDataFileException;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import static org.junit.Assert.assertThrows;

public abstract class EmptyDataFilesContainerTest extends AbstractTest {

    protected static final String TEST_FILE_NAME = "test.txt";
    protected static final String TEST_FILE_MIMETYPE = "text/plain";
    protected static final String EMPTY_FILE_PATH = "src/test/resources/testFiles/helper-files/empty.txt";

    protected static final String DATAFILES_CANNOT_BE_EMPTY_MESSAGE = "Datafiles cannot be empty";

    protected abstract Container.DocumentType getDocumentType();

    @Test
    public void testAddEmptyDataFileFromPath() {
        Container container = createEmptyContainerBy(getDocumentType());

        InvalidDataFileException caughtException = assertThrows(
                InvalidDataFileException.class,
                () -> container.addDataFile(EMPTY_FILE_PATH, TEST_FILE_MIMETYPE)
        );

        Assert.assertEquals(DATAFILES_CANNOT_BE_EMPTY_MESSAGE, caughtException.getMessage());
        Assert.assertEquals(0, container.getDataFiles().size());
    }

    @Test
    public void testAddEmptyDataFileFromStream() {
        Container container = createEmptyContainerBy(getDocumentType());

        InvalidDataFileException caughtException = assertThrows(
                InvalidDataFileException.class,
                () -> {
                    try (InputStream inputStream = new ByteArrayInputStream(new byte[0])) {
                        container.addDataFile(inputStream, TEST_FILE_NAME, TEST_FILE_MIMETYPE);
                    } catch (IOException e) {
                        throw new IllegalStateException(e);
                    }
                }
        );

        Assert.assertEquals(DATAFILES_CANNOT_BE_EMPTY_MESSAGE, caughtException.getMessage());
        Assert.assertEquals(0, container.getDataFiles().size());
    }

    @Test
    public void testAddEmptyDataFileFromFile() {
        Container container = createEmptyContainerBy(getDocumentType());
        File emptyFile = new File(EMPTY_FILE_PATH);

        InvalidDataFileException caughtException = assertThrows(
                InvalidDataFileException.class,
                () -> container.addDataFile(emptyFile, TEST_FILE_MIMETYPE)
        );

        Assert.assertEquals(DATAFILES_CANNOT_BE_EMPTY_MESSAGE, caughtException.getMessage());
        Assert.assertEquals(0, container.getDataFiles().size());
    }

    @Test
    public void testAddEmptyDataFile() {
        Container container = createEmptyContainerBy(getDocumentType());
        DataFile emptyDataFile = new DataFile(new byte[0], TEST_FILE_NAME, TEST_FILE_MIMETYPE);

        InvalidDataFileException caughtException = assertThrows(
                InvalidDataFileException.class,
                () -> container.addDataFile(emptyDataFile)
        );

        Assert.assertEquals(DATAFILES_CANNOT_BE_EMPTY_MESSAGE, caughtException.getMessage());
        Assert.assertEquals(0, container.getDataFiles().size());
    }

}
