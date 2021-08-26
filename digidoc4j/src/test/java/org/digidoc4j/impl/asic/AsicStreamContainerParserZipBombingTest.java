package org.digidoc4j.impl.asic;

import org.digidoc4j.Configuration;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.IOException;

public class AsicStreamContainerParserZipBombingTest extends AsicContainerParserZipBombingTest {

    @Override
    protected AsicContainerParser createAsicContainerParserFromPath(String path, Configuration configuration) {
        try {
            return new AsicStreamContainerParser(new FileInputStream(path), configuration);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to open stream for path: " + path, e);
        }
    }

    /**
     * NB: TEST OVERRIDDEN!!!
     * When reading containers from an input stream, then the total size of the container is not known in advance and
     * must be calculated on the fly while the stream is read. This makes the unpacked container contents size and the
     * total container size ratio calculation inaccurate and can balloon the ratio way over the expected value if
     * heavily compressed files are located at the beginning of the container.
     * When reading containers from an input stream, then depending on the container and its contents, higher
     * ZIP-bombing detection ratio and/or threshold might be needed to be configured.
     */
    @Test
    @Override
    public void testZipBombingNotDetectedWithSingleDataFileWhenUnpackRatioIsBelowAllowedRatio() {
        // The ratio balloons approximately up to 600 before the actual container size in known and the ratio stabilizes
        Configuration configuration = createTestConfigurationWithThresholdAndRatio(ONE_KILOBYTE_IN_BYTES, 600);
        AsicContainerParser asicContainerParser = createAsicContainerParserFromPath(SINGLE_DATAFILE_CONTAINER_PATH, configuration);
        assertReadSucceeds(1, asicContainerParser);
    }

    /**
     * NB: TEST OVERRIDDEN!!!
     * When reading containers from an input stream, then the total size of the container is not known in advance and
     * must be calculated on the fly while the stream is read. This makes the unpacked container contents size and the
     * total container size ratio calculation inaccurate and can balloon the ratio way over the expected value if
     * heavily compressed files are located at the beginning of the container.
     * When reading containers from an input stream, then depending on the container and its contents, higher
     * ZIP-bombing detection ratio and/or threshold might be needed to be configured.
     */
    @Test
    @Override
    public void testZipBombingNotDetectedWithMultipleDataFilesWhenUnpackRatioIsBelowAllowedRatio() {
        // The ratio balloons approximately up to 300 before the actual container size in known and the ratio stabilizes
        Configuration configuration = createTestConfigurationWithThresholdAndRatio(ONE_KILOBYTE_IN_BYTES, 300);
        AsicContainerParser asicContainerParser = createAsicContainerParserFromPath(MULTIPLE_DATAFILE_CONTAINER_PATH, configuration);
        assertReadSucceeds(8, asicContainerParser);
    }

}
