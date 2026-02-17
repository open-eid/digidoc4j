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
import org.digidoc4j.Configuration;
import org.digidoc4j.exceptions.TechnicalException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

abstract class AsicContainerParserZipBombingTest extends AbstractTest {

    protected static final String MULTIPLE_DATAFILE_CONTAINER_PATH = "src/test/resources/testFiles/valid-containers/compression-ratio-46.55-with-8-datafiles.asice";
    protected static final String SINGLE_DATAFILE_CONTAINER_PATH = "src/test/resources/testFiles/valid-containers/compression-ratio-51.91-with-1-datafile.asice";

    protected static final long MULTIPLE_DATAFILE_CONTAINER_UNPACKED_SIZE_IN_BYTES = 546610L;
    protected static final long SINGLE_DATAFILE_CONTAINER_UNPACKED_SIZE_IN_BYTES = 543348L;

    protected static final long ONE_KILOBYTE_IN_BYTES = 1024L;

    protected abstract AsicContainerParser createAsicContainerParserFromPath(String path, Configuration configuration);

    @Test
    void testZipBombingDetectedWithSingleDataFileWhenUnpackRatioExceedsAllowedRatio() {
        Configuration configuration = createTestConfigurationWithThresholdAndRatio(ONE_KILOBYTE_IN_BYTES, 51);
        AsicContainerParser asicContainerParser = createAsicContainerParserFromPath(SINGLE_DATAFILE_CONTAINER_PATH, configuration);
        assertReadThrowsZipBombingException(asicContainerParser);
    }

    @Test
    void testZipBombingNotDetectedWithSingleDataFileWhenUnpackRatioIsBelowAllowedRatio() {
        Configuration configuration = createTestConfigurationWithThresholdAndRatio(ONE_KILOBYTE_IN_BYTES, 52);
        AsicContainerParser asicContainerParser = createAsicContainerParserFromPath(SINGLE_DATAFILE_CONTAINER_PATH, configuration);
        assertReadSucceeds(1, asicContainerParser);
    }

    @Test
    void testZipBombingNotDetectedWithSingleDataFileWhenUnpackRatioExceedsAllowedRatioButThresholdIsSlightlyAboveActualUnpackSize() {
        Configuration configuration = createTestConfigurationWithThresholdAndRatio(SINGLE_DATAFILE_CONTAINER_UNPACKED_SIZE_IN_BYTES + 1, 51);
        AsicContainerParser asicContainerParser = createAsicContainerParserFromPath(SINGLE_DATAFILE_CONTAINER_PATH, configuration);
        assertReadSucceeds(1, asicContainerParser);
    }

    @Test
    void testZipBombingDetectedWithSingleDataFileWhenUnpackRatioExceedsAllowedRatioAndThresholdIsSlightlyBelowActualUnpackSize() {
        Configuration configuration = createTestConfigurationWithThresholdAndRatio(SINGLE_DATAFILE_CONTAINER_UNPACKED_SIZE_IN_BYTES - 1, 51);
        AsicContainerParser asicContainerParser = createAsicContainerParserFromPath(SINGLE_DATAFILE_CONTAINER_PATH, configuration);
        assertReadThrowsZipBombingException(asicContainerParser);
    }

    @Test
    void testZipBombingDetectedWithMultipleDataFilesWhenUnpackRatioExceedsAllowedRatio() {
        Configuration configuration = createTestConfigurationWithThresholdAndRatio(ONE_KILOBYTE_IN_BYTES, 46);
        AsicContainerParser asicContainerParser = createAsicContainerParserFromPath(MULTIPLE_DATAFILE_CONTAINER_PATH, configuration);
        assertReadThrowsZipBombingException(asicContainerParser);
    }

    @Test
    void testZipBombingNotDetectedWithMultipleDataFilesWhenUnpackRatioIsBelowAllowedRatio() {
        Configuration configuration = createTestConfigurationWithThresholdAndRatio(ONE_KILOBYTE_IN_BYTES, 47);
        AsicContainerParser asicContainerParser = createAsicContainerParserFromPath(MULTIPLE_DATAFILE_CONTAINER_PATH, configuration);
        assertReadSucceeds(8, asicContainerParser);
    }

    @Test
    void testZipBombingNotDetectedWithMultipleDataFilesWhenUnpackRatioExceedsAllowedRatioButThresholdIsSlightlyAboveActualUnpackSize() {
        Configuration configuration = createTestConfigurationWithThresholdAndRatio(MULTIPLE_DATAFILE_CONTAINER_UNPACKED_SIZE_IN_BYTES + 1, 46);
        AsicContainerParser asicContainerParser = createAsicContainerParserFromPath(MULTIPLE_DATAFILE_CONTAINER_PATH, configuration);
        assertReadSucceeds(8, asicContainerParser);
    }

    @Test
    void testZipBombingDetectedWithMultipleDataFilesWhenUnpackRatioExceedsAllowedRatioAndThresholdIsSlightlyBelowActualUnpackSize() {
        Configuration configuration = createTestConfigurationWithThresholdAndRatio(MULTIPLE_DATAFILE_CONTAINER_UNPACKED_SIZE_IN_BYTES - 1, 46);
        AsicContainerParser asicContainerParser = createAsicContainerParserFromPath(MULTIPLE_DATAFILE_CONTAINER_PATH, configuration);
        assertReadThrowsZipBombingException(asicContainerParser);
    }

    protected static Configuration createTestConfigurationWithThresholdAndRatio(long threshold, int ratio) {
        Configuration configuration = Configuration.of(Configuration.Mode.TEST);
        configuration.setZipCompressionRatioCheckThresholdInBytes(threshold);
        configuration.setMaxAllowedZipCompressionRatio(ratio);
        return configuration;
    }

    protected static void assertReadSucceeds(int expectedDataFileCount, AsicContainerParser asicContainerParser) {
        AsicParseResult asicParseResult = asicContainerParser.read();
        assertNotNull(asicParseResult);
        assertNotNull(asicParseResult.getSignatures());
        assertEquals(1, asicParseResult.getSignatures().size());
        assertNotNull(asicParseResult.getDataFiles());
        assertEquals(expectedDataFileCount, asicParseResult.getDataFiles().size());
    }

    protected static void assertReadThrowsZipBombingException(AsicContainerParser asicContainerParser) {
        TechnicalException caughtException = assertThrows(
                TechnicalException.class,
                asicContainerParser::read
        );
        assertEquals(
                "Zip Bomb detected in the ZIP container. Validation is interrupted.",
                caughtException.getMessage()
        );
    }

}
