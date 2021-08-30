package org.digidoc4j.impl.asic;

import org.digidoc4j.Configuration;

public class AsicFileContainerParserZipBombingTest extends AsicContainerParserZipBombingTest {

    @Override
    protected AsicContainerParser createAsicContainerParserFromPath(String path, Configuration configuration) {
        return new AsicFileContainerParser(path, configuration);
    }

}
