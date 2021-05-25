package org.digidoc4j.impl.bdoc.asic;

import org.digidoc4j.Container;
import org.digidoc4j.impl.asic.EmptyDataFilesContainerTest;

public class EmptyDataFilesAsicSContainerTest extends EmptyDataFilesContainerTest {

    @Override
    protected Container.DocumentType getDocumentType() {
        return Container.DocumentType.ASICS;
    }

}
