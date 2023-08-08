package org.digidoc4j.impl.asic.asics;

import org.digidoc4j.DataFile;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.impl.EmptyDataFilesSignatureFinalizerTest;
import org.digidoc4j.impl.SignatureFinalizer;

import java.util.List;

public class EmptyDataFilesAsicSSignatureFinalizerTest extends EmptyDataFilesSignatureFinalizerTest {

    @Override
    protected SignatureFinalizer createSignatureFinalizerWithDataFiles(List<DataFile> dataFiles) {
        return new AsicSSignatureFinalizer(dataFiles, new SignatureParameters(), configuration);
    }

}