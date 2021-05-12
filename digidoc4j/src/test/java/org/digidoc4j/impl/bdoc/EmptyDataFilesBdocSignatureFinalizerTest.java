package org.digidoc4j.impl.bdoc;

import org.digidoc4j.DataFile;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.impl.EmptyDataFilesSignatureFinalizerTest;
import org.digidoc4j.impl.SignatureFinalizer;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignatureFinalizer;

import java.util.List;

public class EmptyDataFilesBdocSignatureFinalizerTest extends EmptyDataFilesSignatureFinalizerTest {

    @Override
    protected SignatureFinalizer createSignatureFinalizerWithDataFiles(List<DataFile> dataFiles) {
        return new BDocSignatureFinalizer(dataFiles, new SignatureParameters(), configuration);
    }

}
