package org.digidoc4j.ddoc.c14n;

import org.digidoc4j.ddoc.c14n.common.StringImplementation;

class TinyXMLCanonicalizerHandler_TextStringNormalizer_EntityHelper {

    public String Text;


    public TinyXMLCanonicalizerHandler_TextStringNormalizer_EntityHelper(String e)
    {
        this.Text = e;
    }


    public void set_Item(String e, String value)
    {
        this.Text = StringImplementation.Replace(this.Text, e, value);
    }

}
