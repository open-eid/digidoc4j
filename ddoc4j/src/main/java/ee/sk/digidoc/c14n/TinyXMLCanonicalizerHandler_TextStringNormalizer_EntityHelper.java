package ee.sk.digidoc.c14n;

import ee.sk.digidoc.c14n.common.StringImplementation;

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
