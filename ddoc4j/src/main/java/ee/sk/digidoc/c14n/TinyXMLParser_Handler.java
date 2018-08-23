package ee.sk.digidoc.c14n;

public interface TinyXMLParser_Handler {

    void startDocument();

    void endDocument();

    void nestedElement(TinyXMLParser_NestedElement e);

    void startElement(TinyXMLParser_Element e);

    void endElement(TinyXMLParser_Element e);

    void PI(TinyXMLParser_Tag e);

    void text(TinyXMLParser_TextNode str);

    void comment(TinyXMLParser_Comment str);

    void cdata(TinyXMLParser_CData str);

}
