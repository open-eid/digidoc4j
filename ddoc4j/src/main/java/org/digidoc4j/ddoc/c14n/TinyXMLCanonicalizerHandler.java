package org.digidoc4j.ddoc.c14n;

import org.digidoc4j.ddoc.c14n.common.Convert;
import org.digidoc4j.ddoc.c14n.common.StringImplementation;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Collections;

public class TinyXMLCanonicalizerHandler implements TinyXMLParser_Handler {
    public ByteArrayOutputStream BaseStream;
    public boolean AppendNewlineAfterDocumentElement;
    public boolean IsWithComments;


    public TinyXMLCanonicalizerHandler()
    {
        this.BaseStream = new ByteArrayOutputStream();
        this.AppendNewlineAfterDocumentElement = false;
        this.IsWithComments = false;
    }


    public byte[] get_Bytes()
    {
        return this.BaseStream.toByteArray();
    }

    public void Write(String e)
    {
        byte[] u;

        u = Convert.ToByteArray(e, "UTF-8");
        this.BaseStream.write(u, 0, u.length);
    }

    public void startElement(TinyXMLParser_Element e)
    {
        ArrayList x;

        this.Write("<"+ e.get_TagName());
        x = e.get_Attributes();
        this.WriteAttributes(x, e);
        this.Write(">");
    }

    private void WriteAttributes(ArrayList x, TinyXMLParser_Element owner)
    {
        int length;
        int i;

        length = x.size();

        if ((length > 0))
        {
            Collections.sort(x, new TinyXMLParser_Attribute_AttributeComparator());

            for (i = 0; (i < length); i++)
            {
                this.WriteAttribute(x, owner, i);
            }

        }

    }

    private boolean CanNormalizeXMLNS(TinyXMLParser_Attribute a, TinyXMLParser_Element owner)
    {
        TinyXMLParser_Attribute u;
        String _a;
        String _u;


        if ((owner == null))
        {
            return false;
        }


        if ((owner.Parent == null))
        {
            return false;
        }

        u = TinyXMLCanonicalizerHandler.GetAnyParentXMLNS(a, owner.Parent);
        _a = this.GetAttributeNormalizedValue(a);

        if ((u == null))
        {

            if (_a.equals(""))
            {
                return true;
            }

            return false;
        }

        _u = this.GetAttributeNormalizedValue(u);

        if (_u.equals(_a))
        {
            return true;
        }

        return false;
    }

    private void WriteAttribute(ArrayList x, TinyXMLParser_Element owner, int i)
    {
        TinyXMLParser_Attribute a;
        String[] stringArray2;

        a = ((TinyXMLParser_Attribute)x.get(i));

        if (a.get_IsXMLNS())
        {

            if (this.CanNormalizeXMLNS(a, owner))
            {
                return;
            }

        }

        stringArray2 = new String[]
            {
                " ",
                a.NameFragment.get_DataString(),
                "=\"",
                this.GetAttributeNormalizedValue(a),
                "\""
            };
        this.Write(StringImplementation.Concat(stringArray2));
    }

    private String GetAttributeNormalizedValue(TinyXMLParser_Attribute a)
    {
        EntityParser p;
        TinyXMLCanonicalizerHandler_TextStringNormalizer tx;

        p = EntityParser.Of(a.get_ValueFragment());
        tx = new TinyXMLCanonicalizerHandler_TextStringNormalizer();
        tx.IsAttribute = true;
        p.Resolver = tx;
        return p.get_Text();
    }

    public void endElement(TinyXMLParser_Element e)
    {
        this.Write("</"+ e.get_TagName()+ ">");

        if (this.AppendNewlineAfterDocumentElement)
        {

            if ((e.Parent == null))
            {
                this.WriteLine();
            }

        }

    }

    private void WriteLine()
    {
        this.Write("\n");
    }

    public void PI(TinyXMLParser_Tag e)
    {
        ArrayList x;


        if (e.get_Name().equals("xml"))
        {
            return;
        }

        this.Write("<?");
        this.Write(e.get_NameFragment().get_DataString());
        x = e.Attributes;
        this.WriteAttributes(x, null);
        this.Write("?>");
        this.WriteLine();
    }

    public void startDocument()
    {
    }

    public void endDocument()
    {
    }

    public void text(TinyXMLParser_TextNode str)
    {
        EntityParser p;


        if (!(str.Parent == null))
        {
            p = EntityParser.Of(str.ValueFragment);
            p.Resolver = new TinyXMLCanonicalizerHandler_TextStringNormalizer();
            this.Write(p.get_Text());
        }

    }

    public void cdata(TinyXMLParser_CData str)
    {
        this.Write(TinyXMLCanonicalizerHandler_TextStringNormalizer.StaticResolveTextCData(str.get_DataString()));
    }

    public void comment(TinyXMLParser_Comment str)
    {

        if (this.IsWithComments)
        {
            this.Write("<!-- ");
            this.Write(str.ValueTag.get_DataString());
            this.Write(" -->");

            if ((str.Parent == null))
            {
                this.WriteLine();
            }

        }

    }

    public void nestedElement(TinyXMLParser_NestedElement e)
    {
    }

    private static TinyXMLParser_Attribute GetAnyParentXMLNS(TinyXMLParser_Attribute a, TinyXMLParser_Element e)
    {
        TinyXMLParser_Element p;
        TinyXMLParser_Attribute x;

        p = e;
        while (!(p == null))
        {
            x = p.GetXMLNSAttributeValue(a.get_NameString());

            if (!(x == null))
            {
                return x;
            }

            p = p.Parent;
        }
        return null;
    }

}
