package org.digidoc4j.ddoc.c14n;

import java.util.ArrayList;

public final class TinyXMLParser_NestedElement {

    public TinyXMLParser_Fragment Begin;
    public TinyXMLParser_Fragment End;
    public TinyXMLParser_Fragment NameFragment;
    public TinyXMLParser_Fragment InnerBegin;
    public TinyXMLParser_Fragment InnerEnd;
    public ArrayList Children;

    public TinyXMLParser_NestedElement()
    {
    }



    public static TinyXMLParser_NestedElement Of(TinyXMLParser_Fragment f)
    {
        TinyXMLParser_NestedElement n;
        TinyXMLParser_Fragment i;
        boolean seek;
        TinyXMLParser_NestedElement nc;

        n = new TinyXMLParser_NestedElement();
        n.Begin = f;

        if (!n.Begin.get_Item("<!"))
        {
            return null;
        }

        n.NameFragment = n.Begin.get_Next();

        if (!n.NameFragment.get_IsLiteral())
        {
            return null;
        }

        i = n.NameFragment.get_NextNonSpace();
        seek = true;
        while (seek)
        {

            if ((i == null))
            {
                seek = false;
            }
            else
            {

                if (i.get_Item(">"))
                {
                    n.End = i;
                    seek = false;
                }
                else
                {

                    if (i.get_Item("["))
                    {
                        n.InnerBegin = i;
                        n.Children = new ArrayList();
                    }
                    else
                    {

                        if (i.get_Item("]"))
                        {
                            n.InnerEnd = i;
                        }
                        else
                        {

                            if (i.get_Item("<!"))
                            {
                                nc = TinyXMLParser_NestedElement.Of(i);

                                if (!(nc == null))
                                {
                                    i = nc.End.get_Next();
                                    n.Children.add(nc);
                                    continue;
                                }

                            }

                        }

                    }

                }

            }


            if (seek)
            {
                i = i.get_Next();
            }

        }
        return n;
    }

}
