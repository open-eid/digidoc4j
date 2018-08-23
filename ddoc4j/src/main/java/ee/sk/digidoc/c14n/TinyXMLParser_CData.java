package ee.sk.digidoc.c14n;

public final class TinyXMLParser_CData {

    public TinyXMLParser_Fragment Begin;
    public TinyXMLParser_Fragment End;


    public TinyXMLParser_CData()
    {
    }


    public boolean get_IsValid()
    {

        if ((this.Begin == null))
        {
            return false;
        }


        if ((this.End == null))
        {
            return false;
        }


        if (!this.Begin.get_Item("<!["))
        {
            return false;
        }


        if (!this.End.get_Item("]]>"))
        {
            return false;
        }


        if ((this.Begin.get_Next() == null))
        {
            return false;
        }


        if (!this.Begin.get_Next().get_IsLiteral())
        {
            return false;
        }


        if (!this.Begin.get_Next().get_DataString().equals("CDATA"))
        {
            return false;
        }


        if ((this.Begin.get_Next().get_Next() == null))
        {
            return false;
        }


        if (!this.Begin.get_Next().get_Next().get_Item("["))
        {
            return false;
        }

        return true;
    }

    public String get_DataString()
    {
        return FragmentBase.GetDataBetweenFragments(this.Begin.get_Next().get_Next(), this.End);
    }

    public static TinyXMLParser_CData Of(TinyXMLParser_Fragment f)
    {
        TinyXMLParser_CData n;
        boolean seek;

        n = new TinyXMLParser_CData();
        n.Begin = f;
        n.End = f.get_Next();
        seek = true;

        if (!(n.End == null))
        {

            if (f.get_Item("<!["))
            {
                while (seek)
                {

                    if (n.End.get_Item("]]>"))
                    {
                        seek = false;
                    }
                    else
                    {

                        if ((n.End.get_Next() == null))
                        {
                            seek = false;
                        }
                        else
                        {
                            n.End = n.End.get_Next();
                        }

                    }

                }

                if (!n.get_IsValid())
                {
                    n = null;
                }

            }
            else
            {
                n = null;
            }

        }

        return n;
    }

}
