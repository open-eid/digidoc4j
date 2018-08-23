package ee.sk.digidoc.c14n;

public final class TinyXMLParser_Fragment extends FragmentBase {

    public TinyXMLParser_Document OwnerDocument;
    private TinyXMLParser_Fragment _next;

    public TinyXMLParser_Fragment()
    {
        super();
    }


    private boolean GetMarkupChar(int o)
    {
        return ("<?![=]/->".indexOf(this.GetChar(o)) > -1);
    }

    private boolean GetSpaceChar(int o)
    {
        return ("\t\n\r ".indexOf(this.GetChar(o)) > -1);
    }

    private boolean GetQuoteChar(int o)
    {
        return ("\"\'".indexOf(this.GetChar(o)) > -1);
    }

    private boolean GetLiteralChar(int o)
    {

        if (this.GetMarkupChar(o))
        {
            return false;
        }


        if (this.GetSpaceChar(o))
        {
            return false;
        }


        if (this.GetQuoteChar(o))
        {
            return false;
        }

        return true;
    }

    public boolean get_IsMarkup()
    {
        return this.GetMarkupChar((int)0);
    }

    public boolean get_IsSpace()
    {
        return this.GetSpaceChar((int)0);
    }

    public boolean get_IsQuote()
    {
        return this.GetQuoteChar((int)0);
    }

    public boolean get_IsLiteral()
    {
        return this.GetLiteralChar((int)0);
    }

    private void SpawnAtOffset(int p)
    {
        this.Offset = p;
        this.Length = -1;

        if (this.GetMarkupChar((int)0))
        {

            for (this.Length = 0; (this.InBounds(this.get_LastOffset()) && this.GetMarkupChar(this.Length)); this.Length = (this.Length + 1))
            {
            }

            return;
        }


        if (this.GetSpaceChar((int)0))
        {

            for (this.Length = 0; (this.InBounds(this.get_LastOffset()) && this.GetSpaceChar(this.Length)); this.Length = (this.Length + 1))
            {
            }

            return;
        }


        if (this.GetQuoteChar((int)0))
        {

            for (this.Length = 0; (this.InBounds(this.get_LastOffset()) && this.GetQuoteChar(this.Length)); this.Length = (this.Length + 1))
            {
            }

            return;
        }


        if (this.GetLiteralChar((int)0))
        {

            for (this.Length = 0; (this.InBounds(this.get_LastOffset()) && this.GetLiteralChar(this.Length)); this.Length = (this.Length + 1))
            {
            }

        }

    }

    public void ToConsole()
    {
    }

    public TinyXMLParser_Fragment Clone()
    {
        return TinyXMLParser_Fragment.Of(this.Data, this.Offset);
    }

    private TinyXMLParser_Fragment get_InternalNext()
    {

        if ((this._next == null))
        {
            this._next = TinyXMLParser_Fragment.Of(this.Data, this.get_LastOffset());

            if (!(this._next == null))
            {
                this._next.OwnerDocument = this.OwnerDocument;
            }

        }

        return this._next;
    }

    public TinyXMLParser_Fragment get_Next()
    {

        if (!(this.get_InternalNext() == null))
        {
            this.get_InternalNext().SplitMarkup();
        }

        return this.get_InternalNext();
    }

    public TinyXMLParser_Fragment get_NextNonSpace()
    {
        TinyXMLParser_Fragment f;
        boolean seek;

        f = this.get_Next();
        seek = true;
        while (seek)
        {

            if ((f == null))
            {
                seek = false;
            }
            else
            {

                if (!f.get_IsSpace())
                {
                    seek = false;
                }

            }


            if (seek)
            {
                f = f.get_Next();
            }

        }
        return f;
    }

    public void SplitMarkup()
    {
        String[] stringArray1;


        if (this.get_IsMarkup())
        {
            stringArray1 = new String[]
                    {
                            "<!--",
                            "-->",
                            "<?",
                            "?>",
                            "<![",
                            "]]>",
                            "[",
                            "]",
                            "<!",
                            "/>",
                            "</",
                            ">",
                            "<",
                            "="
                    };

            if (!this.SplitBy(stringArray1))
            {
                this.SplitBy((int)1);
            }

            return;
        }


        if (this.get_IsQuote())
        {
            stringArray1 = new String[]
                    {
                            "\'",
                            "\""
                    };
            this.SplitBy(stringArray1);
        }

    }

    public void JoinNonMarkup()
    {
        boolean seek;
        String[] stringArray2;

        seek = true;
        while (seek)
        {

            if ((this.get_InternalNext() == null))
            {
                seek = false;
            }
            else
            {

                if (this.get_InternalNext().get_IsMarkup())
                {
                    stringArray2 = new String[]
                            {
                                    "<![",
                                    "<!--",
                                    "<?",
                                    "<",
                                    "</",
                                    "<!"
                            };

                    if (this.get_Next().get_Item(stringArray2))
                    {
                        seek = false;
                    }

                }

            }


            if (seek)
            {
                this.Join(this.get_InternalNext());
            }

        }
    }

    public void Join(TinyXMLParser_Fragment e)
    {
        this._next = null;
        this.Length = (this.Length + e.Length);
    }

    private void SplitBy(int len)
    {
        TinyXMLParser_Fragment n2;
        TinyXMLParser_Fragment n1;


        if ((len < this.Length))
        {
            n2 = this.get_InternalNext();
            n1 = this.Clone();
            this._next = n1;
            this._next._next = n2;
            FragmentBase.SplitBy(this, n1, len);
        }

    }

    protected boolean SplitBy(String e)
    {
        TinyXMLParser_Fragment n2;
        TinyXMLParser_Fragment n1;


        if (this.StartsWith(e))
        {

            if ((e.length() < this.Length))
            {
                n2 = this.get_InternalNext();
                n1 = this.Clone();
                this._next = n1;
                this._next._next = n2;
                FragmentBase.SplitBy(this, n1, e.length());
            }

            return true;
        }

        return false;
    }

    public TextPositionInfo get_TextPosition()
    {
        return new TextPositionInfo(this.Data, this.Offset);
    }

    public static TinyXMLParser_Fragment Of(byte[] data, int offset)
    {
        TinyXMLParser_Fragment n;

        n = new TinyXMLParser_Fragment();
        n.Data = data;

        if (n.InBounds(offset))
        {
            n.SpawnAtOffset(offset);
        }
        else
        {
            n = null;
        }

        return n;
    }

}
