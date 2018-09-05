package org.digidoc4j.ddoc.c14n;

public final class EntityParser_Fragment extends FragmentBase {

    private EntityParser_Fragment _next;


    public EntityParser_Fragment()
    {
        super();
    }


    public EntityParser_Fragment get_InternalNext()
    {

        if ((this._next == null))
        {
            this._next = EntityParser_Fragment.Of(this.Data, this.get_LastOffset(), this.ExplicitBounds);
        }

        return this._next;
    }

    public EntityParser_Fragment Clone()
    {
        return EntityParser_Fragment.Of(this.Data, this.Offset, this.ExplicitBounds);
    }

    public void SplitMarkup()
    {
        String[] stringArray1;


        if (this.get_IsMarkup())
        {
            stringArray1 = new String[]
                {
                    "&",
                    ";",
                    "#"
                };
            this.SplitBy(stringArray1);
        }

    }

    public EntityParser_Fragment get_Next()
    {

        if (!(this.get_InternalNext() == null))
        {
            this.get_InternalNext().SplitMarkup();
        }

        return this.get_InternalNext();
    }

    protected boolean SplitBy(String e)
    {
        EntityParser_Fragment n2;
        EntityParser_Fragment n1;


        if (this.StartsWith(e))
        {

            if ((e.length() < this.Length))
            {
                n2 = this.get_InternalNext();
                n1 = this.Clone();
                this._next = n1;
                if(this._next != null)
                this._next._next = n2;
                FragmentBase.SplitBy(this, n1, e.length());
            }

            return true;
        }

        return false;
    }

    private boolean GetMarkupChar(int o)
    {
        return ("&#;".indexOf(this.GetChar(o)) > -1);
    }

    private boolean GetLiteralChar(int o)
    {

        if (this.GetMarkupChar(o))
        {
            return false;
        }

        return true;
    }

    public boolean get_IsMarkup()
    {
        return this.GetMarkupChar((int)0);
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


        if (this.GetLiteralChar((int)0))
        {

            for (this.Length = 0; (this.InBounds(this.get_LastOffset()) && this.GetLiteralChar(this.Length)); this.Length = (this.Length + 1))
            {
            }

        }

    }

    public static EntityParser_Fragment Of(byte[] data, int offset, FragmentBase_Bounds bounds)
    {
        EntityParser_Fragment n;

        n = new EntityParser_Fragment();
        n.ExplicitBounds = bounds;
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
