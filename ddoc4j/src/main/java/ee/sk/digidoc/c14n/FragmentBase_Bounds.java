package ee.sk.digidoc.c14n;

public class FragmentBase_Bounds {
    public int Offset;
    public int Length;


    public FragmentBase_Bounds(int o, int len)
    {
        this.Offset = o;
        this.Length = len;
    }


    public boolean InBounds(int p)
    {

        if ((p < this.Offset))
        {
            return false;
        }

        return (p < (this.Offset + this.Length));
    }

}
