package ee.sk.digidoc.c14n;

import java.util.Comparator;

public class TinyXMLParser_Attribute_AttributeComparator implements Comparator {

    public TinyXMLParser_Attribute_AttributeComparator() {
    }


    public int compare(Object o1, Object o2) {
        TinyXMLParser_Attribute a;
        TinyXMLParser_Attribute b;

        a = ((TinyXMLParser_Attribute)o1);
        b = ((TinyXMLParser_Attribute)o2);
        return a.CompareTo(b);
    }

    public boolean equals(Object obj) {
        return (this == obj);
    }

}
