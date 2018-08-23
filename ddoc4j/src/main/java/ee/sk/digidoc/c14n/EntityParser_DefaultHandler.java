package ee.sk.digidoc.c14n;

public class EntityParser_DefaultHandler implements EntityParser_Handler {

    public EntityParser_DefaultHandler() {
    }

    public String ResolveEntity(EntityParser_Entity e) {

        if ((e.Hash == null)) {

            if (e.get_Item("lt")) {
                return "<";
            }


            if (e.get_Item("gt")) {
                return ">";
            }


            if (e.get_Item("amp")) {
                return "&";
            }


            if (e.get_Item("apos")) {
                return "\'";
            }


            if (e.get_Item("quot")) {
                return "\"";
            }

        } else {
            return null;
        }
        return null;
    }

    public String ResolveText(String e) {
        return e;
    }

}
