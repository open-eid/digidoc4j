package ee.sk.digidoc.c14n;

public interface EntityParser_Handler {

    String ResolveEntity(EntityParser_Entity e);

    String ResolveText(String e);

}
