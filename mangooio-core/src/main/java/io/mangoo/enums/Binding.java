package io.mangoo.enums;

/**
 *
 * @author svenkubiak
 *
 */
public enum Binding {
    FORM("io.mangoo.routing.bindings.Form"),
    SESSION("io.mangoo.routing.bindings.Session"),
    FLASH("io.mangoo.routing.bindings.Flash"),
    REQUEST("io.mangoo.routing.bindings.Request"),
    BODY("io.mangoo.routing.bindings.Body"),
    LOCALDATE("java.time.LocalDate"),
    STRING("java.lang.String"),
    INTEGER("java.lang.Integer"),
    INT_PRIMITIVE("int"),
    FLOAT("java.lang.Float"),
    FLOAT_PRIMITIVE("float"),
    LONG("java.lang.Long"),
    LONG_PRIMITIVE("long"),
    DOUBLE("java.lang.Double"),
    DOUBLE_PRIMITIVE("double"),
    LOCALDATETIME("java.time.LocalDateTime"),
    AUTHENTICATION("io.mangoo.authentication.Authentication"),
    UNDEFINED("undefined");

    private final String value;

    Binding (String value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return this.value;
    }

    public static Binding fromString(String value) {
        for (Binding binding : Binding.values()) {
            if (binding.toString().equalsIgnoreCase(value)) {
                return binding;
            }
        }

        return null;
    }
}