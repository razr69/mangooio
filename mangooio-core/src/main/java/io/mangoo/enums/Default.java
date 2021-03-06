package io.mangoo.enums;

/**
 * Default application values
 *
 * @author svenkubiak
 * @author williamdunne
 *
 */
public enum Default {
    LANGUAGE("en"),
    DATA_DELIMITER("#"),
    DELIMITER("|"),
    FLASH_COOKIE_NAME("MANGOOIO-FLASH"),
    AUTH_COOKIE_NAME("MANGOOIO-AUTH"),
    COOKIE_EXPIRES("86400"),
    LOCALHOST("127.0.0.1"), //NOSONAR
    APPLICATION_HOST("127.0.0.1"), //NOSONAR
    JBCRYPT_ROUNDS("12"),
    APPLICATION_PORT("8080"),
    BUNDLE_NAME("translations/messages"),
    ASSETS_PATH("src/main/resources/files/assets/"),
    CONFIG_PATH("/src/main/resources/application.yaml"),
    STYLESHEET_FOLDER("stylesheets"),
    JAVSCRIPT_FOLDER("javascripts"),
    CONFIGURATION_FILE("application.yaml"),
    DEFAULT_CONFIGURATION("default"),
    VERSION_PROPERTIES("version.properties"),
    LOGO_FILE("logo.txt"),
    CONTENT_TYPE("text/html; charset=UTF-8"),
    SCHEDULER_PREFIX("org.quartz."),
    APPLICATION_SECRET_MIN_LENGTH("16"),
    SERVER("Undertow"),
    CACHE_NAME("mangooio"),
    TEMPLATES_FOLDER("/templates/"),
    AUTH_COOKIE_EXPIRES("3600"),
    COOKIE_NAME("MANGOOIO-SESSION"),
    COOKIE_I18N_NAME("MANGOOIO-I18N"),
    SPLITTER("&"),
    SEPERATOR(":"),
    NOSNIFF("nosniff"),
    SAMEORIGIN("SAMEORIGIN"),
    FILTER_METHOD("execute"),
    AUTHENTICITY_TOKEN("authenticityToken"),
    XSS_PROTECTION("1"),
    FILES_FOLDER("files"),
    MODULE_CLASS("conf.Module"),
    VERSION("unknown"),
    LOGBACK_PROD_FILE("logback.prod.xml"),
    NUMBER_FORMAT("0.######"),
    DEFAULT_TEMPLATES_DIR("/templates/defaults/"),
    X_XSS_PPROTECTION("1"),
    COOKIE_SECURE("false"), //NOSONAR
    AUTH_COOKIE_SECURE("false"), //NOSONAR
    CACHE_MAX_SIZE("5000"),
    APPLICATION_MASTERKEY("f8%q8G6Px8vxn7Tl%2P40vyT9e8KeTJ9"),
    APPLICATION_ADMIN_HEALTH("false"),
    APPLICATION_ADMIN_CACHE("false"),
    APPLICATION_ADMIN_CONFIG("false"),
    APPLICATION_ADMIN_ROUTES("false"),
    APPLICATION_ADMIN_SYSTEM("false"),
    APPLICATION_ADMIN_METRICS("false"),
    APPLICATION_ADMIN_MEMORY("false"),
    APPLICATION_ADMIN_SCHEDULER("false"),
    APPLICATION_TIMER("false"),
    AUTH_COOKIE_ENCRYPT("false"),
    AUTH_COOKIE_VERSION("0"),
    AUTH_COOKIE_REMEMBER_EXPIRES("1209600"),
    COOKIE_VERSION("0"),
    SCHEDULER_AUTOSTART("true"),
    SCHEDULER_JOB_GROUP("MangooSchedulerJobGroup"),
    SCHEDULER_TRIGGER_GROUP("MangooSchedulerTriggerGroup"),
    BASICAUTH_CREDENTIALS_LENGTH("2"),
    OAUTH_REQUEST_PARAMETER("oauth"),
    SCHEDULER_PACKAGE("jobs"),
    COOKIE_ENCRYPTION("false"),
    EXECUTION_THREADPOOL("10"),
    ROUTES_FILE("routes.yaml"),
    APPLICATION_CONTROLLER("controllers."),
    SSE_CACHE_PREFIX("MANGOOIO-SSE-"),
    WSS_CACHE_PREFIX("MANGOOIO-WSS-"),
    AUTHENTICATION("@authentication"),
    BLOCKING("@blocking"),
    CACHE_CLASS("io.mangoo.cache.GuavaCache"),
    VALUE_REQUIRED("For a new cache entry a non null value is required"),
    KEY_REQUIRED("For a new cache entry a non null key is required"),
    TEMPLATE_ENGINE_CLASS("io.mangoo.templating.freemarker.TemplateEngineFreemarker"),
    UNDERTOW_MAX_ENTITY_SIZE("4194304");

    private final String value;

    Default (String value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return this.value;
    }

    public int toInt() {
        return Integer.valueOf(this.value);
    }

    public long toLong() {
        return Long.valueOf(this.value);
    }

    public boolean toBoolean() {
        return Boolean.valueOf(this.value);
    }
}