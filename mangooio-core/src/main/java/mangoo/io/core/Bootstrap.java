package mangoo.io.core;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Properties;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.lalyos.jfiglet.FigletFont;
import com.google.common.io.Resources;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.Module;
import com.google.inject.Stage;
import com.icegreen.greenmail.util.GreenMail;
import com.icegreen.greenmail.util.ServerSetup;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.core.joran.spi.JoranException;
import io.undertow.Handlers;
import io.undertow.Undertow;
import io.undertow.server.RoutingHandler;
import io.undertow.server.handlers.PathHandler;
import io.undertow.server.handlers.resource.ClassPathResourceManager;
import io.undertow.server.handlers.resource.ResourceHandler;
import io.undertow.util.Methods;
import mangoo.io.configuration.Config;
import mangoo.io.enums.Default;
import mangoo.io.enums.Key;
import mangoo.io.enums.Mode;
import mangoo.io.enums.RouteType;
import mangoo.io.interfaces.MangooLifecycle;
import mangoo.io.interfaces.MangooRoutes;
import mangoo.io.routing.Route;
import mangoo.io.routing.Router;
import mangoo.io.routing.handlers.ExceptionHandler;
import mangoo.io.routing.handlers.FallbackHandler;
import mangoo.io.routing.handlers.RequestHandler;
import mangoo.io.routing.handlers.WebSocketHandler;

/**
 *
 * @author svenkubiak
 *
 */
public class Bootstrap {
    private static final Logger LOG = LoggerFactory.getLogger(Bootstrap.class);
    private PathHandler pathHandler;
    private ResourceHandler resourceHandler;
    private Mode mode;
    private Undertow undertow;
    private GreenMail fakeSMTP;
    private Injector injector;
    private Config config;
    private String host;
    private boolean error;
    private int port;
    private long start;
    private long end;

    public void prepareApplication() {
        this.start = new Date().getTime();
    }

    public void prepareMode() {
        String property = System.getProperty(Key.APPLICATION_MODE.toString());
        if (StringUtils.isNotBlank(property)) {
            switch (property.toLowerCase(Locale.ENGLISH)) {
            case "dev"  : this.mode = Mode.DEV;
            break;
            case "test" : this.mode = Mode.TEST;
            break;
            default     : this.mode = Mode.PROD;
            break;
            }
        } else {
            this.mode = Mode.PROD;
        }
    }

    public void prepareInjector() {
        this.injector = Guice.createInjector(Stage.PRODUCTION, getModules());
        this.config = this.injector.getInstance(Config.class);
        this.injector.getInstance(MangooLifecycle.class).applicationInitialized();
    }

    public void prepareConfig() {
        if (!this.config.hasValidSecret()) {
            LOG.error("Please make sure that your application.yaml has an application.secret property which has at least 16 characters");
            this.error = true;
        }
    }

    public void prepareRoutes() {
        if (!this.error) {
            try {
                MangooRoutes mangooRoutes = (MangooRoutes) this.injector.getInstance(Class.forName("conf.Routes"));
                mangooRoutes.routify();
            } catch (ClassNotFoundException e) {
                LOG.error("Failed to load routes. Please check, that conf/Routes.java exisits in your applicaiotn", e);
                this.error = true;
            }

            for (Route route : Router.getRoutes()) {
                if (RouteType.REQUEST.equals(route.getRouteType())) {
                    Class<?> controllerClass = route.getControllerClass();
                    boolean found = false;
                    for (Method method : controllerClass.getMethods()) {
                        if (method.getName().equals(route.getControllerMethod())) {
                            found = true;
                        }
                    }

                    if (!found) {
                        LOG.error("Could not find controller method '" + route.getControllerMethod() + "' in controller class '" + controllerClass.getSimpleName() + "'");
                        this.error = true;
                    }
                }
            }

            if (!this.error) {
                RoutingHandler routingHandler = Handlers.routing();
                routingHandler.setFallbackHandler(new FallbackHandler());
                for (Route route : Router.getRoutes()) {
                    if (RouteType.REQUEST.equals(route.getRouteType())) {
                        routingHandler.add(route.getRequestMethod(), route.getUrl(), new RequestHandler(route.getControllerClass(), route.getControllerMethod(), this.injector));
                    } else if (RouteType.RESOURCE_FILE.equals(route.getRouteType())) {
                        routingHandler.add(Methods.GET, route.getUrl(), getResourceHandler(null));
                    }
                }

                this.pathHandler = new PathHandler(routingHandler);
                for (Route route : Router.getRoutes()) {
                    if (RouteType.WEBSOCKET.equals(route.getRouteType())) {
                        this.pathHandler.addExactPath(route.getUrl(), Handlers.websocket(new WebSocketHandler(route.getControllerClass())));
                    } else if (RouteType.RESOURCE_PATH.equals(route.getRouteType())) {
                        this.pathHandler.addPrefixPath(route.getUrl(), getResourceHandler(route.getUrl()));
                    }
                }
            }
        }
    }

    private ResourceHandler getResourceHandler(String postfix) {
        if (StringUtils.isBlank(postfix)) {
            if (this.resourceHandler == null) {
                this.resourceHandler = new ResourceHandler(new ClassPathResourceManager(Thread.currentThread().getContextClassLoader(), "files/"));
            }

            return this.resourceHandler;
        }

        return new ResourceHandler(new ClassPathResourceManager(Thread.currentThread().getContextClassLoader(), "files" + postfix));
    }

    public void startServer() {
        if (!this.error) {
            this.host = this.config.getString(Key.APPLICATION_HOST, Default.APPLICATION_HOST.toString());
            this.port = this.config.getInt(Key.APPLICATION_PORT, Default.APPLICATION_PORT.toInt());

            Undertow server = Undertow.builder()
                    .addHttpListener(this.port, this.host)
                    .setHandler(Handlers.exceptionHandler(this.pathHandler).addExceptionHandler(Throwable.class, new ExceptionHandler()))
                    .build();

            server.start();

            this.undertow = server;
        }
    }

    private List<Module> getModules() {
        List<Module> modules = new ArrayList<Module>();
        if (!this.error) {
            try {
                Class<?> module = Class.forName("conf.Module");
                AbstractModule abstractModule;
                abstractModule = (AbstractModule) module.getConstructor().newInstance();
                modules.add(abstractModule);
                modules.add(new Modules());
            } catch (InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException
                    | NoSuchMethodException | SecurityException | ClassNotFoundException e) {
                LOG.error("Failed to load modules. Check that conf/Module.java exisits in your application", e);
                this.error = true;
            }
        }

        return modules;
    }

    public void applicationStarted() {
        if (!this.error) {
            this.end = new Date().getTime();
            String logo = "";
            try {
                logo = "\n" + FigletFont.convertOneLine("mangoo I/O");
                logo = logo + "\n\nhttps://mangoo.io | @mangoo_io | " + getApplicationVersion() + "\n";
            } catch (IOException e) {
                //intentionally left blank //NOSONAR
            }

            LOG.info(logo);
            LOG.info("mangoo I/O application started @{}:{} in {} ms in {} mode. Enjoy.", this.host, this.port, this.end - this.start, this.mode.toString());
            this.injector.getInstance(MangooLifecycle.class).applicationStarted();
        }
    }

    private static String getApplicationVersion() {
        String version = "UNKNOWN";
        try (InputStream inputStream = Resources.getResource(Default.VERSION_PROPERTIES.toString()).openStream()) {
            Properties properties = new Properties();
            properties.load(inputStream);
            version = String.valueOf(properties.get("version"));
        } catch (IOException e) {
            LOG.error("Failed to get application version", e);
        }

        return version;
    }

    public void startFakeSMTP() {
        if (!this.error && !Mode.PROD.equals(Application.getMode())) {
            GreenMail greenMail = new GreenMail(new ServerSetup(
                    this.config.getInt(Key.SMTP_PORT, Default.SMTP_PORT.toInt()),
                    this.config.getString(Key.SMTP_HOST, Default.LOCALHOST.toString()), "smtp"));
            greenMail.start();

            this.fakeSMTP = greenMail;
        }
    }

    public void prepareLogging() {
        if (Mode.PROD.equals(this.mode)) {
            LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
            try {
                URL resource = Resources.getResource("logback.prod.xml");
                if (resource != null) {
                    JoranConfigurator configurator = new JoranConfigurator();
                    configurator.setContext(context);
                    context.reset();
                    configurator.doConfigure(resource);
                }
            } catch (JoranException | IllegalArgumentException e) { //NOSONAR
                //intentionally left blank
            }
        }
    }

    public Mode getMode() {
        return this.mode;
    }

    public boolean isStarted() {
        return !this.error;
    }

    public Injector getInjector() {
        return this.injector;
    }

    public GreenMail getFakeSMTP() {
        return this.fakeSMTP;
    }

    public Undertow getServer() {
        return this.undertow;
    }
}