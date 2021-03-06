package io.mangoo.routing.handlers;

import io.mangoo.enums.Default;
import io.mangoo.enums.Header;
import io.mangoo.enums.Template;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.Headers;
import io.undertow.util.StatusCodes;

/**
 *
 * @author svenkubiak
 *
 */
public class FallbackHandler implements HttpHandler {
    @Override
    public void handleRequest(HttpServerExchange exchange) throws Exception {
        exchange.getResponseHeaders().put(Header.X_XSS_PPROTECTION.toHttpString(), Default.XSS_PROTECTION.toInt());
        exchange.getResponseHeaders().put(Header.X_CONTENT_TYPE_OPTIONS.toHttpString(), Default.NOSNIFF.toString());
        exchange.getResponseHeaders().put(Header.X_FRAME_OPTIONS.toHttpString(), Default.SAMEORIGIN.toString());
        exchange.getResponseHeaders().put(Headers.SERVER, Default.SERVER.toString());
        exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, Default.CONTENT_TYPE.toString());
        exchange.setStatusCode(StatusCodes.NOT_FOUND);
        exchange.getResponseSender().send(Template.DEFAULT.notFound());
    }
}