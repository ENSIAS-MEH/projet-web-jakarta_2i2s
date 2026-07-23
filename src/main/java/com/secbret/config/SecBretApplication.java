package com.secbret.config;

import jakarta.ws.rs.ApplicationPath;
import jakarta.ws.rs.core.Application;

/**
 * JAX-RS application entry point.
 * All REST endpoints are rooted under /api/v1 per Part III §0.
 */
@ApplicationPath("/api/v1")
public class SecBretApplication extends Application {
    // No custom config needed at this stage; Jersey/RESTEasy discovers resources via CDI.
}
