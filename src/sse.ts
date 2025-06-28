// Edit file: index.ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import {
    ErrorCode,
    Implementation,
    McpError
} from "@modelcontextprotocol/sdk/types.js";

import { Database } from 'bun:sqlite';
import cors from 'cors';
import express, { Request, Response } from 'express';
import fs from 'fs/promises';
import http from 'http';
import https from 'https';
import { execSync } from 'child_process'; // Import for running build command
import { Command } from 'commander';
import path from 'path'; // Import path module
import { v4 as uuidv4 } from 'uuid';

// --- Local Imports ---
import { ClientFullEHR } from '../clientTypes.js'; // Import ClientFullEHR
import { AppConfig, loadConfig } from './config.ts';
import { addOauthRoutesAndProvider } from './oauth.ts';
import { UserSession, createOrOpenDbForSession, activeSessions, activeSseTransports, transportIdToMcpAccessToken } from './sessionUtils.js'; // Import the new DB function and state
import {
    registerEhrTools // Import the new function
} from './tools.js';
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { ehrToSqlite, sqliteToEhr } from './dbUtils.js'; // Import functions from dbUtils
import type { AuthzRequestState } from './oauth';
import { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
import { addStreamableHttpTransport } from './streamable-http.ts';

// --- Add Type Declaration for req.auth ---
declare module "express-serve-static-core" {
    interface Request {
        auth?: AuthInfo;
    }
}

// --- Global Config Variable ---
// Declared here, loaded in main()
let config: AppConfig;

// --- Runtime Checks (Using Config) ---
const SERVER_INFO: Implementation = { name: "Health Record Search MCP", version: "0.5.0" };

// --- MCP Server Instance ---
const mcpServer = new McpServer(SERVER_INFO);

// --- Register Tools ---

// Context retrieval function for SSE environment
async function getSseContext(
    _toolName: string,
    extra?: Record<string, any>
): Promise<{ fullEhr?: ClientFullEHR, db?: Database }> {
    const transportSessionId = extra?.sessionId as string | undefined;
    if (!transportSessionId) {
        throw new McpError(ErrorCode.InvalidRequest, "Missing session identifier.");
    }

    const mcpAccessToken = transportIdToMcpAccessToken.get(transportSessionId);
    if (!mcpAccessToken) {
        console.error(`[SSE Context] Inconsistency: Transport ${transportSessionId} has no corresponding MCP Access Token.`);
        throw new McpError(ErrorCode.InternalError, "Session data not found for active connection (no token mapping).");
    }

    const transportEntry = activeSseTransports.get(mcpAccessToken);
    if (!transportEntry) {
        // This case should be rare if the transportIdToMcpAccessToken map is synced correctly
        throw new McpError(ErrorCode.InvalidRequest, "Invalid or disconnected session.");
    }

    const session: UserSession | undefined = activeSessions.get(mcpAccessToken);
    
    if (!session) {
        // This indicates an inconsistency if transportEntry exists but session doesn't
        console.error(`[SSE Context] Inconsistency: Transport and token mapping exist for ${mcpAccessToken.substring(0,8)} but no session found in activeSessions.`);
        throw new McpError(ErrorCode.InternalError, "Session data not found for active connection.");
    }

    // Ensure config is loaded before trying to use it
    if (!config) {
         console.error(`[SSE Context] CRITICAL: AppConfig not loaded before getSseContext call for session ${mcpAccessToken?.substring(0,8)}.`);
         throw new McpError(ErrorCode.InternalError, "Server configuration not available.");
    }

    let db: Database | undefined = undefined;
    let fullEhr: ClientFullEHR | undefined = undefined;

    try {
        // Use the centralized function to get/open/create the DB handle
        db = await createOrOpenDbForSession(session, config);
    } catch (dbError: any) {
         console.error(`[SSE Context] Error getting/creating DB for session ${mcpAccessToken?.substring(0,8)}:`, dbError);
         // Propagate a generic internal error to the client
         throw new McpError(ErrorCode.InternalError, `Failed to access session data store: ${dbError.message}`);
    }

    // grep and eval need fullEhr - ensure it's loaded (should be by createSession/loadSession)
    // If DB is in-memory and wasn't populated initially, createOrOpenDb handles population now.
    if (!session.fullEhr) {
        // This might happen if loading from DB failed but DB handle was obtained?
        // Or if session somehow got created without fullEhr.
        console.warn(`[SSE Context] Session ${mcpAccessToken?.substring(0,8)} exists and DB handle obtained, but fullEhr is missing.`);
        // Depending on tool requirements, might not be critical, but likely indicates an issue.
        // For now, let's throw as tools expect it.
        throw new McpError(ErrorCode.InternalError, "Session data (fullEhr) not found for active connection.");
    }
    fullEhr = session.fullEhr;

    // Return the db handle obtained/created by createOrOpenDbForSession
    return { fullEhr, db };
}

// Register tools using the centralized function
registerEhrTools(mcpServer, getSseContext);

// --- Express Server Setup ---
const app = express();

// --- Main Application Startup Function ---
async function main() {
    try {
        // Set up command-line argument parsing
        const program = new Command();
        program
            .name('smart-mcp')
            .description('SMART on FHIR MCP Server')
            .version('0.5.0')
            .option('-c, --config <path>', 'Path to configuration file', './config.json')
            .parse(process.argv);
        
        const options = program.opts();
        const configPath = options.config || Bun.env.MCP_CONFIG_PATH || './config.json';
        
        console.log(`[CONFIG] Loading configuration from: ${configPath}`);
        config = await loadConfig(configPath);

        // --- Build the client-side retriever using the determined config ---
        console.log(`[BUILD] Building ehretriever with config: ${configPath}...`);
        try {
            const buildCommand = `bun run build:ehretriever --config ${configPath}`;
            // Execute synchronously, inherit stdio to see build output/errors
            execSync(buildCommand, { stdio: 'inherit' }); 
            console.log(`[BUILD] Successfully built ehretriever.`);
        } catch (buildError) {
            console.error(`[BUILD] FATAL ERROR: Failed to build ehretriever with config ${configPath}. See error below.`);
            // The error from execSync usually includes stdout/stderr, so no need to log buildError directly unless needed
            process.exit(1); // Exit if build fails
        }
        // --- End Build Step ---

        // --- Global Middleware ---
        app.use(cors());
        app.use(express.urlencoded({ extended: true }));
        // Note: express.json() is added selectively to specific POST endpoints where needed so it doesn't break SSE

        // Logging Middleware
        app.use((req, res, next) => {
            console.log(`[HTTP] ${req.method} ${req.path}`);
            next();
        });

        app.use(express.static( 'static'))


        // --- Add OAuth Routes and Get Provider ---
        const oauthProvider = addOauthRoutesAndProvider(app, config, activeSessions);
        console.log("[INIT] OAuth routes and provider initialized.");
        
        addStreamableHttpTransport(app, mcpServer, oauthProvider);
        console.log("[INIT] Streamable HTTP transport initialized.");

        // --- Custom Bearer Auth Middleware for SSE ---
        const sseBearerAuthMiddleware = async (req: Request, res: Response, next: express.NextFunction) => {
            try {
                const authHeader = req.headers.authorization;
                if (!authHeader || !authHeader.toLowerCase().startsWith('bearer ')) {
                    res.status(401).header('WWW-Authenticate', 'Bearer').json({ error: 'unauthorized', error_description: 'Missing bearer token.' });
                    return;
                }
                
                const token = authHeader.substring(7);
                const authInfo = await oauthProvider.verifyAccessToken(token);
                req.auth = authInfo;
                next();
            } catch (error: any) {
                console.warn(`[SSE Auth] Token verification failed: ${error.message}`);
                res.status(401).header('WWW-Authenticate', 'Bearer error="invalid_token"').json({ error: 'invalid_token', error_description: 'The access token is invalid or has expired.' });
            }
        };
        console.log("[INIT] SSE Bearer auth middleware initialized.");
        

        // --- API Endpoints (Not OAuth related) ---

        app.get('/api/list-stored-records', async (req, res) => { // Renamed endpoint
            if (!config.persistence?.enabled) {
                console.log("[/api/list-stored-records] Request received but persistence is disabled.");
                res.json([]); // Return empty array if persistence is off
                return;
            }
            const persistenceDir = config.persistence?.directory; // Use local var for clarity
            if (!persistenceDir) {
                console.error("[/api/list-stored-records] Persistence directory not configured.");
                res.status(500).json({ error: "Server configuration error: persistence directory missing." });
                return;
            }
        
            console.log(`[/api/list-stored-records] Scanning directory: ${persistenceDir}`);
            const recordList: any[] = []; // Renamed variable
            let db: Database | undefined = undefined;
        
            try {
                // Ensure the directory exists
                try {
                    await fs.access(persistenceDir);
                } catch (dirError: any) {
                    if (dirError.code === 'ENOENT') {
                        console.log(`[/api/list-stored-records] Persistence directory ${persistenceDir} does not exist. Returning empty list.`);
                        res.json([]); // Directory doesn't exist, so no records
                        return;
                    } else {
                        throw dirError; // Re-throw other errors
                    }
                }
        
                const files = await fs.readdir(persistenceDir);
                for (const file of files) {
                    if (file.endsWith('.sqlite')) {
                        const databaseId = file.replace('.sqlite', '');
                        const filePath = path.join(persistenceDir, file);
                        console.log(`[/api/list-stored-records] Processing file: ${file} (DB ID: ${databaseId})`);
        
                        try {
                            db = new Database(filePath);
                            // Query for Patient resource
                            const patientQuery = db.query<{ json: string }, []>(
                                `SELECT json FROM fhir_resources WHERE resource_type = 'Patient' LIMIT 1`
                            );
                            const patientRow = patientQuery.get(); // Use get() for LIMIT 1
        
                            if (patientRow) {
                                const patientResource = JSON.parse(patientRow.json);
                                const patientName = patientResource.name?.[0] ?
                                    `${patientResource.name[0].given?.join(' ') || ''} ${patientResource.name[0].family || ''}`.trim()
                                    : 'Unknown Name';
                                const patientId = patientResource.id || 'Unknown ID';
                                const patientBirthDate = patientResource.birthDate || undefined;
        
                                recordList.push({ // Use renamed variable
                                    databaseId,
                                    patientName,
                                    patientId,
                                    patientBirthDate
                                });
                                console.log(`[/api/list-stored-records] Added patient: ${patientName} (ID: ${patientId}) from DB: ${databaseId}`);
                            } else {
                                console.warn(`[/api/list-stored-records] No Patient resource found in DB: ${databaseId}`);
                                // Optionally add a placeholder if you want to list DBs without patients
                                // recordList.push({ databaseId, patientName: "No Patient Found", patientId: "N/A" });
                            }
                            db.close(); // Close DB after querying
                            db = undefined;
                        } catch (error: any) {
                            console.error(`[/api/list-stored-records] Error processing DB file ${file}:`, error);
                            // Simpler check: If db was assigned, try closing it.
                            if (db) {
                                try { db.close(); } catch (e) { /* ignore close error */ }
                            }
                            db = undefined;
                            // Continue to the next file
                        }
                    }
                }
                console.log(`[/api/list-stored-records] Finished scan. Found ${recordList.length} valid stored records.`); // Updated log
                res.json(recordList); // Use renamed variable
            } catch (error: any) {
                console.error("[/api/list-stored-records] Failed to list stored records:", error); // Updated log
                res.status(500).json({ error: "Failed to list stored records", message: error.message }); // Updated error message
            }
        });

        // --- MCP SSE Endpoint ---
        app.get("/mcp-sse", sseBearerAuthMiddleware, async (req: Request, res: Response) => {
            const authInfo = req.auth; // Provided by bearerAuthMiddleware
            if (!authInfo) {
                // This *shouldn't* happen if middleware is correct, but safeguard anyway
                console.error("[SSE GET] Middleware succeeded but req.auth is missing!");
                if (!res.headersSent) res.status(500).send("Authentication failed unexpectedly.");
                return;
            }
        
            const mcpAccessToken = authInfo.token;
            console.log(`[SSE GET] Auth successful for token ${mcpAccessToken.substring(0, 8)}..., client: ${authInfo.clientId}`);
        
            // --- Find the corresponding UserSession ---
            const session = activeSessions.get(mcpAccessToken);
            if (!session) {
                // Valid token, but no active session found (e.g., revoked, expired, server restart)
                console.warn(`[SSE GET] Session data not found for valid token ${mcpAccessToken.substring(0, 8)}... Client: ${authInfo.clientId}`);
                // Respond with 401 and specific error message
                res.set("WWW-Authenticate", `Bearer error="invalid_token", error_description="Session associated with token not found or expired."`)
                res.status(401).json({ error: "invalid_token", error_description: "Session associated with token not found or expired." });
                return;
            }
            console.log(`[SSE GET] Session found for token ${mcpAccessToken.substring(0, 8)}... Client: ${authInfo.clientId}`);
            console.log(session);
        
            // --- Verify Client ID Match (Optional but recommended unless checks disabled) ---
            if (!config.security?.disableClientChecks && session.mcpClientInfo.client_id !== authInfo.clientId) {
                 // Should be rare if token verification worked, but could happen with token theft / session mismatch
                console.error(`[SSE GET] Forbidden: Client ID mismatch for token ${mcpAccessToken.substring(0, 8)}... Token Client: ${authInfo.clientId}, Session Client: ${session.mcpClientInfo.client_id}`);
                res.set("WWW-Authenticate", `Bearer error="invalid_token", error_description="Token client ID does not match session client ID."`);
                // Use 403 Forbidden might be more appropriate than 401 here
                res.status(403).json({ error: "forbidden", error_description: "Token client ID does not match session client ID." });
                return;
            }
        
            // --- Establish SSE Connection ---
            let transport: SSEServerTransport | null = null;
            try {
                // Create the SSE transport using the response object
                transport = new SSEServerTransport(`/mcp-messages`, res); // Pass base path for POST messages
                const transportSessionId = transport.sessionId; // Get the unique ID generated by the transport
        
                // Link the transport session ID back to the UserSession
                // session.transportSessionId = transportSessionId;
        
                // Store the active transport, linking it to the MCP token and auth info
                activeSseTransports.set(mcpAccessToken, { 
                    transport: transport,
                });
                // Create the reverse mapping
                transportIdToMcpAccessToken.set(transportSessionId, mcpAccessToken);

                console.log(`[SSE GET] Client connected & authenticated. Transport Session ID: ${transportSessionId}, linked to MCP Token: ${mcpAccessToken.substring(0, 8)}...`);
        
                await mcpServer.connect(transport);
                 console.log(`[SSE GET] MCP Server connected to transport ${transportSessionId}. Waiting for messages...`);
            } catch (error) {
                console.error("[SSE GET] Error setting up authenticated SSE connection:", error);
                // --- Cleanup on Error ---
                if (transport) {
                     const transportSessionId = transport.sessionId; // Get ID even if setup failed mid-way
                     console.log(`[SSE Error Cleanup] Removing transport entry for ${transportSessionId}`);
                    activeSseTransports.delete(mcpAccessToken);
                    transportIdToMcpAccessToken.delete(transportSessionId);
                    // If the session was partially updated, reset its transport ID
                    // if (session && session.transportSessionId === transportSessionId) {
                    //      session.transportSessionId = ""; 
                    //  }
                     // Ensure transport is closed if possible
                     try { transport.close(); } catch(e) {}
                }
                
                // --- Send Error Response if possible ---
                if (!res.headersSent) {
                    // TODO: Improve error typing and mapping to OAuthError codes
                     const message = (error instanceof Error /* OAuthError */) ? "SSE connection setup failed due to authorization issue." : "Failed to establish SSE connection";
                     const statusCode = 500; // Default to 500, refine if OAuthError is used
                     res.status(statusCode).send(message);
                } else if (!res.writableEnded) {
                     // If headers sent but connection not ended, try to end it cleanly
                     console.log("[SSE GET] Ending response stream after error during setup.");
                     res.end();
                }
            }
        });
        
        // --- MCP Message POST Endpoint ---
        app.post("/mcp-messages", sseBearerAuthMiddleware, (req: Request, res: Response) => { 
            const authInfo = req.auth; // Provided by bearerAuthMiddleware
            if (!authInfo) {
                console.error("[MCP POST] Middleware succeeded but req.auth is missing!");
                if (!res.headersSent) res.status(500).send("Authentication failed unexpectedly.");
                return;
            }

            const session = activeSessions.get(authInfo.token);
            if (!session) {
                // This case should be rare since bearerAuthMiddleware just validated the token
                console.warn(`[MCP POST] Inconsistency: Auth succeeded but session not found for token ${authInfo.token.substring(0,8)}...`);
                res.status(404).send("Invalid or expired session");
                return;
            }
            
            const transportEntry = activeSseTransports.get(authInfo.token);
            if (!transportEntry) {
                console.warn(`[MCP POST] Received POST for active session without a transport: ${authInfo.token.substring(0,8)}... Has the SSE connection been established?`);
                res.status(404).send("SSE transport not established for this session");
                return;
            }
        
            const transport = transportEntry.transport;
            try {
                console.log(`[MCP POST] Received POST for session with MCP Token: ${authInfo.token.substring(0,8)}...`);
                // Log headers or body if needed for debugging (careful with sensitive data)
                // console.log("[MCP POST] Headers:", req.headers);
                // console.log("[MCP POST] Body (partial):", JSON.stringify(req.body).substring(0, 200)); 
                
                // Pass the request and response to the transport's handler
                // The SDK's handlePostMessage will parse the MCP message, find the handler, execute it, and send the response.
                transport.handlePostMessage(req, res);
                console.log(`[MCP POST] Handled POST for session ${authInfo.token.substring(0,8)}...`);
        
            } catch (error) {
                // Catch errors specifically from handlePostMessage (e.g., invalid message format, handler execution error)
                console.error(`[MCP POST] Error in handlePostMessage for session ${authInfo.token.substring(0,8)}...:`, error);
                if (!res.headersSent) {
                    // Send a generic 500 error if the handler failed internally
                    res.status(500).send("Error processing message");
                } else if (!res.writableEnded) {
                     console.log("[MCP POST] Ending response stream after error during handling.");
                    res.end(); // Ensure the response is closed if an error occurred after headers were sent
                }
            }
        });

        // --- Error Handling Middleware (Last Resort) ---
        // Catches errors not handled by specific route handlers
        app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
            console.error("[HTTP Unhandled Error] An unexpected error occurred:", err);
            
            // If headers already sent, delegate to Express default handler (closes connection)
            if (res.headersSent) {
                console.error("[HTTP Unhandled Error] Headers already sent, cannot send error response.");
                return next(err);
            }
        
            // Send a generic 500 response
            res.status(500).json({ 
                error: "Internal Server Error", 
                // Avoid sending detailed error messages in production unless configured
                message: "An unexpected internal server error occurred." // Generic message
            });
        });


        // --- Start Server ---
            let server: http.Server | https.Server; // Union type
            let serverOptions: https.ServerOptions = {}; // Use https.ServerOptions type
        
            // Use config for HTTPS settings
            if (config.server.https.enabled) {
                console.log("[HTTP] HTTPS is enabled. Loading certificates...");
                // Paths validated by loadConfig earlier
                try {
                    // Use await with fs.readFile
                    const cert = await fs.readFile(config.server.https.certPath!);
                    const key = await fs.readFile(config.server.https.keyPath!);
                    serverOptions = { key: key, cert: cert };
                    console.log(`[HTTP] Certificates loaded successfully from ${config.server.https.certPath} and ${config.server.https.keyPath}`);
                    server = https.createServer(serverOptions, app); // Create HTTPS server
                } catch (error) {
                    console.error(`[HTTP] FATAL ERROR: Failed to read certificate files:`, error);
                    process.exit(1); // Exit if certs can't be loaded
                }
            } else {
                console.log("[HTTP] HTTPS is disabled. Creating HTTP server.");
                server = http.createServer(app); // Create HTTP server
            }
        
            // Use config for port and derive protocol for logging
            const protocol = config.server.https.enabled ? 'https' : 'http';
            server.listen(config.server.port, () => {
                // Log the actual base URL from config
                console.log(`[HTTP] Server listening on ${config.server.baseUrl}`);
                console.log(`[MCP] OAuth Issuer: ${config.server.baseUrl}`);
                console.log(`[MCP] Authorization Endpoint: ${config.server.baseUrl}/authorize`);
                console.log(`[MCP] Token Endpoint: ${config.server.baseUrl}/token`);
                console.log(`[MCP] SSE Endpoint: ${config.server.baseUrl}/mcp-sse`);
            });
        
            // --- Graceful Shutdown ---
            const shutdown = async (signal: string) => {
                console.log(`\nReceived ${signal}. Shutting down gracefully...`);
                    
                // 1. Stop accepting new connections
                server.close(async (err) => {
                    if (err) {
                        console.error(`[Shutdown] Error closing ${protocol} server:`, err);
                    } else {
                        console.log(`[Shutdown] ${protocol} server closed. No longer accepting connections.`);
                    }
                     // Proceed with other cleanup even if server close had error
        
                     // 2. Close MCP Server (closes active SSE transports via SDK)
                     try {
                        await mcpServer.close();
                        console.log("[Shutdown] MCP server and active SSE transports closed.");
                     } catch (e) { 
                        console.error("[Shutdown] Error closing MCP server:", e); 
                     }
        
                     // 3. Close remaining resources (DBs, clear caches)
                    console.log(`[Shutdown] Closing ${activeSessions.size} active session(s) and their database connections...`);
                     for (const [token, session] of activeSessions.entries()) {
                         if (session.db) {
                             try {
                                 // console.log(`[Shutdown] Closing DB for session token ${token.substring(0, 8)}...`);
                                 session.db.close();
                             } catch (dbErr) { 
                                 console.error(`[Shutdown] Error closing DB for session token ${token.substring(0, 8)}...:`, dbErr); 
                             }
                         }
                     }
                     activeSessions.clear();
                     console.log("[Shutdown] Active sessions cleared.");
                     
                     // Clear other state maps (Moved inside src/oauth.ts - how to clear?)
                     // We might need an explicit shutdown function exported from oauth.ts
                     // Or rely on process exit to clear memory.
                     // sessionsByMcpAuthCode.clear();
                     // authFlowStates.clear();
                     // pickerSessions.clear();
                     // registeredMcpClients.clear(); // Clear registered clients if dynamic
                     activeSseTransports.clear(); // Should be cleared by mcpServer.close, but clear again to be sure
                     transportIdToMcpAccessToken.clear();
                     console.log("[Shutdown] Temporary state maps cleared (Note: OAuth internal state persists until exit).");
        
                     console.log("[Shutdown] Shutdown complete.");
                     process.exit(0); // Exit cleanly
                });
        
                // If server close takes too long, force exit
                 setTimeout(() => {
                     console.error('[Shutdown] Could not close connections in time, forcing shutdown.');
                     process.exit(1);
                 }, 10000); // 10 second timeout
        
            };
        
            // Listen for termination signals
            process.on('SIGINT', () => shutdown('SIGINT'));
            process.on('SIGTERM', () => shutdown('SIGTERM'));

    } catch (error) {
        console.error("[Startup] FATAL ERROR during application startup:", error);
        process.exit(1);
    }
}

// Start the application
main();