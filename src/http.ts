import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
    ErrorCode,
    Implementation,
    McpError
} from "@modelcontextprotocol/sdk/types.js";
import { Database } from 'bun:sqlite';
import cors from 'cors';
import express, { Request, Response, NextFunction } from 'express';
import http from 'http';
import https from 'https';
import fs from 'fs/promises';
import { Command } from 'commander';
import path from 'path';
import { z } from "zod";

import { AppConfig, loadConfig } from './config.js';
import { addOauthRoutesAndProvider, MyOAuthServerProvider } from './oauth.js';
import { UserSession, createOrOpenDbForSession, activeSessions } from './sessionUtils.js';
import { registerEhrTools } from './tools.js';
import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { ClientFullEHR } from '../clientTypes.js';

// Augment Express Request type
declare module "express-serve-static-core" {
    interface Request {
        auth?: AuthInfo;
    }
}

const SERVER_INFO: Implementation = { name: "Health Record Search MCP (Stateless HTTP)", version: "0.6.0" };
let config: AppConfig;
let oauthProvider: MyOAuthServerProvider;

async function main() {
    const program = new Command();
    program
        .name('smart-mcp-http')
        .description('SMART on FHIR MCP Server (Stateless Streamable HTTP)')
        .version('0.6.0')
        .option('-c, --config <path>', 'Path to configuration file', './config.json')
        .parse(process.argv);

    const options = program.opts();
    const configPath = options.config || Bun.env.MCP_CONFIG_PATH || './config.json';

    console.log(`[CONFIG] Loading configuration from: ${configPath}`);
    config = await loadConfig(configPath);

    const app = express();
    app.use(cors());
    app.use(express.json({ limit: '50mb' }));
    app.use(express.urlencoded({ extended: true }));

    app.use((req, res, next) => {
        console.log(`[HTTP] ${req.method} ${req.path}`);
        next();
    });
    
    app.use(express.static('static'));

    // Setup OAuth routes to enable token generation
    oauthProvider = addOauthRoutesAndProvider(app, config, activeSessions);
    console.log("[INIT] OAuth routes and provider initialized.");

    app.get('/api/list-stored-records', async (req, res) => { 
        if (!config.persistence?.enabled) {
            console.log("[/api/list-stored-records] Request received but persistence is disabled.");
            res.json([]); 
            return;
        }
        const persistenceDir = config.persistence?.directory; 
        if (!persistenceDir) {
            console.error("[/api/list-stored-records] Persistence directory not configured.");
            res.status(500).json({ error: "Server configuration error: persistence directory missing." });
            return;
        }
    
        console.log(`[/api/list-stored-records] Scanning directory: ${persistenceDir}`);
        const recordList: any[] = []; 
        let db: Database | undefined = undefined;
    
        try {
            try {
                await fs.access(persistenceDir);
            } catch (dirError: any) {
                if (dirError.code === 'ENOENT') {
                    console.log(`[/api/list-stored-records] Persistence directory ${persistenceDir} does not exist. Returning empty list.`);
                    res.json([]); 
                    return;
                } else {
                    throw dirError; 
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
                        const patientQuery = db.query<{ json: string }, []>(
                            `SELECT json FROM fhir_resources WHERE resource_type = 'Patient' LIMIT 1`
                        );
                        const patientRow = patientQuery.get(); 
    
                        if (patientRow) {
                            const patientResource = JSON.parse(patientRow.json);
                            const patientName = patientResource.name?.[0] ?
                                `${patientResource.name[0].given?.join(' ') || ''} ${patientResource.name[0].family || ''}`.trim()
                                : 'Unknown Name';
                            const patientId = patientResource.id || 'Unknown ID';
                            const patientBirthDate = patientResource.birthDate || undefined;
    
                            recordList.push({ 
                                databaseId,
                                patientName,
                                patientId,
                                patientBirthDate
                            });
                            console.log(`[/api/list-stored-records] Added patient: ${patientName} (ID: ${patientId}) from DB: ${databaseId}`);
                        } else {
                            console.warn(`[/api/list-stored-records] No Patient resource found in DB: ${databaseId}`);
                        }
                        db.close(); 
                        db = undefined;
                    } catch (error: any) {
                        console.error(`[/api/list-stored-records] Error processing DB file ${file}:`, error);
                        if (db) {
                            try { db.close(); } catch (e) { /* ignore close error */ }
                        }
                        db = undefined;
                    }
                }
            }
            console.log(`[/api/list-stored-records] Finished scan. Found ${recordList.length} valid stored records.`); 
            res.json(recordList); 
        } catch (error: any) {
            console.error("[/api/list-stored-records] Failed to list stored records:", error); 
            res.status(500).json({ error: "Failed to list stored records", message: error.message });
        }
    });

    // Custom bearer auth middleware
    const customBearerAuthMiddleware = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.toLowerCase().startsWith('bearer ')) {
            res.status(401).header('WWW-Authenticate', 'Bearer').json({ error: 'unauthorized', error_description: 'Missing bearer token.' });
            return;
        }
        
        const token = authHeader.substring(7);
        try {
            const authInfo = await oauthProvider.verifyAccessToken(token);
            req.auth = authInfo;
            next();
        } catch (error: any) {
            res.status(401).header('WWW-Authenticate', 'Bearer error="invalid_token"').json({ error: 'invalid_token', error_description: 'The access token is invalid or has expired.' });
            return;
        }
    };

    // MCP Endpoint
    app.post('/mcp', customBearerAuthMiddleware, async (req: Request, res: Response): Promise<void> => {
        const token = req.auth!.token!;
        console.log(`[/mcp POST] Handling stateless request for authenticated token ${token.substring(0,8)}...`);

        // We still check for an active session to ensure the token is valid,
        // but we do not use this for MCP-level session state.
        const userSession = activeSessions.get(token);
        if (!userSession) {
            res.status(403).json({ error: 'forbidden', error_description: 'No active session found for this token.' });
            return;
        }

        // Following the stateless example: create a new server and transport for each request.
        try {
            const mcpServer = new McpServer(SERVER_INFO);

            // Context retrieval function specific to this request
            async function getRequestContext(): Promise<{ fullEhr?: ClientFullEHR; db?: Database }> {
                const session = activeSessions.get(token);
                if (!session) {
                    throw new McpError(ErrorCode.InvalidRequest, "Session not found for token.");
                }
                const db = await createOrOpenDbForSession(session, config);
                return { fullEhr: session.fullEhr, db };
            }

            // Register EHR tools with the request-specific context
            registerEhrTools(mcpServer, getRequestContext);

            const transport = new StreamableHTTPServerTransport({
                // Per stateless example, we don't generate a session ID from our side.
                // The transport handles its lifecycle within this single request.
                sessionIdGenerator: undefined
            });

            res.on('close', () => {
                console.log(`[/mcp POST] Request connection closed for stateless request.`);
                transport.close();
                mcpServer.close();
            });

            await mcpServer.connect(transport);
            await transport.handleRequest(req, res, req.body);

        } catch (error) {
            console.error(`[/mcp POST] Error handling stateless MCP request:`, error);
            if (!res.headersSent) {
                res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: 'Internal server error' }, id: null });
            }
        }
    });
    
    app.get('/mcp', (_req, res) => {
        res.status(405).send('Method Not Allowed. Use POST for MCP requests.');
    });
    app.delete('/mcp', (_req, res) => {
        res.status(405).send('Method Not Allowed.');
    });

    // --- Start Server ---
    let server: http.Server | https.Server;
    if (config.server.https.enabled) {
        const cert = await fs.readFile(config.server.https.certPath!);
        const key = await fs.readFile(config.server.https.keyPath!);
        server = https.createServer({ key, cert }, app);
    } else {
        server = http.createServer(app);
    }

    server.listen(config.server.port, () => {
        console.log(`[HTTP] Server listening on ${config.server.baseUrl}`);
        console.log(`[MCP] MCP Endpoint: ${config.server.baseUrl}/mcp`);
    });
}

main().catch(error => {
    console.error("[Startup] FATAL ERROR during application startup:", error);
    process.exit(1);
}); 